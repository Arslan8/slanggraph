from __future__ import annotations

import json
import os
import socket
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import get_ident

import pytest

from langgraph.prebuilt.security import AuthorityDomain, Grant, GrantRule
from langgraph.prebuilt.security.broker import (
    CredentialBroker,
    GitHubAppIssuer,
    IssuedCredential,
    SpawnRecord,
    broker_request,
)


def _grant() -> Grant:
    return Grant(
        "alice",
        "session",
        "issue_comment",
        "a" * 64,
        "call-1",
        "b" * 64,
        "c" * 64,
        (
            GrantRule(
                "service:github",
                AuthorityDomain.SERVICE,
                "invoke",
                "github",
                {
                    "issuer": "github_app",
                    "installation": "42",
                    "permission": "issues:write",
                    "repository": "org/repo",
                },
            ),
        ),
    )


def _spawn(grant: Grant) -> SpawnRecord:
    return SpawnRecord("alice", "issue_comment", grant.digest, "spawn-1")


def test_broker_retains_token_and_uses_exact_rule_scope(monkeypatch) -> None:
    grant = _grant()
    minted: list[Mapping[str, str]] = []
    handled: list[tuple[str, Mapping[str, object]]] = []

    def mint(spawn: SpawnRecord, scope: Mapping[str, str]) -> str:
        minted.append(scope)
        return "secret-installation-token"

    def handle(token, operation, payload, spawn):
        assert token == "secret-installation-token"
        assert spawn == _spawn(grant)
        handled.append((operation, payload))
        return {"comment_id": 7}

    broker = CredentialBroker({"github_app": GitHubAppIssuer(mint)}, {"github": handle})
    session = broker.open_session(_spawn(grant), grant)
    assert os.get_inheritable(session.worker_fd) is False
    monkeypatch.setenv("SLANGGRAPH_BROKER_FD", str(session.worker_fd))
    try:
        assert broker_request("github", "invoke", {"body": "hello"}) == {
            "comment_id": 7
        }
    finally:
        session.close()

    assert minted == [
        {
            "installation": "42",
            "permission": "issues:write",
            "repository": "org/repo",
        }
    ]
    assert handled == [("invoke", {"body": "hello"})]
    record = broker.audit_records()[0]
    assert record.allowed is True
    assert record.reason == "exact_scope"
    assert "secret-installation-token" not in repr(record)
    assert "secret-installation-token" not in os.environ.values()


def test_broker_reuses_server_thread_without_reusing_invocation_binding(
    monkeypatch,
) -> None:
    """Serving infrastructure is reusable while each socket keeps a fresh grant."""
    grant = _grant()
    serving_threads: list[int] = []

    def handle(token, operation, payload, spawn):
        serving_threads.append(get_ident())
        return spawn.nonce

    with ThreadPoolExecutor(max_workers=1) as executor:
        broker = CredentialBroker(
            {"github_app": GitHubAppIssuer(lambda spawn, scope: "secret")},
            {"github": handle},
            server_executor=executor,
        )
        results = []
        for nonce in ("spawn-1", "spawn-2"):
            spawn = replace(_spawn(grant), nonce=nonce)
            session = broker.open_session(spawn, grant)
            monkeypatch.setenv("SLANGGRAPH_BROKER_FD", str(session.worker_fd))
            try:
                results.append(broker_request("github", "invoke"))
            finally:
                session.close()

    assert results == ["spawn-1", "spawn-2"]
    assert len(set(serving_threads)) == 1
    assert [record.spawn_nonce for record in broker.audit_records()] == [
        "spawn-1",
        "spawn-2",
    ]


class WrongScopeIssuer:
    def issue(self, spawn, rule, scope):
        return IssuedCredential("secret", {"repository": "other/repo"})


def test_broker_denies_credential_scope_mismatch(monkeypatch) -> None:
    grant = _grant()
    broker = CredentialBroker(
        {"github_app": WrongScopeIssuer()},
        {"github": lambda token, operation, payload, spawn: "unreachable"},
    )
    session = broker.open_session(_spawn(grant), grant)
    monkeypatch.setenv("SLANGGRAPH_BROKER_FD", str(session.worker_fd))
    try:
        with pytest.raises(PermissionError, match="broker:service_failure"):
            broker_request("github", "invoke")
    finally:
        session.close()
    assert broker.audit_records()[0].allowed is False


def test_broker_rejects_worker_supplied_identity() -> None:
    grant = _grant()
    broker = CredentialBroker(
        {"github_app": GitHubAppIssuer(lambda spawn, scope: "secret")},
        {"github": lambda token, operation, payload, spawn: "unreachable"},
    )
    session = broker.open_session(_spawn(grant), grant)
    duplicate = os.dup(session.worker_fd)
    channel = socket.socket(fileno=duplicate)
    try:
        channel.sendall(
            json.dumps(
                {
                    "service": "github",
                    "operation": "invoke",
                    "payload": {},
                    "principal_id": "mallory",
                }
            ).encode()
            + b"\n"
        )
        response = json.loads(channel.makefile("rb").readline())
    finally:
        channel.close()
        session.close()
    assert response == {
        "error": "broker:worker_identity_rejected",
        "status": "denied",
    }


@pytest.mark.parametrize(
    "result",
    [object(), "x" * 1_048_576, float("nan")],
    ids=["non-json", "oversized", "non-finite"],
)
def test_broker_response_does_not_leak_repr_or_unbounded_data(monkeypatch, result):
    grant = _grant()
    broker = CredentialBroker(
        {"github_app": GitHubAppIssuer(lambda spawn, scope: "secret")},
        {"github": lambda *args: result},
    )
    session = broker.open_session(_spawn(grant), grant)
    monkeypatch.setenv("SLANGGRAPH_BROKER_FD", str(session.worker_fd))
    try:
        with pytest.raises(PermissionError, match="broker:invalid_response"):
            broker_request("github", "invoke")
    finally:
        session.close()
    assert session.terminated


def test_oversized_frame_cannot_smuggle_second_request():
    grant = _grant()
    seen = []
    broker = CredentialBroker(
        {"github_app": GitHubAppIssuer(lambda spawn, scope: "secret")},
        {"github": lambda *args: seen.append(args)},
    )
    session = broker.open_session(_spawn(grant), grant)
    channel = socket.socket(fileno=os.dup(session.worker_fd))
    channel.settimeout(2)
    valid = b'{"service":"github","operation":"invoke","payload":{}}\n'
    try:
        try:
            channel.sendall(b" " * 1_048_577 + valid)
        except (BrokenPipeError, ConnectionResetError):
            pass
        try:
            assert channel.recv(1024) == b""
        except ConnectionResetError:
            pass
    finally:
        channel.close()
        session.close()
    assert not seen
