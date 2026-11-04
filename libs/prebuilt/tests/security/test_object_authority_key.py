"""Prepared-worker selection must preserve exact authority without encoding it."""

from dataclasses import replace

import pytest

from langgraph.prebuilt.security import object_broker
from langgraph.prebuilt.security.object_policy import (
    EnforcementKind,
    ObjectGrant,
    ObjectGrantLine,
)
from langgraph.prebuilt.security.profile import Requirement


@pytest.fixture
def grant():
    return ObjectGrant(
        "alice",
        "tool",
        "call",
        "policy",
        (
            ObjectGrantLine(
                "line",
                "records",
                "read",
                "alice",
                {"a": "1", "b": "2"},
                Requirement.NEED,
                EnforcementKind.BROKER,
            ),
        ),
    )


def test_key_needs_no_json_or_sha256(grant, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("prepared lookup must not serialize or digest authority")

    monkeypatch.setattr(object_broker.json, "dumps", forbidden)
    monkeypatch.setattr(object_broker.hashlib, "sha256", forbidden)
    key = object_broker._object_authority_key(grant)
    reordered = replace(grant.lines[0], attributes={"b": "2", "a": "1"})
    fresh = replace(grant, principal_id="bob", call_id="fresh", lines=(reordered,))
    assert {key: "prepared"}[object_broker._object_authority_key(fresh)] == "prepared"


@pytest.mark.parametrize(
    "change",
    [
        {"line_id": "other"},
        {"class_name": "files"},
        {"operation": "write"},
        {"selector": "bob"},
        {"attributes": {"a": "different"}},
        {"requirement": Requirement.WANT},
        {"lowering": "different"},
        {"provenance": ("different",)},
    ],
)
def test_changed_authority_cannot_select_prepared_worker(grant, change):
    original = object_broker._object_authority_key(grant)
    changed = replace(grant, lines=(replace(grant.lines[0], **change),))
    assert object_broker._object_authority_key(changed) not in {original: "prepared"}


@pytest.mark.parametrize(
    "change",
    [
        {"policy_digest": "other"},
        {"tool_name": "other"},
        {"enforcement_waivers": {"line": "reason"}},
    ],
)
def test_changed_configuration_cannot_select_prepared_worker(grant, change):
    original = object_broker._object_authority_key(grant)
    assert object_broker._object_authority_key(replace(grant, **change)) != original
