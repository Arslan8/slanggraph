"""Evaluation preflight, including an explicit trusted authentication adapter."""

import hashlib
import hmac
import json
import secrets

_AUTH_KEY = secrets.token_bytes(32)


def authenticated_principal(user, session):
    from langgraph.prebuilt.security import Principal

    # Synthetic test credentials, verified before binding identity to the graph.
    payload = json.dumps([user, session], separators=(",", ":")).encode()
    token = hmac.digest(_AUTH_KEY, payload, "sha256")
    return verify_credential(payload, token)


def verify_credential(payload, token):
    from langgraph.prebuilt.security import Principal

    if not hmac.compare_digest(hmac.digest(_AUTH_KEY, payload, "sha256"), token):
        raise PermissionError("evaluation:unauthenticated_principal")
    user, session = json.loads(payload)
    return Principal(user, frozenset(), frozenset(), session)


def assert_complete_path(graph, config, dispatcher):
    from langgraph._internal import _runtime_policy
    from langgraph.prebuilt.security import MacOSObjectDispatcher
    from langgraph.prebuilt.security.mac import RuntimeMAC
    from langgraph.prebuilt.security.lean_lifecycle import LeanLifecycleChecker
    from langgraph.prebuilt.security.object_policy import (
        ObjectPolicyHostExecutor,
        CedarObjectAuthorizer,
    )

    checks = {
        "required_principal": config.require_principal is True,
        "cedar_authorization": type(config.host_executor) is ObjectPolicyHostExecutor
        and type(config.host_executor.authorizer) is CedarObjectAuthorizer,
        "dispatcher_binding": getattr(config.host_executor, "dispatcher", None) is dispatcher,
        "sealed_operator_mac": type(_runtime_policy.runtime_policy()) is RuntimeMAC,
        "closed_admission": config.closed_admission is True
        and bool(graph.builder._security_admission),
        "native_seatbelt_route": type(dispatcher) is MacOSObjectDispatcher,
        "resource_mediators": bool(getattr(dispatcher, "mediators", ())),
        "live_lean_checker": type(getattr(dispatcher, "lifecycle_checker", None))
        is LeanLifecycleChecker,
        "audit": config.audit_sink is not None,
        "cleanup_recovery": getattr(
            dispatcher, "recovery_directory", __import__("pathlib").Path("relative")
        ).is_absolute(),
    }
    missing = [name for name, value in checks.items() if not value]
    if missing:
        raise RuntimeError("evaluation:incomplete_path:" + ",".join(missing))
    return dict(
        checks=checks,
        operator_policy_sha256=hashlib.sha256(
            _runtime_policy.runtime_policy().forbids.encode()
        ).hexdigest(),
        identity_source="trusted HMAC test authenticator; never graph state/model arguments",
    )
