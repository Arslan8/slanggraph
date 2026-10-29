"""Cedar-backed forbid-wins evaluation for attributed grants."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from collections import OrderedDict
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from threading import RLock

from langgraph.prebuilt.security.enforcement import Grant, GrantRule, RequirementLedger
from langgraph.prebuilt.security.policy import (
    PolicyFilterResult,
    TypedPolicyBackend,
    _Relation,
    _relation,
)
from langgraph.prebuilt.security.types import (
    ForbidConstraint,
    PolicyConstraint,
)

_SCHEMA = """namespace slangGraph {
  entity Principal;
  entity GrantRule;
  action "operate" appliesTo {
    principal: [Principal],
    resource: [GrantRule],
    context: { matchedForbids: Set<String> }
  };
}
"""


class CedarPolicyBackend:
    """Validate and evaluate generated forbid-only policy with Cedar CLI.

    Typed constraints are first compiled into a monotone candidate grant. Cedar
    then evaluates one request for every surviving rule against one ephemeral
    DAC permit and the complete operator-forbid set. Missing executables,
    validation errors, evaluation diagnostics, timeouts, and malformed output
    all deny the call.
    """

    def __init__(
        self,
        executable: str | Path = "cedar",
        *,
        timeout_s: float = 5.0,
        cache_entries: int = 128,
    ) -> None:
        if timeout_s <= 0:
            raise ValueError("Cedar timeout must be positive")
        if cache_entries < 0:
            raise ValueError("Cedar cache size cannot be negative")
        self.executable = os.fspath(executable)
        self.timeout_s = timeout_s
        self.cache_entries = cache_entries
        self._verified: OrderedDict[str, None] = OrderedDict()
        self._cache_lock = RLock()

    def filter(
        self,
        grant: Grant,
        ledger: RequirementLedger,
        constraints: Sequence[PolicyConstraint],
    ) -> PolicyFilterResult:
        """Return only lines allowed by constructive DAC and every forbid."""
        candidate = TypedPolicyBackend().filter(grant, ledger, constraints)
        if candidate.diagnostics:
            return candidate
        executable = _resolve_executable(self.executable)
        if executable is None:
            return PolicyFilterResult(
                None,
                candidate.ledger,
                "policy_error",
                candidate.removed_rule_ids,
                ("cedar_error:executable_unavailable",),
            )
        engine = _engine_identity(executable)
        if engine is None:
            return PolicyFilterResult(
                None,
                candidate.ledger,
                "policy_error",
                candidate.removed_rule_ids,
                ("cedar_error:executable_unavailable",),
            )
        plan_rules, expected, matches = _evaluation_plan(grant, candidate, constraints)
        policy_grant = replace(grant, rules=plan_rules)
        policies = _policies(policy_grant, constraints)
        entities = _entities(policy_grant)
        requests = tuple(
            _request(grant, rule.rule_id, matches.get(rule.rule_id, ()))
            for rule in plan_rules
        )
        verification_key = _verification_key(
            engine, policies, entities, requests, expected
        )
        if self._cached(verification_key):
            return _cedar_result(candidate, policies)
        try:
            with tempfile.TemporaryDirectory(prefix="slanggraph-cedar-") as directory:
                root = Path(directory)
                policy_path = root / "policy.cedar"
                schema_path = root / "schema.cedarschema"
                entities_path = root / "entities.json"
                policy_path.write_text(policies, encoding="utf-8")
                schema_path.write_text(_SCHEMA, encoding="utf-8")
                entities_path.write_text(
                    json.dumps(entities, sort_keys=True, separators=(",", ":")),
                    encoding="utf-8",
                )
                validation = self._run(
                    executable,
                    "validate",
                    "--policies",
                    os.fspath(policy_path),
                    "--schema",
                    os.fspath(schema_path),
                    "--schema-format",
                    "cedar",
                )
                if validation.returncode != 0:
                    return _cedar_error(candidate, "validation", validation)
                for rule, request in zip(plan_rules, requests, strict=True):
                    request_path = root / "request.json"
                    request_path.write_text(
                        json.dumps(
                            request,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        encoding="utf-8",
                    )
                    evaluation = self._run(
                        executable,
                        "authorize",
                        "--policies",
                        os.fspath(policy_path),
                        "--entities",
                        os.fspath(entities_path),
                        "--request-json",
                        os.fspath(request_path),
                    )
                    decision = evaluation.stdout.strip()
                    if evaluation.returncode != 0 and decision != "DENY":
                        return _cedar_error(candidate, "evaluation", evaluation)
                    if decision not in {"ALLOW", "DENY"}:
                        return PolicyFilterResult(
                            None,
                            candidate.ledger,
                            "policy_error",
                            candidate.removed_rule_ids,
                            (f"cedar_error:malformed_decision:{decision[:120]}",),
                        )
                    allowed = decision == "ALLOW"
                    if allowed != (rule.rule_id in expected):
                        return PolicyFilterResult(
                            None,
                            candidate.ledger,
                            f"cedar_decision_mismatch:{rule.rule_id}",
                            candidate.removed_rule_ids,
                            (
                                "cedar_error:decision_mismatch:"
                                f"{rule.rule_id}:{decision}",
                            ),
                        )
        except (OSError, subprocess.SubprocessError) as exc:
            return PolicyFilterResult(
                None,
                candidate.ledger,
                "policy_error",
                candidate.removed_rule_ids,
                (f"cedar_error:{type(exc).__name__}",),
            )
        self._remember(verification_key)
        return _cedar_result(candidate, policies)

    def _cached(self, key: str) -> bool:
        if not self.cache_entries:
            return False
        with self._cache_lock:
            if key not in self._verified:
                return False
            self._verified.move_to_end(key)
            return True

    def _remember(self, key: str) -> None:
        if not self.cache_entries:
            return
        with self._cache_lock:
            self._verified[key] = None
            self._verified.move_to_end(key)
            while len(self._verified) > self.cache_entries:
                self._verified.popitem(last=False)

    def _run(
        self, executable: str, *arguments: str
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            (executable, *arguments),
            check=False,
            capture_output=True,
            text=True,
            timeout=self.timeout_s,
        )


def _resolve_executable(executable: str) -> str | None:
    if os.path.sep in executable:
        path = Path(executable)
        return os.fspath(path) if path.is_file() and os.access(path, os.X_OK) else None
    return shutil.which(executable)


def _verification_key(
    engine: tuple[str, int, int, int, int, int],
    policies: str,
    entities: Sequence[dict[str, object]],
    requests: Sequence[dict[str, object]],
    expected: frozenset[str],
) -> str:
    """Identify one complete successful Cedar verification.

    The cache stores only successful engine checks. It includes every Cedar
    input and the typed backend's expected decisions, so neither a changed
    policy nor a changed request can reuse an earlier result.
    """
    return hashlib.sha256(
        json.dumps(
            {
                "engine": engine,
                "entities": entities,
                "expected": sorted(expected),
                "policies": policies,
                "requests": requests,
                "schema": _SCHEMA,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def _engine_identity(executable: str) -> tuple[str, int, int, int, int, int] | None:
    """Bind cached checks to the executable file that produced them."""
    try:
        status = os.stat(executable)
    except OSError:
        return None
    return (
        executable,
        status.st_dev,
        status.st_ino,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


def _cedar_result(candidate: PolicyFilterResult, policies: str) -> PolicyFilterResult:
    if not candidate.allowed or candidate.grant is None:
        return candidate
    digest = hashlib.sha256(
        json.dumps(
            {
                "backend": "cedar-cli",
                "candidate": candidate.grant.policy_digest,
                "policies": policies,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return replace(
        candidate,
        grant=replace(candidate.grant, policy_digest=digest),
        reason="allow:cedar",
    )


def _policies(grant: Grant, constraints: Sequence[PolicyConstraint]) -> str:
    lines: list[str] = []
    principal = _cedar_string(grant.principal_id)
    for rule in grant.rules:
        lines.append(
            f'@id("dac:{_cedar_string(rule.rule_id)}")\n'
            "permit (\n"
            f'  principal == slangGraph::Principal::"{principal}",\n'
            '  action == slangGraph::Action::"operate",\n'
            f'  resource == slangGraph::GrantRule::"{_cedar_string(rule.rule_id)}"\n'
            ");"
        )
    for constraint in sorted(
        constraints, key=lambda item: (item.module, item.constraint_id)
    ):
        identity = _constraint_identity(constraint)
        lines.append(
            f'@id("forbid:{_cedar_string(identity)}")\n'
            "forbid (principal, action, resource)\n"
            f'when {{ context.matchedForbids.contains("{_cedar_string(identity)}") }};'
        )
    return "\n\n".join(lines) + "\n"


def _entities(grant: Grant) -> list[dict[str, object]]:
    entities = [
        {
            "uid": {"type": "slangGraph::Principal", "id": grant.principal_id},
            "attrs": {},
            "parents": [],
        }
    ]
    entities.extend(
        {
            "uid": {"type": "slangGraph::GrantRule", "id": rule.rule_id},
            "attrs": {},
            "parents": [],
        }
        for rule in grant.rules
    )
    return entities


def _request(
    grant: Grant, rule_id: str, matched_forbids: Sequence[str]
) -> dict[str, object]:
    return {
        "principal": _entity_literal("slangGraph::Principal", grant.principal_id),
        "action": _entity_literal("slangGraph::Action", "operate"),
        "resource": _entity_literal("slangGraph::GrantRule", rule_id),
        "context": {"matchedForbids": list(matched_forbids)},
    }


def _evaluation_plan(
    grant: Grant,
    candidate: PolicyFilterResult,
    constraints: Sequence[PolicyConstraint],
) -> tuple[tuple[GrantRule, ...], frozenset[str], dict[str, tuple[str, ...]]]:
    candidate_rules = candidate.grant.rules if candidate.grant is not None else ()
    by_id = {rule.rule_id: rule for rule in (*grant.rules, *candidate_rules)}
    expected = frozenset(rule.rule_id for rule in candidate_rules)
    matches: dict[str, tuple[str, ...]] = {}
    removed = set(candidate.removed_rule_ids)
    for rule in grant.rules:
        identities: list[str] = []
        for constraint in constraints:
            if isinstance(constraint, ForbidConstraint):
                relation = _relation(constraint.predicate, rule)
                if relation is _Relation.FULL or (
                    relation is _Relation.PARTIAL and rule.rule_id in removed
                ):
                    identities.append(_constraint_identity(constraint))
            elif rule.rule_id in removed and all(
                any(_relation(term, item) is not _Relation.NONE for item in grant.rules)
                for term in constraint.terms
            ):
                identities.append(_constraint_identity(constraint))
        matches[rule.rule_id] = tuple(sorted(identities))
    for rule in candidate_rules:
        matches.setdefault(rule.rule_id, ())
    return tuple(by_id.values()), expected, matches


def _constraint_identity(constraint: PolicyConstraint) -> str:
    return f"{constraint.module}:{constraint.constraint_id}"


def _cedar_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)[1:-1]


def _entity_literal(entity_type: str, entity_id: str) -> str:
    return f'{entity_type}::"{_cedar_string(entity_id)}"'


def _cedar_error(
    candidate: PolicyFilterResult,
    stage: str,
    result: subprocess.CompletedProcess[str],
) -> PolicyFilterResult:
    diagnostic = (result.stderr or result.stdout).strip().replace("\n", " ")
    return PolicyFilterResult(
        None,
        candidate.ledger,
        "policy_error",
        candidate.removed_rule_ids,
        (f"cedar_error:{stage}:{diagnostic[:240] or result.returncode}",),
    )
