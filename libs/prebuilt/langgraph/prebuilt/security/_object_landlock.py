"""Landlock host adapter for composed object-resource enforcement."""

from __future__ import annotations

import hmac
import os
import platform
import stat
import time
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

from langgraph.prebuilt.security.enforcement import (
    AdapterPlan,
    AuthorityDomain,
    EnforcementObligation,
    ExecutionContext,
    Grant,
    GrantRule,
    HostAttestation,
    ObligationKind,
    SupportAssessment,
    SupportLevel,
)
from langgraph.prebuilt.security.landlock import open_path_descriptor
from langgraph.prebuilt.security.resource_mediator import _digest, _LocalEvidence


class _LandlockObjectAdapter(_LocalEvidence):
    """Own local isolation obligations; never claim semantic resource support."""

    def __init__(self, worker: Any, grant: Grant) -> None:
        super().__init__("host:landlock-object-v1")
        self.worker = worker
        self.grant = grant
        self.plan: AdapterPlan | None = None
        self.context: ExecutionContext | None = None
        self.host: HostAttestation | None = None
        self.rules: tuple[GrantRule, ...] = ()

    def attest(self, nonce: str) -> HostAttestation:
        now = time.time()
        probe = self.worker.capabilities
        host = HostAttestation(
            self.adapter_id,
            nonce,
            probe.boot_id,
            platform.system().lower(),
            now,
            now
            + self.worker.default_wall_timeout_s
            + self.worker.startup_timeout_s
            + 10,
            probe.capabilities
            | frozenset(
                {"seccomp:minimal", "broker:spawn-bound", "credentials:parent-only"}
            ),
            {"supervisor_pid": str(os.getpid())},
            {
                "landlock_abi": self.worker.abi,
                "python_digest": self.worker.python_digest,
                "worker_digest": self.worker.worker_digest,
                "probe": dict(probe.evidence),
            },
            "pending",
        )
        self.host = replace(host, signature=self._sign(host.digest))
        return self.host

    def verify(self, host: HostAttestation) -> bool:
        return (
            host.issuer == self.adapter_id
            and self.host is not None
            and host.digest == self.host.digest
            and host.boot_id == self.worker.capabilities.boot_id
            and hmac.compare_digest(host.signature, self._sign(host.digest))
        )

    def _protected(self, paths: Sequence[str]) -> bool:
        for value in paths:
            protected = Path(value).resolve()
            for rule in self.grant.rules:
                if rule.domain not in {
                    AuthorityDomain.FILESYSTEM,
                    AuthorityDomain.RUNTIME,
                }:
                    continue
                if rule.operation not in {
                    "read",
                    "write",
                    "create",
                    "delete",
                    "truncate",
                }:
                    continue
                exposed = Path(rule.selector).resolve()
                if (
                    exposed == protected
                    or protected in exposed.parents
                    or (exposed.is_dir() and exposed in protected.parents)
                ):
                    return False
        return True

    def assess(
        self, item: EnforcementObligation, host: HostAttestation
    ) -> SupportAssessment:
        support, reason = SupportLevel.UNSUPPORTED, "host_cannot_enforce"
        if (
            not self.verify(host)
            or host.platform != "linux"
            or host.evidence.get("landlock_abi", 0) < 5
        ):
            reason = "host_cannot_enforce:landlock_abi_5"
        elif item.kind is ObligationKind.DENY_COMPLEMENT:
            support, reason = (
                SupportLevel.EXACT,
                "landlock_seccomp_closed_world_and_broker_allowlist",
            )
        elif (
            item.kind is ObligationKind.AUTHENTICATED_CHANNEL
            and item.operation == "spawn_bound_broker"
        ):
            if self.worker.credential_broker is not None:
                support, reason = SupportLevel.EXACT, "private_inherited_socketpair"
        elif (
            item.kind is ObligationKind.BYPASS_PREVENTION
            and item.operation == "deny_direct_resource_access"
        ):
            required = frozenset(item.conditions.get("required_capabilities", ()))
            if required.issubset(host.capabilities) and self._protected(
                item.conditions.get("protected_paths", ())
            ):
                support, reason = (
                    SupportLevel.EXACT,
                    "no_direct_network_process_or_protected_path",
                )
            else:
                reason = "resource_bypass_not_closed"
        elif item.kind in {
            ObligationKind.OPERATE,
            ObligationKind.RESOURCE_LIMIT,
        } and item.domain not in {
            AuthorityDomain.SERVICE,
            AuthorityDomain.NETWORK,
            AuthorityDomain.CREDENTIAL,
            AuthorityDomain.DELEGATION,
        }:
            rule = next(
                (rule for rule in self.grant.rules if rule.rule_id == item.rule_id),
                None,
            )
            if rule is not None and (
                item.operation,
                item.selector,
                dict(item.conditions),
            ) == (rule.operation, rule.selector, dict(rule.conditions)):
                support, reason = self.worker._assess_rule(rule)
                if (
                    rule.domain is AuthorityDomain.PROCESS
                    and rule.operation != "syscall_set"
                ):
                    support, reason = (
                        SupportLevel.UNSUPPORTED,
                        "process_authority_unavailable",
                    )
                if rule.conditions.get("exact_file"):
                    try:
                        fd = open_path_descriptor(rule.selector, no_symlinks=True)
                        try:
                            if not stat.S_ISREG(os.fstat(fd).st_mode):
                                support, reason = (
                                    SupportLevel.UNSUPPORTED,
                                    "exact_file_required",
                                )
                        finally:
                            os.close(fd)
                    except (OSError, ValueError):
                        support, reason = (
                            SupportLevel.UNSUPPORTED,
                            "canonical_file_unavailable",
                        )
        if item.conditions.get("lowering") is not None:
            support, reason = SupportLevel.UNSUPPORTED, "unknown_host_lowering_strategy"
        return SupportAssessment(
            self.adapter_id,
            item.obligation_id,
            support,
            reason,
            ("landlock-worker-conformance-v1",)
            if support is not SupportLevel.UNSUPPORTED
            else (),
        )

    def lower(
        self,
        grant: Grant,
        obligations: Sequence[EnforcementObligation],
        host: HostAttestation,
    ) -> AdapterPlan:
        if any(
            self.assess(item, host).support is SupportLevel.UNSUPPORTED
            for item in obligations
        ):
            raise ValueError("host support changed during lowering")
        operated = {
            item.rule_id
            for item in obligations
            if item.kind in {ObligationKind.OPERATE, ObligationKind.RESOURCE_LIMIT}
        }
        self.rules = tuple(rule for rule in grant.rules if rule.rule_id in operated)
        payload = {
            "grant": grant.digest,
            "host": host.digest,
            "rules": [dict(rule.canonical()) for rule in self.rules],
            "obligations": [dict(item.canonical()) for item in obligations],
        }
        self.plan = AdapterPlan(
            self.adapter_id,
            frozenset(item.obligation_id for item in obligations),
            _digest(payload),
            payload,
        )
        return self.plan

    def bind_worker(self, pid: int, broker_epoch: str) -> ExecutionContext:
        status = Path(f"/proc/{pid}/status").read_text()
        fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
        if any(
            fields.get(key, "").strip() != value
            for key, value in {
                "Seccomp": "2",
                "NoNewPrivs": "1",
                "Threads": "1",
            }.items()
        ):
            raise ValueError("worker confinement state is invalid")
        # comm may contain whitespace and parentheses; fields after the last ')'
        # start at stat field 3, so starttime (22) is index 19.
        start = Path(f"/proc/{pid}/stat").read_text().rpartition(")")[2].split()[19]
        namespaces = {
            name: os.readlink(f"/proc/{pid}/ns/{name}")
            for name in ("user", "mnt", "pid", "net", "ipc", "uts", "cgroup")
        }
        self.context = ExecutionContext(
            f"landlock:{pid}:{start}",
            f"pid:{pid}:start:{start}",
            Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            namespaces,
            _digest(
                {
                    key: fields.get(key, "").strip()
                    for key in ("Uid", "Gid", "CapEff", "NoNewPrivs", "Seccomp")
                }
            ),
            Path(f"/proc/{pid}/cgroup").read_text().strip(),
            broker_epoch,
        )
        return self.context

    def activate(self, plan: AdapterPlan, context: ExecutionContext, nonce: str):
        if (
            self.context is None
            or context != self.context
            or plan != self.plan
            or self.host is None
        ):
            raise ValueError("host activation does not match the verified worker")
        return self._evidence(plan, context, nonce, self.host.expires_at)
