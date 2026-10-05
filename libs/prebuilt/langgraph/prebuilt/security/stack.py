"""Restrictive security-module composition for tool calls."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import replace
from functools import partial
from typing import Any

from langgraph.prebuilt.security.dac import dac_check
from langgraph.prebuilt.security.descriptor import normalize_resource
from langgraph.prebuilt.security.hooks import SecurityModule
from langgraph.prebuilt.security.types import (
    Approval,
    Decision,
    Principal,
    Slot,
    ToolCall,
    Verdict,
)


class CapModule(SecurityModule):
    """Mandatory capability module that prevents scope growth."""

    name = "cap"

    def tool_call_permission(self, principal: Principal, call: ToolCall) -> Decision:
        """Require the tool's declared scopes as a defense-in-depth check."""
        if not call.tool.dac.required_scopes.issubset(principal.scopes):
            return Decision(Verdict.DENY, "cap:scope")
        return Decision(Verdict.ALLOW, "cap:allow")

    def cred_transfer(
        self, parent: Principal, child: Principal, slot: Slot
    ) -> Decision:
        """Reject delegation that adds authority absent from the parent."""
        if not child.scopes.issubset(parent.scopes):
            return Decision(Verdict.DENY, "cap:scope_growth")
        return Decision(Verdict.ALLOW, "cap:allow")

    def resume_permission(self, principal: Principal, approval: Approval) -> Decision:
        """Treat human rejection as restrictive policy input."""
        if not approval.approved:
            return Decision(Verdict.DENY, "cap:approval_rejected")
        return Decision(Verdict.ALLOW, "cap:approval")


class SecurityStack:
    """Run DAC and independent security modules with restrictive semantics."""

    def __init__(
        self,
        modules: Sequence[SecurityModule] = (),
        *,
        policy_timeout_s: float = 2.0,
    ) -> None:
        if policy_timeout_s <= 0:
            raise ValueError("policy_timeout_s must be positive")
        if any(module.name == "cap" for module in modules):
            raise ValueError("cap is framework-managed and cannot be registered")
        names = [module.name for module in modules]
        if any(not name for name in names) or len(names) != len(set(names)):
            raise ValueError("security module names must be unique and non-empty")
        self.modules = (CapModule(), *modules)
        self.policy_timeout_s = policy_timeout_s
        self._executor = ThreadPoolExecutor(
            max_workers=max(4, len(self.modules)),
            thread_name_prefix="slanggraph-policy",
        )

    def close(self) -> None:
        """Cancel queued policy work and release executor resources."""
        self._executor.shutdown(wait=False, cancel_futures=True)

    def permission(self, principal: Principal, call: ToolCall) -> Decision:
        """Run DAC first, then stop on the first module objection."""
        author = dac_check(principal, call.tool, call.normalized)
        if author.verdict is not Verdict.ALLOW:
            return author
        return self._restrictive_sync(
            lambda module: module.tool_call_permission(principal, call)
        )

    async def apermission(self, principal: Principal, call: ToolCall) -> Decision:
        """Asynchronously run DAC and module permission hooks."""
        author = dac_check(principal, call.tool, call.normalized)
        if author.verdict is not Verdict.ALLOW:
            return author
        return await self._restrictive_async(
            lambda module: module.tool_call_permission(principal, call)
        )

    def prepare(
        self, principal: Principal, call: ToolCall
    ) -> tuple[Decision, ToolCall]:
        """Apply ordered argument narrowing and re-run DAC on the final call."""
        initial = dac_check(principal, call.tool, call.normalized)
        if initial.verdict is not Verdict.ALLOW:
            return initial, call
        current = call
        for module in self.modules:
            decision = self._sync_decision(
                module,
                partial(module.tool_call_prepare, principal, current),
            )
            if decision.verdict is Verdict.TRANSFORM:
                current = _replace_call_args(current, decision.new_args or {})
                continue
            if decision.verdict is not Verdict.ALLOW:
                return decision, current
        final = dac_check(principal, current.tool, current.normalized)
        if final.verdict is not Verdict.ALLOW:
            return Decision(Verdict.DENY, f"prepare:{final.reason}"), current
        return Decision(Verdict.ALLOW, "prepare:allow"), current

    async def aprepare(
        self, principal: Principal, call: ToolCall
    ) -> tuple[Decision, ToolCall]:
        """Asynchronously apply ordered narrowing and final DAC validation."""
        initial = dac_check(principal, call.tool, call.normalized)
        if initial.verdict is not Verdict.ALLOW:
            return initial, call
        current = call
        for module in self.modules:
            decision = await self._async_decision(
                module,
                partial(module.tool_call_prepare, principal, current),
            )
            if decision.verdict is Verdict.TRANSFORM:
                current = _replace_call_args(current, decision.new_args or {})
                continue
            if decision.verdict is not Verdict.ALLOW:
                return decision, current
        final = dac_check(principal, current.tool, current.normalized)
        if final.verdict is not Verdict.ALLOW:
            return Decision(Verdict.DENY, f"prepare:{final.reason}"), current
        return Decision(Verdict.ALLOW, "prepare:allow"), current

    def cred_transfer(self, parent: Principal, child: Principal) -> Decision:
        """Run every module's restrictive delegation hook."""
        return self._restrictive_sync(
            lambda module: module.cred_transfer(
                parent, child, child.security.allocate(module.name)
            )
        )

    async def acred_transfer(self, parent: Principal, child: Principal) -> Decision:
        """Asynchronously run restrictive delegation hooks."""
        return await self._restrictive_async(
            lambda module: module.cred_transfer(
                parent, child, child.security.allocate(module.name)
            )
        )

    def resume_permission(self, principal: Principal, approval: Approval) -> Decision:
        """Run every module after a human approval response."""
        return self._restrictive_sync(
            lambda module: module.resume_permission(principal, approval)
        )

    async def aresume_permission(
        self, principal: Principal, approval: Approval
    ) -> Decision:
        """Asynchronously run every post-approval hook."""
        return await self._restrictive_async(
            lambda module: module.resume_permission(principal, approval)
        )

    def _restrictive_sync(self, hook: Callable[[SecurityModule], Any]) -> Decision:
        for module in self.modules:
            decision = self._sync_decision(module, partial(hook, module))
            if decision.verdict is not Verdict.ALLOW:
                return decision
        return Decision(Verdict.ALLOW, "stack:allow")

    async def _restrictive_async(
        self, hook: Callable[[SecurityModule], Any]
    ) -> Decision:
        for module in self.modules:
            decision = await self._async_decision(module, partial(hook, module))
            if decision.verdict is not Verdict.ALLOW:
                return decision
        return Decision(Verdict.ALLOW, "stack:allow")

    def _sync_decision(
        self, module: SecurityModule, hook: Callable[[], Any]
    ) -> Decision:
        future = self._executor.submit(hook)
        try:
            result = future.result(timeout=self.policy_timeout_s)
        except FutureTimeoutError:
            future.cancel()
            return Decision(Verdict.DENY, f"module_timeout:{module.name}")
        except BaseException:
            return Decision(Verdict.DENY, f"module_error:{module.name}")
        if not isinstance(result, Decision):
            return Decision(Verdict.DENY, f"module_error:{module.name}")
        return result

    async def _async_decision(
        self, module: SecurityModule, hook: Callable[[], Any]
    ) -> Decision:
        try:
            if inspect.iscoroutinefunction(hook):
                result = await asyncio.wait_for(hook(), self.policy_timeout_s)
            else:
                loop = asyncio.get_running_loop()
                result = await asyncio.wait_for(
                    loop.run_in_executor(self._executor, hook), self.policy_timeout_s
                )
                if inspect.isawaitable(result):
                    result = await asyncio.wait_for(result, self.policy_timeout_s)
        except TimeoutError:
            return Decision(Verdict.DENY, f"module_timeout:{module.name}")
        except BaseException:
            return Decision(Verdict.DENY, f"module_error:{module.name}")
        if not isinstance(result, Decision):
            return Decision(Verdict.DENY, f"module_error:{module.name}")
        return result


def _replace_call_args(call: ToolCall, args: Mapping[str, Any]) -> ToolCall:
    normalized: dict[str, Any] = {}
    for resource in call.tool.resources:
        if resource.arg not in args:
            continue
        value = normalize_resource(resource, args[resource.arg])
        normalized[resource.arg] = value
        if resource.normalizer in {"domain", "email_domain"}:
            normalized[f"{resource.arg}_domain"] = value
        elif resource.normalizer == "sql_statement_kind":
            normalized[f"{resource.arg}_statement_kind"] = value
        elif resource.normalizer == "shell_argv0":
            normalized[f"{resource.arg}_argv0"] = value
    return replace(call, args=args, normalized=normalized)
