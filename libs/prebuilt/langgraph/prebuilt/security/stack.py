"""Restrictive security-module composition for tool calls."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import replace
from functools import partial
from time import perf_counter
from typing import Any, cast

from langgraph.prebuilt.security.dac import dac_check
from langgraph.prebuilt.security.descriptor import normalize_resource
from langgraph.prebuilt.security.hooks import SecurityModule
from langgraph.prebuilt.security.observability import (
    SecurityEvent,
    SecurityObserver,
    compose_observer,
    hash_args,
)
from langgraph.prebuilt.security.types import (
    Approval,
    AuditSink,
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
        observer: SecurityObserver | None = None,
        audit_sink: AuditSink | None = None,
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
        self.observer = compose_observer(observer, audit_sink)
        self.audit_events = audit_sink is not None
        self._executor = ThreadPoolExecutor(
            max_workers=max(4, len(self.modules)),
            thread_name_prefix="slanggraph-policy",
        )

    def close(self) -> None:
        """Cancel queued policy work and release executor resources."""
        self._executor.shutdown(wait=False, cancel_futures=True)

    def permission(self, principal: Principal, call: ToolCall) -> Decision:
        """Run DAC first, then stop on the first module objection."""
        started = self._started()
        author = dac_check(principal, call.tool, call.normalized)
        self._observe(principal, call, "permission", "dac", author, started)
        if author.verdict is not Verdict.ALLOW:
            return author
        for module in self.modules:
            started = self._started()
            decision = self._sync_decision(
                module, partial(module.tool_call_permission, principal, call)
            )
            self._observe(principal, call, "permission", module.name, decision, started)
            if decision.verdict is not Verdict.ALLOW:
                return decision
        return Decision(Verdict.ALLOW, "stack:allow")

    async def apermission(self, principal: Principal, call: ToolCall) -> Decision:
        """Asynchronously run DAC and module permission hooks."""
        started = self._started()
        author = dac_check(principal, call.tool, call.normalized)
        self._observe(principal, call, "permission", "dac", author, started)
        if author.verdict is not Verdict.ALLOW:
            return author
        for module in self.modules:
            started = self._started()
            decision = await self._async_decision(
                module, partial(module.tool_call_permission, principal, call)
            )
            self._observe(principal, call, "permission", module.name, decision, started)
            if decision.verdict is not Verdict.ALLOW:
                return decision
        return Decision(Verdict.ALLOW, "stack:allow")

    def prepare(
        self, principal: Principal, call: ToolCall
    ) -> tuple[Decision, ToolCall]:
        """Apply ordered argument narrowing and re-run DAC on the final call."""
        started = self._started()
        initial = dac_check(principal, call.tool, call.normalized)
        self._observe(principal, call, "prepare", "dac_initial", initial, started)
        if initial.verdict is not Verdict.ALLOW:
            return initial, call
        current = call
        for module in self.modules:
            if type(module).tool_call_prepare is SecurityModule.tool_call_prepare:
                continue
            started = self._started()
            decision = self._sync_decision(
                module,
                partial(module.tool_call_prepare, principal, current),
            )
            self._observe(principal, current, "prepare", module.name, decision, started)
            if decision.verdict is Verdict.TRANSFORM:
                current = _replace_call_args(current, decision.new_args or {})
                continue
            if decision.verdict is not Verdict.ALLOW:
                return decision, current
        started = self._started()
        final = dac_check(principal, current.tool, current.normalized)
        self._observe(principal, current, "prepare", "dac_final", final, started)
        if final.verdict is not Verdict.ALLOW:
            return Decision(Verdict.DENY, f"prepare:{final.reason}"), current
        return Decision(Verdict.ALLOW, "prepare:allow"), current

    async def aprepare(
        self, principal: Principal, call: ToolCall
    ) -> tuple[Decision, ToolCall]:
        """Asynchronously apply ordered narrowing and final DAC validation."""
        started = self._started()
        initial = dac_check(principal, call.tool, call.normalized)
        self._observe(principal, call, "prepare", "dac_initial", initial, started)
        if initial.verdict is not Verdict.ALLOW:
            return initial, call
        current = call
        for module in self.modules:
            if type(module).tool_call_prepare is SecurityModule.tool_call_prepare:
                continue
            started = self._started()
            decision = await self._async_decision(
                module,
                partial(module.tool_call_prepare, principal, current),
            )
            self._observe(principal, current, "prepare", module.name, decision, started)
            if decision.verdict is Verdict.TRANSFORM:
                current = _replace_call_args(current, decision.new_args or {})
                continue
            if decision.verdict is not Verdict.ALLOW:
                return decision, current
        started = self._started()
        final = dac_check(principal, current.tool, current.normalized)
        self._observe(principal, current, "prepare", "dac_final", final, started)
        if final.verdict is not Verdict.ALLOW:
            return Decision(Verdict.DENY, f"prepare:{final.reason}"), current
        return Decision(Verdict.ALLOW, "prepare:allow"), current

    def cred_transfer(self, parent: Principal, child: Principal) -> Decision:
        """Run every module's restrictive delegation hook."""
        return self._restrictive_sync(
            lambda module: module.cred_transfer(
                parent, child, child.security.allocate(module.name)
            ),
            principal=child,
            stage="cred_transfer",
        )

    async def acred_transfer(self, parent: Principal, child: Principal) -> Decision:
        """Asynchronously run restrictive delegation hooks."""
        return await self._restrictive_async(
            lambda module: module.cred_transfer(
                parent, child, child.security.allocate(module.name)
            ),
            principal=child,
            stage="cred_transfer",
        )

    def resume_permission(self, principal: Principal, approval: Approval) -> Decision:
        """Run every module after a human approval response."""
        return self._restrictive_sync(
            lambda module: module.resume_permission(principal, approval),
            principal=principal,
            stage="resume",
        )

    async def aresume_permission(
        self, principal: Principal, approval: Approval
    ) -> Decision:
        """Asynchronously run every post-approval hook."""
        return await self._restrictive_async(
            lambda module: module.resume_permission(principal, approval),
            principal=principal,
            stage="resume",
        )

    def post(self, principal: Principal, call: ToolCall, result: Any) -> Decision:
        """Run every post hook; failures are reported but cannot alter the result."""
        for module in self.modules:
            if type(module).tool_call_post is SecurityModule.tool_call_post:
                continue
            started = self._started()
            future = self._executor.submit(
                module.tool_call_post,
                principal,
                call,
                result,
                call.tool.security.allocate(module.name),
            )
            try:
                hook_result = future.result(timeout=self.policy_timeout_s)
            except FutureTimeoutError:
                future.cancel()
                decision = Decision(Verdict.DENY, f"module_timeout:{module.name}")
            except BaseException:
                decision = Decision(Verdict.DENY, f"module_error:{module.name}")
            else:
                decision = (
                    Decision(Verdict.ALLOW, f"{module.name}:complete")
                    if hook_result is None
                    else Decision(Verdict.DENY, f"module_error:{module.name}")
                )
            self._observe(principal, call, "post", module.name, decision, started)
            if decision.verdict is not Verdict.ALLOW:
                return decision
        return Decision(Verdict.ALLOW, "post:complete")

    async def apost(
        self, principal: Principal, call: ToolCall, result: Any
    ) -> Decision:
        """Asynchronously run every post-execution hook."""
        for module in self.modules:
            if type(module).tool_call_post is SecurityModule.tool_call_post:
                continue
            started = self._started()
            loop = asyncio.get_running_loop()
            hook = cast(
                Callable[[], Any],
                partial(
                    module.tool_call_post,
                    principal,
                    call,
                    result,
                    call.tool.security.allocate(module.name),
                ),
            )
            try:
                hook_result = await asyncio.wait_for(
                    loop.run_in_executor(self._executor, hook), self.policy_timeout_s
                )
                if inspect.isawaitable(hook_result):
                    hook_result = await asyncio.wait_for(
                        hook_result, self.policy_timeout_s
                    )
            except TimeoutError:
                decision = Decision(Verdict.DENY, f"module_timeout:{module.name}")
            except BaseException:
                decision = Decision(Verdict.DENY, f"module_error:{module.name}")
            else:
                decision = (
                    Decision(Verdict.ALLOW, f"{module.name}:complete")
                    if hook_result is None
                    else Decision(Verdict.DENY, f"module_error:{module.name}")
                )
            self._observe(principal, call, "post", module.name, decision, started)
            if decision.verdict is not Verdict.ALLOW:
                return decision
        return Decision(Verdict.ALLOW, "post:complete")

    def _restrictive_sync(
        self,
        hook: Callable[[SecurityModule], Any],
        *,
        principal: Principal,
        stage: str,
    ) -> Decision:
        for module in self.modules:
            started = self._started()
            decision = self._sync_decision(module, partial(hook, module))
            self._observe(principal, None, stage, module.name, decision, started)
            if decision.verdict is not Verdict.ALLOW:
                return decision
        return Decision(Verdict.ALLOW, "stack:allow")

    async def _restrictive_async(
        self,
        hook: Callable[[SecurityModule], Any],
        *,
        principal: Principal,
        stage: str,
    ) -> Decision:
        for module in self.modules:
            started = self._started()
            decision = await self._async_decision(module, partial(hook, module))
            self._observe(principal, None, stage, module.name, decision, started)
            if decision.verdict is not Verdict.ALLOW:
                return decision
        return Decision(Verdict.ALLOW, "stack:allow")

    def _started(self) -> float | None:
        return perf_counter() if self.observer is not None else None

    def _observe(
        self,
        principal: Principal,
        call: ToolCall | None,
        stage: str,
        module: str,
        decision: Decision,
        started: float | None,
    ) -> None:
        if self.observer is None or started is None:
            return
        self.observer.record(
            SecurityEvent(
                stage=stage,
                module=module,
                verdict=decision.verdict,
                reason=decision.reason,
                latency_ms=(perf_counter() - started) * 1000,
                user_id=principal.user_id,
                tool_name=call.tool.name if call is not None else None,
                call_index=call.call_index if call is not None else None,
                args_hash=hash_args(call.args) if call is not None else "",
            )
        )

    def _sync_decision(
        self, module: SecurityModule, hook: Callable[[], Any]
    ) -> Decision:
        if isinstance(module, CapModule):
            result = hook()
            if not isinstance(result, Decision):
                return Decision(Verdict.DENY, "module_error:cap")
            return result
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
        if isinstance(module, CapModule):
            result = hook()
            if not isinstance(result, Decision):
                return Decision(Verdict.DENY, "module_error:cap")
            return result
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
