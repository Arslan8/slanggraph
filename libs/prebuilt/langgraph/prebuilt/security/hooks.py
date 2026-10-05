"""Graph-independent interface implemented by security policy modules."""

from __future__ import annotations

from typing import Any

from langgraph.prebuilt.security.types import (
    Approval,
    Decision,
    Principal,
    Slot,
    Tool,
    ToolCall,
    Verdict,
)


class SecurityModule:
    """Base class for composable, restrictive tool-security policies.

    Subclasses override only the hooks they need. Every decision hook defaults
    to `ALLOW`, which means "no objection" and never overrides another deny.
    Allocation, preparation, and post-execution hooks default to no action.
    """

    name = "module"
    can_escalate = False

    def tool_alloc_security(self, tool: Tool, slot: Slot) -> None:
        """Initialize this module's private slot on a tool."""

    def cred_prepare(self, principal: Principal, slot: Slot) -> None:
        """Initialize this module's private slot on a principal."""

    def cred_transfer(
        self, parent: Principal, child: Principal, slot: Slot
    ) -> Decision:
        """Restrict authority transferred from a parent to a child principal."""
        return Decision(Verdict.ALLOW, "default")

    def tool_call_prepare(self, principal: Principal, call: ToolCall) -> Decision:
        """Optionally narrow tool arguments before permission checks."""
        return Decision(Verdict.ALLOW, "default")

    def tool_call_permission(self, principal: Principal, call: ToolCall) -> Decision:
        """Object to a tool call before execution."""
        return Decision(Verdict.ALLOW, "default")

    def tool_call_post(
        self,
        principal: Principal,
        call: ToolCall,
        result: Any,
        slot: Slot,
    ) -> None:
        """Observe a completed tool call without changing its result."""

    def resume_permission(self, principal: Principal, approval: Approval) -> Decision:
        """Object after a human approval or rejection resumes execution."""
        return Decision(Verdict.ALLOW, "default")
