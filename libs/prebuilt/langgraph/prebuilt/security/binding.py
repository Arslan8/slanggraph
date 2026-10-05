"""Bind authenticated principals outside graph state and model messages."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence
from typing import Any, cast

from langchain_core.runnables import RunnableConfig

from langgraph.prebuilt.security.hooks import SecurityModule
from langgraph.prebuilt.security.stack import CapModule
from langgraph.prebuilt.security.types import Principal

PRINCIPAL_CONFIG_KEY = "__principal__"


class SecurityBindingError(RuntimeError):
    """Raised when a module fails while preparing a bound principal."""


def with_principal(
    config: RunnableConfig | None,
    principal: Principal,
    *,
    modules: Sequence[SecurityModule] = (),
) -> RunnableConfig:
    """Return a copied config containing a prepared authenticated principal.

    The reserved `configurable.__principal__` value is framework-owned. The
    principal is never read from graph state or messages. Each module receives
    only its named slot during credential preparation.
    """

    if not isinstance(principal, Principal):
        raise TypeError("principal must be a Principal")
    configured_modules = (CapModule(), *modules)
    names = [module.name for module in configured_modules]
    if len(names) != len(set(names)):
        raise ValueError("security module names must be unique")
    for module in configured_modules:
        slot = principal.security.allocate(module.name)
        try:
            module.cred_prepare(principal, slot)
        except BaseException as exc:
            raise SecurityBindingError(f"cred_prepare failed:{module.name}") from exc

    copied = dict(config or {})
    raw_configurable = copied.get("configurable")
    if raw_configurable is None:
        configurable: dict[str, Any] = {}
    elif isinstance(raw_configurable, Mapping):
        configurable = dict(raw_configurable)
    else:
        raise TypeError("configurable config must be a mapping")
    configurable[PRINCIPAL_CONFIG_KEY] = principal
    copied["configurable"] = configurable
    _bind_runtime_context(configurable, principal)
    return cast("RunnableConfig", copied)


def principal_from(config: Mapping[str, Any] | None) -> Principal | None:
    """Read a bound principal from the reserved config or runtime context."""

    if not config:
        return None
    configurable = config.get("configurable")
    if not isinstance(configurable, Mapping):
        return None
    candidate = configurable.get(PRINCIPAL_CONFIG_KEY)
    if candidate is None:
        runtime = configurable.get("__pregel_runtime")
        context = getattr(runtime, "context", None)
        if isinstance(context, Mapping):
            candidate = context.get(PRINCIPAL_CONFIG_KEY)
        else:
            candidate = getattr(context, PRINCIPAL_CONFIG_KEY, None)
    if candidate is None:
        return None
    if not isinstance(candidate, Principal):
        raise TypeError("reserved principal config contains an invalid value")
    return candidate


def _bind_runtime_context(
    configurable: MutableMapping[str, Any], principal: Principal
) -> None:
    runtime = configurable.get("__pregel_runtime")
    context = getattr(runtime, "context", None)
    if isinstance(context, MutableMapping):
        context[PRINCIPAL_CONFIG_KEY] = principal
