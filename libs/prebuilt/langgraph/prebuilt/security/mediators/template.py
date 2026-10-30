"""Copy this tutorial skeleton to implement a new resource mediator.

This is deliberately not a functioning backend: assessment is UNSUPPORTED and
activation/invocation refuse to run. Do not change assessment to EXACT until
the resource semantics, bypass prevention, and conformance tests are implemented.
See README.md in this directory for the manifest and registration example.
"""

from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Any

from langgraph.prebuilt.security.enforcement import HostAttestation, SupportLevel
from langgraph.prebuilt.security.mediators.contracts import ResourceContract
from langgraph.prebuilt.security.object_policy import ObjectGrantLine
from langgraph.prebuilt.security.resource_mediator import (
    ResourceInvocation,
    ResourceMediatorAdapter,
    ResourceSupport,
)


class ExampleAPI(ABC):
    """One definition for the client, effect inference, and backend signature."""

    __slots__ = ()

    @abstractmethod
    def read(self) -> str:
        raise NotImplementedError


EXAMPLE = ResourceContract(
    ExampleAPI,
    class_name="example",
    object_kind="item",
    lowering="tutorial.example.v1",
)
example = EXAMPLE.client(export=__name__ + ".example")


class ExampleBackend(ExampleAPI):
    def read(self) -> str:
        # TODO: Perform the exact authorized operation with bounded I/O.
        # current_invocation() supplies authenticated context if needed.
        raise NotImplementedError("tutorial mediator invocation is not implemented")


class ExampleMediator:
    """Implement lowering support and per-request validation here."""

    def assess(self, line: ObjectGrantLine, host: HostAttestation) -> ResourceSupport:
        # The framework already matched this object, operation, and contract.
        # TODO: Describe how this backend enforces the requested permission.
        # Check host capabilities and declare protected credential/data paths.
        # Supported results require a real conformance-test witness.
        return ResourceSupport(
            SupportLevel.UNSUPPORTED, "tutorial.example.v1 is not implemented"
        )

    def validate(
        self, operation: str, arguments: Mapping[str, Any], context: ResourceInvocation
    ) -> None:
        # TODO: Validate application-specific limits before backend effects.
        raise NotImplementedError("tutorial mediator validation is not implemented")


def example_resource() -> ResourceContract[ExampleAPI]:
    """Build an unimplemented tutorial adapter; it grants no resource authority."""

    def preflight(
        lines: tuple[ObjectGrantLine, ...], context: ResourceInvocation
    ) -> None:
        # TODO: Prepare immutable schemas, clients, or invocation-local caches
        # before activation and before the worker is released.
        raise NotImplementedError("tutorial mediator preflight is not implemented")

    def activate(
        lines: tuple[ObjectGrantLine, ...], context: ResourceInvocation
    ) -> None:
        # TODO: Establish parent-owned clients/leases for this authenticated
        # invocation before worker execution. Clean up if activation fails.
        raise NotImplementedError("tutorial mediator activation is not implemented")

    def release(context: ResourceInvocation) -> None:
        # TODO: Release only this invocation's clients/leases once its activity
        # stops. This empty template allocates nothing, so cleanup has no work.
        pass

    return EXAMPLE.bind(
        implementation=ExampleBackend(),
        mediator=ExampleMediator(),
        preflight=preflight,
        activate=activate,
        release=release,
    )


def example_mediator() -> ResourceMediatorAdapter:
    """Compatibility access to the tutorial resource adapter."""
    return example_resource().adapter
