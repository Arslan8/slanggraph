"""Grant-scoped random values with an inert generated client."""

from __future__ import annotations

import secrets
import string
from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Any

from langgraph.prebuilt.security.enforcement import HostAttestation, SupportLevel
from langgraph.prebuilt.security.mediators.contracts import ResourceContract
from langgraph.prebuilt.security.object_policy import ObjectGrantLine
from langgraph.prebuilt.security.resource_mediator import (
    ResourceInvocation,
    ResourceSupport,
)


class RandomValuesAPI(ABC):
    """Bounded random values used by booking-style tools."""

    __slots__ = ()

    @abstractmethod
    def appointment_time(self) -> str:
        """Return an office-hours time in `HH:MM:SS` form."""
        raise NotImplementedError

    @abstractmethod
    def booking_reference(self) -> str:
        """Return a six-character uppercase booking reference."""
        raise NotImplementedError


RANDOM_VALUES = ResourceContract(
    RandomValuesAPI,
    class_name="random_source",
    object_kind="generator",
    lowering="python.secrets.booking.v1",
)
random_values = RANDOM_VALUES.client(export=__name__ + ".random_values")


class _RandomValues(RandomValuesAPI):
    def appointment_time(self) -> str:
        hour = 8 + secrets.randbelow(10)
        minute = (0, 15, 30, 45)[secrets.randbelow(4)]
        return f"{hour:02d}:{minute:02d}:00"

    def booking_reference(self) -> str:
        alphabet = string.ascii_uppercase + string.digits
        return "".join(secrets.choice(alphabet) for _ in range(6))


class _RandomValuesMediator:
    def assess(self, line: ObjectGrantLine, host: HostAttestation) -> ResourceSupport:
        return ResourceSupport(
            SupportLevel.EXACT,
            "fixed-shape random strings; no module, callback, or generator state is exposed",
            witness="tests/security/test_library_mediators.py",
        )

    def validate(
        self,
        operation: str,
        arguments: Mapping[str, Any],
        context: ResourceInvocation,
    ) -> None:
        if arguments:
            raise ValueError("random value operations accept no arguments")


def random_values_resource() -> ResourceContract[RandomValuesAPI]:
    """Bind the shared API to Python's trusted `secrets` implementation."""
    return RANDOM_VALUES.bind(
        implementation=_RandomValues(), mediator=_RandomValuesMediator()
    )
