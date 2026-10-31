"""Runtime `dataset_read`: policy before open, pinned openat2 read, exact bytes."""

from __future__ import annotations

import asyncio
import csv
import hashlib
import inspect
import os
import sys
from pathlib import Path

import pytest

from langgraph.prebuilt.security import dataset_operation
from langgraph.prebuilt.security.dataset_operation import (
    DatasetEntry,
    DatasetReadRequest,
    DatasetRegistry,
    aread_dataset,
    read_dataset,
)
from langgraph.prebuilt.security.types import (
    Decision,
    ForbidConstraint,
    Principal,
    RulePredicate,
    Verdict,
)
from langgraph.prebuilt.security.unsupported import (
    REGISTRY,
    RefusalCategory,
    UnsupportedFeatureError,
)

pytestmark = pytest.mark.skipif(
    sys.platform not in {"linux", "darwin"}, reason="native pinned read required"
)

PRINCIPAL = Principal("analyst", frozenset(), frozenset(), "session-1")
ALLOW = Decision(Verdict.ALLOW, "dataset_read permitted")
DENY = Decision(Verdict.DENY, "dataset_read forbidden")


def _sales_fixture(root: Path) -> bytes:
    """Write `sales.csv` exactly as eval `reset_fixture` (sales-v1) does."""
    rows = [
        ("2026-01-05", "North", 100),
        ("2026-01-10", "South", 60),
        ("2026-02-05", "North", 80),
        ("2026-02-12", "South", 40),
        ("2026-03-01", "North", 20),
        ("2026-03-08", "South", 100),
    ]
    with (root / "sales.csv").open("w") as stream:
        writer = csv.writer(stream)
        writer.writerow(["date", "region", "sales"])
        writer.writerows(rows)
    return (root / "sales.csv").read_bytes()


@pytest.fixture
def root(tmp_path: Path) -> Path:
    return tmp_path.resolve()


@pytest.fixture
def sales(root: Path) -> tuple[bytes, DatasetRegistry]:
    data = _sales_fixture(root)
    entry = DatasetEntry(
        "sales",
        str(root / "sales.csv"),
        hashlib.sha256(data).hexdigest(),
        4096,
    )
    return data, DatasetRegistry((entry,))


class Recorder:
    def __init__(self, decision: object) -> None:
        self.decision = decision
        self.requests: list[tuple[Principal, DatasetReadRequest]] = []

    def __call__(self, principal: Principal, request: DatasetReadRequest) -> object:
        self.requests.append((principal, request))
        return self.decision


@pytest.fixture
def opens(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []
    real = dataset_operation.open_path_descriptor

    def counted(path: str, *, no_symlinks: bool = False) -> int:
        calls.append(path)
        assert no_symlinks is True
        return real(path, no_symlinks=no_symlinks)

    monkeypatch.setattr(dataset_operation, "open_path_descriptor", counted)
    return calls


def _code(info: pytest.ExceptionInfo[UnsupportedFeatureError]) -> str:
    return info.value.code


def test_allowed_read_returns_exact_fixture_bytes(sales, opens) -> None:
    data, registry = sales
    authorize = Recorder(ALLOW)
    result = read_dataset(PRINCIPAL, "sales", registry=registry, authorize=authorize)
    assert type(result) is bytes and result == data
    assert result.startswith(b"date,region,sales\r\n2026-01-05,North,100\r\n")
    assert authorize.requests == [(PRINCIPAL, DatasetReadRequest("sales", "analyst"))]
    assert opens == [registry.entries["sales"].path]


@pytest.mark.parametrize(
    "decision",
    [
        DENY,
        Decision(Verdict.REDACT, "x", new_args={}),
        Decision(
            Verdict.ALLOW,
            "x",
            constraints=(ForbidConstraint("c", RulePredicate(), "r"),),
        ),
        True,
        "allow",
        None,
    ],
)
def test_non_allow_denies_before_any_open(sales, opens, decision) -> None:
    _, registry = sales
    with pytest.raises(UnsupportedFeatureError) as info:
        read_dataset(
            PRINCIPAL, "sales", registry=registry, authorize=Recorder(decision)
        )
    assert _code(info) == "dataset:denied"
    assert opens == []


def test_sync_route_rejects_async_authorizer_without_open(sales, opens) -> None:
    _, registry = sales

    async def authorize(principal, request):
        return ALLOW

    with pytest.raises(UnsupportedFeatureError) as info:
        read_dataset(PRINCIPAL, "sales", registry=registry, authorize=authorize)
    assert _code(info) == "dataset:denied"
    assert opens == []


def test_unknown_id_refuses_without_policy_or_open(sales, opens) -> None:
    _, registry = sales
    authorize = Recorder(ALLOW)
    with pytest.raises(UnsupportedFeatureError) as info:
        read_dataset(PRINCIPAL, "payroll", registry=registry, authorize=authorize)
    assert _code(info) == "dataset:unknown"
    assert authorize.requests == [] and opens == []


def test_symlinked_final_component_refused(root, sales) -> None:
    data, _ = sales
    real = root / "real.csv"
    real.write_bytes(data)
    link = root / "linked.csv"
    link.symlink_to(real)
    registry = DatasetRegistry(
        (DatasetEntry("s", str(link), hashlib.sha256(data).hexdigest(), 4096),)
    )
    with pytest.raises(UnsupportedFeatureError) as info:
        read_dataset(PRINCIPAL, "s", registry=registry, authorize=Recorder(ALLOW))
    assert _code(info) == "dataset:changed"


def test_symlinked_parent_component_refused(root, sales) -> None:
    data, _ = sales
    (root / "dir").mkdir()
    (root / "dir" / "sales.csv").write_bytes(data)
    (root / "alias").symlink_to(root / "dir")
    registry = DatasetRegistry(
        (
            DatasetEntry(
                "s",
                str(root / "alias" / "sales.csv"),
                hashlib.sha256(data).hexdigest(),
                4096,
            ),
        )
    )
    with pytest.raises(UnsupportedFeatureError) as info:
        read_dataset(PRINCIPAL, "s", registry=registry, authorize=Recorder(ALLOW))
    assert _code(info) == "dataset:changed"


def test_changed_content_refused(sales) -> None:
    data, registry = sales
    path = Path(registry.entries["sales"].path)
    path.write_bytes(data.replace(b"North,100", b"North,999"))
    with pytest.raises(UnsupportedFeatureError) as info:
        read_dataset(PRINCIPAL, "sales", registry=registry, authorize=Recorder(ALLOW))
    assert _code(info) == "dataset:changed"
    assert info.value.__cause__ is None and info.value.__suppress_context__ is False


def test_non_regular_file_refused(root) -> None:
    os.mkfifo(root / "pipe.csv")
    registry = DatasetRegistry(
        (DatasetEntry("p", str(root / "pipe.csv"), "0" * 64, 16),)
    )
    with pytest.raises(UnsupportedFeatureError) as info:
        read_dataset(PRINCIPAL, "p", registry=registry, authorize=Recorder(ALLOW))
    assert _code(info) == "dataset:changed"


def test_missing_file_unavailable(root) -> None:
    registry = DatasetRegistry(
        (DatasetEntry("m", str(root / "missing.csv"), "0" * 64, 16),)
    )
    with pytest.raises(UnsupportedFeatureError) as info:
        read_dataset(PRINCIPAL, "m", registry=registry, authorize=Recorder(ALLOW))
    assert _code(info) == "dataset:unavailable"


def test_oversize_refused(sales) -> None:
    data, _ = sales
    entry = DatasetEntry(
        "sales",
        sales[1].entries["sales"].path,
        hashlib.sha256(data).hexdigest(),
        len(data) - 1,
    )
    with pytest.raises(UnsupportedFeatureError) as info:
        read_dataset(
            PRINCIPAL,
            "sales",
            registry=DatasetRegistry((entry,)),
            authorize=Recorder(ALLOW),
        )
    assert _code(info) == "dataset:too_large"


def test_cap_enforced_while_reading(sales, monkeypatch) -> None:
    """A stale `st_size` cannot lift the cap; the read itself stops at cap + 1."""
    data, registry = sales
    entry = DatasetEntry(
        "sales",
        registry.entries["sales"].path,
        hashlib.sha256(data).hexdigest(),
        10,
    )
    real_fstat = os.fstat

    class Small:
        def __init__(self, result: os.stat_result) -> None:
            self._result = result

        def __getattr__(self, name: str) -> object:
            if name == "st_size":
                return 0
            return getattr(self._result, name)

    monkeypatch.setattr(dataset_operation.os, "fstat", lambda fd: Small(real_fstat(fd)))
    reads: list[int] = []
    real_read = os.read

    def counted_read(fd: int, n: int) -> bytes:
        reads.append(n)
        return real_read(fd, n)

    monkeypatch.setattr(dataset_operation.os, "read", counted_read)
    with pytest.raises(UnsupportedFeatureError) as info:
        read_dataset(
            PRINCIPAL,
            "sales",
            registry=DatasetRegistry((entry,)),
            authorize=Recorder(ALLOW),
        )
    assert _code(info) == "dataset:too_large"
    assert sum(reads) <= 11


def test_exact_cap_is_allowed(sales) -> None:
    data, registry = sales
    entry = DatasetEntry(
        "sales",
        registry.entries["sales"].path,
        registry.entries["sales"].sha256,
        len(data),
    )
    assert (
        read_dataset(
            PRINCIPAL,
            "sales",
            registry=DatasetRegistry((entry,)),
            authorize=Recorder(ALLOW),
        )
        == data
    )


def test_api_accepts_ids_only(sales, opens) -> None:
    _, registry = sales
    params = inspect.signature(read_dataset).parameters
    assert list(params) == ["principal", "dataset_id", "registry", "authorize"]
    assert list(inspect.signature(aread_dataset).parameters) == list(params)
    for bad in (
        registry.entries["sales"].path,
        "../sales.csv",
        "sales/../x",
        Path("sales"),
        b"sales",
        "",
    ):
        with pytest.raises(TypeError):
            read_dataset(PRINCIPAL, bad, registry=registry, authorize=Recorder(ALLOW))
    assert opens == []


def test_principal_and_registry_types_exact(sales) -> None:
    _, registry = sales

    class SubRegistry(DatasetRegistry):
        pass

    with pytest.raises(TypeError):
        read_dataset("analyst", "sales", registry=registry, authorize=Recorder(ALLOW))  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        read_dataset(
            PRINCIPAL,
            "sales",
            registry=dict(registry.entries),  # type: ignore[arg-type]
            authorize=Recorder(ALLOW),
        )
    with pytest.raises(TypeError):
        read_dataset(
            PRINCIPAL,
            "sales",
            registry=SubRegistry(tuple(registry.entries.values())),
            authorize=Recorder(ALLOW),
        )
    with pytest.raises(TypeError):
        read_dataset(PRINCIPAL, "sales", registry=registry, authorize=None)  # type: ignore[arg-type]


def test_registry_validation(sales) -> None:
    _, registry = sales
    good = registry.entries["sales"]
    with pytest.raises(TypeError):
        DatasetRegistry([good])  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        DatasetRegistry((("sales", good.path),))  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        DatasetRegistry((good, good))
    for kwargs in (
        {"path": "relative.csv"},
        {"path": "/a/../b.csv"},
        {"path": "/a//b.csv"},
        {"path": "/"},
        {"sha256": "A" * 64},
        {"sha256": "0" * 63},
        {"max_bytes": 0},
        {"max_bytes": True},
        {"max_bytes": 1.0},
        {"format": "parquet"},
        {"dataset_id": "../x"},
    ):
        fields = {
            "dataset_id": "x",
            "path": "/x.csv",
            "sha256": "0" * 64,
            "max_bytes": 1,
            "format": "csv",
        }
        fields.update(kwargs)
        with pytest.raises((TypeError, ValueError)):
            DatasetEntry(**fields)  # type: ignore[arg-type]
    with pytest.raises(AttributeError):
        registry.entries = {}  # type: ignore[misc]
    with pytest.raises(TypeError):
        registry.entries["other"] = good  # type: ignore[index]


def test_async_allowed_and_denied(sales, opens) -> None:
    data, registry = sales

    async def allow(principal, request):
        return ALLOW

    async def deny(principal, request):
        return DENY

    assert (
        asyncio.run(
            aread_dataset(PRINCIPAL, "sales", registry=registry, authorize=allow)
        )
        == data
    )
    assert len(opens) == 1
    with pytest.raises(UnsupportedFeatureError) as info:
        asyncio.run(
            aread_dataset(PRINCIPAL, "sales", registry=registry, authorize=deny)
        )
    assert _code(info) == "dataset:denied"
    assert len(opens) == 1
    assert (
        asyncio.run(
            aread_dataset(
                PRINCIPAL, "sales", registry=registry, authorize=Recorder(ALLOW)
            )
        )
        == data
    )


def test_async_refusals(root, sales, opens) -> None:
    data, registry = sales
    with pytest.raises(UnsupportedFeatureError) as info:
        asyncio.run(
            aread_dataset(
                PRINCIPAL, "nope", registry=registry, authorize=Recorder(ALLOW)
            )
        )
    assert _code(info) == "dataset:unknown"
    Path(registry.entries["sales"].path).write_bytes(data + b"extra\r\n")
    with pytest.raises(UnsupportedFeatureError) as info:
        asyncio.run(
            aread_dataset(
                PRINCIPAL, "sales", registry=registry, authorize=Recorder(ALLOW)
            )
        )
    assert _code(info) == "dataset:changed"
    with pytest.raises(TypeError):
        asyncio.run(
            aread_dataset(
                PRINCIPAL,
                "/etc/passwd",
                registry=registry,
                authorize=Recorder(ALLOW),
            )
        )


def test_codes_registered_with_categories() -> None:
    expected = {
        "dataset:unknown": RefusalCategory.UNSUPPORTED,
        "dataset:denied": RefusalCategory.POLICY_DENIED,
        "dataset:too_large": RefusalCategory.UNSUPPORTED,
        "dataset:changed": RefusalCategory.POLICY_DENIED,
        "dataset:unavailable": RefusalCategory.EXECUTION_FAILED,
    }
    for code, category in expected.items():
        assert REGISTRY[code].category is category
        assert UnsupportedFeatureError(code).record is REGISTRY[code]
