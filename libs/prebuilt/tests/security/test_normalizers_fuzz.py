"""Property-based fuzz targets for every resource normalizer."""

from __future__ import annotations

import os

from hypothesis import given
from hypothesis import strategies as st

from langgraph.prebuilt.security import NORMALIZERS


@given(st.text())
def test_realpath_fuzz(value: str) -> None:
    """Successful path normalization is absolute and idempotent."""
    try:
        normalized = NORMALIZERS["realpath"](value)
    except (TypeError, ValueError, OSError):
        return
    assert os.path.isabs(normalized)
    assert NORMALIZERS["realpath"](normalized) == normalized


@given(st.text())
def test_domain_fuzz(value: str) -> None:
    """Successful domain normalization is lowercase and idempotent."""
    try:
        normalized = NORMALIZERS["domain"](value)
    except (TypeError, ValueError):
        return
    assert normalized == normalized.lower()
    assert NORMALIZERS["domain"](normalized) == normalized


@given(st.text())
def test_email_domain_fuzz(value: str) -> None:
    """Email normalization never returns an unnormalized host."""
    try:
        normalized = NORMALIZERS["email_domain"](value)
    except (TypeError, ValueError):
        return
    assert NORMALIZERS["domain"](normalized) == normalized


@given(st.text())
def test_sql_statement_kind_fuzz(value: str) -> None:
    """SQL classification returns one lowercase alphabetic keyword."""
    try:
        normalized = NORMALIZERS["sql_statement_kind"](value)
    except (TypeError, ValueError):
        return
    assert normalized.isascii()
    assert normalized.isalpha()
    assert normalized == normalized.lower()


@given(st.one_of(st.text(), st.lists(st.text(), max_size=20)))
def test_shell_argv0_fuzz(value: str | list[str]) -> None:
    """Shell normalization returns a single control-free basename."""
    try:
        normalized = NORMALIZERS["shell_argv0"](value)
    except (TypeError, ValueError):
        return
    assert normalized
    assert os.path.basename(normalized) == normalized
    assert not any(ord(char) < 32 or ord(char) == 127 for char in normalized)
