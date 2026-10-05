"""Allocation and copy helpers for per-module private security blobs."""

from __future__ import annotations

from collections.abc import Iterable

from langgraph.prebuilt.security.types import Blobs


def allocate_blobs(module_names: Iterable[str]) -> Blobs:
    """Allocate one independent empty slot for every unique module name."""
    blobs = Blobs()
    for name in module_names:
        blobs.allocate(name)
    return blobs


def copy_blobs(source: Blobs, module_names: Iterable[str] | None = None) -> Blobs:
    """Copy selected slots without sharing their mutable mappings."""
    selected = tuple(source) if module_names is None else tuple(module_names)
    copied = Blobs()
    for name in selected:
        if name in source:
            copied.allocate(name).update(source[name].snapshot())
        else:
            copied.allocate(name)
    return copied
