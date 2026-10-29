"""Shared complete-workflow model timing for the ordinary-demo campaign."""

from __future__ import annotations

import time


class ModelTiming:
    """Accumulate model-call wall time without changing application behavior."""

    def __init__(self) -> None:
        self.calls = 0
        self.wall_ms = 0.0

    def invoke(self, runnable, *args, **kwargs):
        started = time.perf_counter()
        try:
            return runnable.invoke(*args, **kwargs)
        finally:
            self.calls += 1
            self.wall_ms += (time.perf_counter() - started) * 1000

    async def ainvoke(self, runnable, *args, **kwargs):
        started = time.perf_counter()
        try:
            return await runnable.ainvoke(*args, **kwargs)
        finally:
            self.calls += 1
            self.wall_ms += (time.perf_counter() - started) * 1000
