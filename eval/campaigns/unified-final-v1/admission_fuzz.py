"""Fixed-corpus differential fuzzing for the admitted language interpreter."""

from __future__ import annotations

import ast
import random
import time
import traceback
from collections import Counter
from pathlib import Path
from typing import Any

from campaign import write_json
from langgraph.prebuilt.security._language_sandbox import LanguageProgram
from langgraph.prebuilt.security.errors import SecurityConfigurationError
from langgraph.prebuilt.security.execution import HostExecutionDenied
from langgraph.prebuilt.security.language_verification import TerminalContract

SAFE_KINDS = ("while-branch", "for-range", "collections", "terminal", "terminal-alias")
MUTATION_KINDS = (
    "dynamic-import",
    "unregistered-import",
    "alias-rebinding",
    "reflection-dunder",
    "dynamic-code",
    "forged-terminal",
    "privileged-return",
    "malformed-ir",
)


def _safe_program(
    kind: str, randomizer: random.Random
) -> tuple[str, dict[str, str], Any, list[str]]:
    count = randomizer.randrange(0, 12)
    path = "/fixture/allowed"
    arguments = {"count": str(count), "path": path}
    if kind == "while-branch":
        source = """def f(count, path):
    i = 0
    total = 0
    while i < int(count):
        if i % 2 == 0:
            total += i
        else:
            total += 1
        i += 1
    return str(total)
"""
        expected = sum(value if value % 2 == 0 else 1 for value in range(count))
        return source, arguments, str(expected), []
    if kind == "for-range":
        source = """def f(count, path):
    total = 0
    for i in range(int(count)):
        if i < 3:
            continue
        total += i
    else:
        total += 7
    return str(total)
"""
        return source, arguments, str(sum(range(3, count)) + 7), []
    if kind == "collections":
        source = """def f(count, path):
    values = [int(count), 2, 3]
    result = {"count": values[0], "size": len(values)}
    return result
"""
        return source, arguments, {"count": count, "size": 3}, []
    if kind == "terminal":
        source = """def f(count, path):
    if int(count) >= 0:
        value = read_text(path)
    else:
        value = "unreachable"
    return value
"""
        return source, arguments, "fixture-value", ["read_text"]
    source = """def f(count, path):
    reader = read_text
    return reader(path)
"""
    return source, arguments, "fixture-value", ["read_text"]


def _mutation(kind: str) -> str:
    bodies = {
        "dynamic-import": "module = __import__('os')\n    return str(module)",
        "unregistered-import": "import os\n    return os.getcwd()",
        "alias-rebinding": "reader = read_text\n    reader = str\n    return reader(path)",
        "reflection-dunder": "return path.__class__.__mro__[1].__subclasses__()",
        "dynamic-code": "return eval(count)",
        "forged-terminal": "return read_text('/fixture/secret')",
        "privileged-return": "return read_text",
    }
    if kind == "malformed-ir":
        return "def f(count, path):\n    return path\n"
    return f"def f(count, path):\n    {bodies[kind]}\n"


def _lower(source: str, terminal) -> LanguageProgram:
    return LanguageProgram.lower(
        ast.parse(source).body[0],
        {"read_text": terminal},
        (),
        {},
        contracts={"read_text": TerminalContract((("path", "str"),), frozenset({"str"}))},
    )


def _fake_terminal(effects: list[tuple[str, str]]):
    def terminal(path: str) -> str:
        effects.append(("fs::read", path))
        if path != "/fixture/allowed":
            raise HostExecutionDenied("fuzz:operation_not_granted")
        return "fixture-value"

    return terminal


def run_fuzz(config: dict[str, Any], output: Path) -> dict[str, Any]:
    spec = config["admission_fuzz"]
    output.mkdir(parents=True, exist_ok=False)
    totals = Counter()
    coverage = Counter()
    seed_reports = []
    reproducers = []
    started = time.monotonic()
    for seed in spec["seeds"]:
        randomizer = random.Random(seed)
        seed_counts = Counter()
        for index in range(spec["programs_per_seed"]):
            totals["generated"] += 1
            seed_counts["generated"] += 1
            safe = index % 5 != 0
            kind = randomizer.choice(SAFE_KINDS if safe else MUTATION_KINDS)
            coverage[kind] += 1
            effects: list[tuple[str, str]] = []
            terminal = _fake_terminal(effects)

            try:
                if safe:
                    source, arguments, expected, expected_effects = _safe_program(kind, randomizer)
                    program = _lower(source, terminal)
                    totals["admitted"] += 1
                    seed_counts["admitted"] += 1
                    actual = program.invoke(arguments)
                    projected = [name for name, _ in effects]
                    if actual != expected or projected != ["fs::read"] * len(expected_effects):
                        totals["mismatches"] += 1
                        seed_counts["mismatches"] += 1
                        reproducers.append(
                            {
                                "seed": seed,
                                "index": index,
                                "kind": kind,
                                "source": source,
                                "arguments": arguments,
                                "expected": expected,
                                "actual": actual,
                                "effects": effects,
                            }
                        )
                    if any(path != "/fixture/allowed" for _, path in effects):
                        totals["security_violations"] += 1
                        seed_counts["security_violations"] += 1
                elif kind == "malformed-ir":
                    try:
                        LanguageProgram(
                            (("unknown",),), _lower(_mutation(kind), terminal).signature, {}, {}
                        ).proof()
                    except (SecurityConfigurationError, ValueError, TypeError):
                        totals["rejected"] += 1
                        seed_counts["rejected"] += 1
                    else:
                        totals["security_violations"] += 1
                        seed_counts["security_violations"] += 1
                else:
                    source = _mutation(kind)
                    try:
                        program = _lower(source, terminal)
                        program.invoke({"count": "1", "path": "/fixture/allowed"})
                    except (SecurityConfigurationError, HostExecutionDenied, ValueError, TypeError):
                        totals["rejected"] += 1
                        seed_counts["rejected"] += 1
                    else:
                        totals["security_violations"] += 1
                        seed_counts["security_violations"] += 1
                        reproducers.append(
                            {"seed": seed, "index": index, "kind": kind, "source": source}
                        )
            except TimeoutError:
                totals["timeouts"] += 1
                seed_counts["timeouts"] += 1
            except Exception as exc:  # retain unexpected interpreter failures
                totals["crashes"] += 1
                seed_counts["crashes"] += 1
                reproducers.append(
                    {
                        "seed": seed,
                        "index": index,
                        "kind": kind,
                        "error": repr(exc),
                        "traceback": traceback.format_exc(),
                    }
                )
        seed_reports.append({"seed": seed, **seed_counts})
    report = {
        "schema_version": 1,
        "corpus": "fixed generated corpus",
        "seeds": spec["seeds"],
        "programs_per_seed": spec["programs_per_seed"],
        "watchdog_seconds": spec["watchdog_seconds"],
        "watchdog_scope": "test harness only; production loops have no artificial bound",
        "reference": "independent generator-side evaluator with fake grant-checking terminal",
        "counts": {
            name: totals[name]
            for name in (
                "generated",
                "admitted",
                "rejected",
                "timeouts",
                "crashes",
                "mismatches",
                "security_violations",
            )
        },
        "construct_coverage": dict(sorted(coverage.items())),
        "seed_reports": seed_reports,
        "elapsed_seconds": time.monotonic() - started,
        "passed": totals["generated"] == len(spec["seeds"]) * spec["programs_per_seed"]
        and not any(
            totals[name] for name in ("timeouts", "crashes", "mismatches", "security_violations")
        ),
        "reproducer_count": len(reproducers),
    }
    write_json(output / "summary.json", report)
    write_json(output / "minimized-reproducers.json", reproducers)
    return report
