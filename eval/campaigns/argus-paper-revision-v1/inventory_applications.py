"""Generate reproducible source, effort, manifest and policy inventory tables."""

from __future__ import annotations

import ast
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
APPS = ROOT / "eval/apps/demos"
OUT = Path(__file__).with_name("generated")
REVISION = "23961cff61a42b52525f3b20b4094d8d2fba1744"
PANDAS_REVISION = "4ffeb7f38178aa250917f29b01355f8b89ba809e"
APPLICATIONS = {
    "D1 SQL": ("sql_agent.py", "SQL record mediator", "query/read"),
    "D2 RAG": ("agentic_rag.py", "retriever mediator", "retrieve"),
    "D3 plan-execute": ("plan_execute.py", "search mediator", "search"),
    "D4 multi-agent": ("multi_agent.py", "persistent Python mediator", "search/execute"),
    "D5 support": (
        "customer_support.py",
        "travel/policy/search mediators",
        "read/search/update/cancel",
    ),
    "T1 add-tools": ("add_tools_protected.py", "search mediator", "search"),
    "T2 custom-weather": ("tool_calling_protected.py", "generic tool worker", "weather"),
    "T3 fixed-weather": ("tool_calling_protected.py", "generic tool worker", "weather"),
    "T4 parallel-weather": ("tool_calling_protected.py", "generic tool worker", "weather/parallel"),
    "T5 multiply": ("tool_calling_protected.py", "generic tool worker", "multiply"),
    "T6 return-direct": ("tool_calling_protected.py", "generic tool worker", "add"),
    "T7 forced-tool": ("tool_calling_protected.py", "generic tool worker", "greet"),
    "T8 serial-tools": ("tool_calling_protected.py", "generic tool worker", "add/multiply"),
    "T9 add-memory": ("persistence_protected.py", "search mediator", "search/checkpoint-tip"),
    "T10 time-travel": (
        "persistence_protected.py",
        "search + mediated checkpoint",
        "search/history-restore",
    ),
}
RUNTIME_CONFIGURATION_SIZES = {
    "D1 SQL": ([31, 651], [47, 1002], [1, 65], [1, 67]),
    "D2 RAG": ([21, 373], [15, 334], [1, 65], [1, 67]),
    "D3 plan-execute": ([21, 390], [15, 356], [1, 65], [1, 67]),
    "D4 multi-agent": ([35, 664], [31, 671], [1, 65], [1, 67]),
    "D5 support": ([64, 1412], [95, 2139], [1, 65], [1, 67]),
    "T1 add-tools": ([4, 48], [6, 136], [1, 65], [6, 83]),
    "T2 custom-weather": ([4, 46], [6, 134], [1, 65], [1, 67]),
    "T3 fixed-weather": ([4, 46], [6, 134], [1, 65], [1, 67]),
    "T4 parallel-weather": ([8, 100], [13, 276], [1, 65], [1, 67]),
    "T5 multiply": ([4, 43], [6, 131], [1, 65], [1, 67]),
    "T6 return-direct": ([4, 38], [6, 126], [1, 65], [1, 67]),
    "T7 forced-tool": ([4, 40], [6, 128], [1, 65], [1, 67]),
    "T8 serial-tools": ([8, 82], [13, 258], [1, 65], [1, 67]),
    "T9 add-memory": ([4, 48], [6, 136], [1, 65], [6, 83]),
    "T10 time-travel": ([4, 48], [6, 136], [1, 65], [6, 83]),
}
SECURITY_WORDS = {
    "admission",
    "audit",
    "cedar",
    "dispatcher",
    "grant",
    "lean",
    "manifest",
    "mediator",
    "policy",
    "principal",
    "security",
    "with_principal",
}
ENVIRONMENT_WORDS = {"base_url", "environment", "model", "path", "root", "seed"}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def classify(path: Path) -> dict[str, int]:
    source = path.read_text()
    lines = source.splitlines()
    categories = [None] * len(lines)
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            continue
        text = "\n".join(lines[node.lineno - 1 : node.end_lineno]).casefold()
        category = None
        if any(word in text for word in SECURITY_WORDS):
            category = "security_integration"
        elif any(word in text for word in ENVIRONMENT_WORDS):
            category = "environment_setup"
        if category:
            for index in range(node.lineno - 1, node.end_lineno):
                categories[index] = category
    counts = {key: 0 for key in ("environment_setup", "security_integration", "application_logic")}
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        category = categories[index]
        if category is None:
            lowered = stripped.casefold()
            if stripped.startswith(("import ", "from ")) or any(
                word in lowered for word in ENVIRONMENT_WORDS
            ):
                category = "environment_setup"
            elif any(word in lowered for word in SECURITY_WORDS):
                category = "security_integration"
            else:
                category = "application_logic"
        counts[category] += 1
    counts["changed_lines"] = sum(counts.values())
    return counts


def policy_sizes(path: Path) -> dict[str, int]:
    tree = ast.parse(path.read_text())
    manifests = []
    policies = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        value = node.value.strip()
        if "runs " in value and "returns " in value:
            manifests.append(value)
        if "permit(" in value or "forbid(" in value:
            policies.append(value)
    return {
        "manifest_lines": sum(len(value.splitlines()) for value in manifests),
        "manifest_bytes": sum(len(value.encode()) for value in manifests),
        "cedar_lines": sum(len(value.splitlines()) for value in policies),
        "cedar_bytes": sum(len(value.encode()) for value in policies),
    }


def patch(path: Path, destination: Path) -> None:
    result = subprocess.run(
        ["git", "diff", "--no-index", "--", "/dev/null", str(path)],
        cwd=ROOT,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
    )
    if result.returncode not in {0, 1}:
        raise RuntimeError("failed to generate adapter patch")
    destination.write_text(result.stdout)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    patches = OUT / "patches"
    patches.mkdir(exist_ok=True)
    file_records = {}
    for filename in sorted({value[0] for value in APPLICATIONS.values()}):
        path = APPS / filename
        file_records[filename] = {
            "path": str(path.relative_to(ROOT)),
            "sha256": sha(path),
            **classify(path),
            **policy_sizes(path),
        }
        patch(path, patches / f"{path.stem}.patch")
    rows = []
    for application, (filename, mediators, operations) in APPLICATIONS.items():
        manifest, owner, principal, operator = RUNTIME_CONFIGURATION_SIZES[application]
        rows.append(
            {
                "application": application,
                "upstream_revision": REVISION,
                "adapter": file_records[filename],
                "exact_adapter_patch": str(
                    (patches / f"{Path(filename).stem}.patch").relative_to(OUT)
                ),
                "mediators": mediators,
                "supported_operations": operations,
                "unsupported_operations": (
                    "history branching without an authenticated continuation"
                    if application == "T10 time-travel"
                    else "operations absent from the manifest"
                ),
                "runtime_configuration_size": {
                    "basis": "captured rendered configuration; values are [lines, UTF-8 bytes]",
                    "manifest": manifest,
                    "owner_cedar": owner,
                    "principal_cedar": principal,
                    "sealed_operator_cedar": operator,
                    "source_sha256": file_records[filename]["sha256"],
                },
            }
        )
    pandas_files = [
        ROOT / "eval/apps/pandas/integration_closed.py",
        ROOT / "eval/apps/pandas/sandbox_codec.py",
        ROOT / "eval/apps/pandas/workflow_contract.py",
    ]
    pandas = {
        "application": "Pandas case study",
        "upstream_revision": PANDAS_REVISION,
        "files": [],
        "mediators": "dataset read + output mediator; period helper newly implemented",
        "supported_operations": "ten frozen analysis tasks",
        "unsupported_operations": "arbitrary filesystem/network/process authority",
        "runtime_configuration_size": {
            "basis": "manifest-v23-full.json and its embedded UTF-8 Cedar strings",
            "manifest": [56, 2734],
            "principal_cedar": [1, 65],
            "sealed_operator_cedar": [1, 71],
        },
        "policy_manifest": {
            "path": "eval/apps/pandas/policy/manifest-v23-full.json",
            "sha256": sha(ROOT / "eval/apps/pandas/policy/manifest-v23-full.json"),
        },
    }
    for path in pandas_files:
        target = patches / f"pandas-{path.stem}.patch"
        patch(path, target)
        pandas["files"].append(
            {
                "path": str(path.relative_to(ROOT)),
                "sha256": sha(path),
                **classify(path),
                **policy_sizes(path),
                "exact_adapter_patch": str(target.relative_to(OUT)),
            }
        )
    record = {
        "schema": 1,
        "classification_method": (
            "nonblank physical lines; AST function/class ranges containing security or "
            "environment vocabulary, then deterministic line fallback; patches are full "
            "adapter additions because upstream examples are notebooks/Markdown"
        ),
        "applications": rows,
        "pandas": pandas,
    }
    (OUT / "application-inventory.json").write_text(json.dumps(record, indent=2) + "\n")


if __name__ == "__main__":
    main()
