#!/usr/bin/env python3
"""Build and audit the language-route Lean model into a new evidence directory.

Steps: regenerate `Controls.lean` from the real Python lowering and checker and
require it to equal the committed file (no drift); require the Python verdicts
the controls encode; `lake build` (kernel typecheck); fresh `leanchecker`
replay; axiom audit of the published theorems. This verifies the finite model
and its agreement with the Python checker on the controls, not the Python
interpreter (trusted per docs/security/threat-model.md).
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
THEOREMS = (
    "LanguageRoute.checked_program_calls_only_registered",
    "LanguageRoute.checkStmts_calls_registered",
    "LanguageRoute.evalStmts_trace",
    "LanguageRoute.unregistered_call_refused",
    "LanguageEffects.checked_trace_registered",
)
ALLOWED_AXIOMS = {"propext", "Classical.choice", "Quot.sound"}
FORBIDDEN_TOKENS = ("sorry", "admit", "native_decide", "implemented_by", "extern")

USEFUL = {
    "reader": "def reader(path: str) -> str:\n    return read_text(path)\n",
    "two_reads": (
        "def two_reads(first: str, second: str) -> str:\n"
        "    return f'{read_text(first)}{read_text(second)}'\n"
    ),
    "select": (
        "def select(path: str, mode: str) -> str:\n"
        "    if mode == 'full':\n"
        "        return read_text(path)\n"
        "    return 'skipped'\n"
    ),
    "keyword": (
        "def keyword(path: str) -> str:\n"
        "    label = 'x'\n"
        "    return read_text(path=path)\n"
    ),
}
# IR the lowering never emits, built directly; derive_program must refuse each.
FORGED = {
    "unregistered_call": ((("return", ("call", "open_file", (("local", "path"),), ())),)),
    "compare_int": ((("return", ("compare", True, ("constant", 1), ("constant", "a"))),)),
    "join_int": ((("return", ("join", (("constant", 3),))),)),
    "branch_on_str": ((("if", ("local", "path"), (("return", ("local", "path")),), ()),)),
    "surplus_argument": (
        (("return", ("call", "read_text", (("local", "path"), ("local", "path")), ())),)
    ),
    "unknown_keyword": ((("return", ("call", "read_text", (), (("mode", ("local", "path")),))),)),
    "duplicate_keyword": (
        (("return", ("call", "read_text", (("local", "path"),), (("path", ("local", "path")),))),)
    ),
    "argument_type": ((("return", ("call", "read_text", (("constant", 7),), ())),)),
    "unbound_local": ((("return", ("local", "missing")),)),
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def lean_string(text: str) -> str:
    return json.dumps(text, ensure_ascii=False)


def lean_val(value) -> str:
    if type(value) is str:
        return f".str {lean_string(value)}"
    if type(value) is bool:
        return f".bool {'true' if value else 'false'}"
    if type(value) is int:
        return f".int ({value})"
    if type(value) is float:
        return f".float {lean_string(repr(value))}"
    if value is None:
        return ".none"
    raise ValueError(f"unencodable constant {value!r}")


def lean_list(items) -> str:
    return "[" + ", ".join(items) + "]"


def lean_expr(node) -> str:
    kind = node[0]
    if kind == "constant":
        return f"(.const ({lean_val(node[1])}))"
    if kind == "local":
        return f"(.local {lean_string(node[1])})"
    if kind == "join":
        return f"(.join {lean_list(lean_expr(p) for p in node[1])})"
    if kind == "compare":
        return f"(.compare {'true' if node[1] else 'false'} {lean_expr(node[2])} {lean_expr(node[3])})"
    if kind == "call":
        args = lean_list(lean_expr(p) for p in node[2])
        kws = lean_list(f"({lean_string(k)}, {lean_expr(v)})" for k, v in node[3])
        return f"(.call {lean_string(node[1])} {args} {kws})"
    raise ValueError(f"unencodable expression {kind}")


def lean_stmts(body) -> str:
    out = []
    for node in body:
        kind = node[0]
        if kind == "return":
            out.append(f"(.ret {lean_expr(node[1])})")
        elif kind == "expression":
            out.append(f"(.expr {lean_expr(node[1])})")
        elif kind == "assign":
            names = lean_list(lean_string(n) for n in node[1])
            out.append(f"(.assign {names} {lean_expr(node[2])})")
        elif kind == "if":
            out.append(f"(.ite {lean_expr(node[1])} {lean_stmts(node[2])} {lean_stmts(node[3])})")
        else:
            raise ValueError(f"unencodable statement {kind}")
    return lean_list(out)


def lean_ty(kinds) -> str:
    fields = {"str": "str", "int": "int", "float": "float", "bool": "bool", "NoneType": "none", "dict": "dict"}
    parts = [f"{fields[k]} := true" for k in sorted(kinds)]
    return "{ " + ", ".join(parts) + " }" if parts else "Ty.empty"


def generate_controls() -> tuple[str, dict]:
    from inspect import Signature

    from langgraph.prebuilt.security._language_sandbox import LanguageProgram
    from langgraph.prebuilt.security.errors import SecurityConfigurationError
    from langgraph.prebuilt.security.inprocess import read_text
    from langgraph.prebuilt.security.language_verification import (
        TerminalContract,
        derive_program,
    )

    contracts = {"read_text": TerminalContract((("path", "str"),), frozenset({"str"}))}
    lines = [
        "import LanguageRoute",
        "/-! Generated by check.py from the real Python lowering and checker; do not edit. -/",
        "namespace LanguageRoute.Controls",
        "open LanguageRoute",
        "",
        'def C : Contracts := [("read_text", { params := [("path", .str)], result := { str := true } })]',
        "",
    ]
    verdicts: dict = {"useful": {}, "forged": {}}
    for name, source in USEFUL.items():
        program = LanguageProgram.lower(
            ast.parse(source).body[0], {"read_text": read_text}, (), {}, contracts=contracts
        )
        proof = program.proof()
        params = lean_list(lean_string(p) for p in program.signature.parameters)
        lines.append(f"def {name}_params : List String := {params}")
        lines.append(f"def {name}_body : List Stmt := {lean_stmts(program.body)}")
        lines.append(
            f"example : checkProgram C {name}_params {name}_body = some ({lean_ty(proof['result_types'])}) := by decide"
        )
        lines.append("")
        verdicts["useful"][name] = {"python": "accepted", "result_types": proof["result_types"]}
    for name, body in FORGED.items():
        signature = Signature.from_callable(lambda path: path)  # one string parameter
        try:
            derive_program(body, signature, contracts)
            python = "accepted"
        except SecurityConfigurationError as exc:
            python = str(exc)
        lines.append(f"def {name}_body : List Stmt := {lean_stmts(body)}")
        lines.append(f'example : checkProgram C ["path"] {name}_body = none := by decide')
        lines.append("")
        verdicts["forged"][name] = {"python": python}
    lines.append("end LanguageRoute.Controls")
    return "\n".join(lines) + "\n", verdicts


# The value/type model above retains its original straight-line scope. This
# independent effect projection covers the extended control-flow IR, including
# every finite prefix of arbitrary iteration. Unknown instructions fail export.
def effect_sequence(parts):
    result = ".pure"
    for part in reversed(list(parts)):
        result = f"(.seq {part} {result})"
    return result


def effect_expr(node):
    kind = node[0]
    if kind in {"constant", "local"}:
        return ".pure"
    if kind == "join":
        return effect_sequence(effect_expr(p) for p in node[1])
    if kind == "compare":
        return effect_sequence(effect_expr(p) for p in node[2:])
    if kind == "pure":
        return effect_sequence(effect_expr(p) for p in node[2])
    if kind == "call":
        return effect_sequence([*(effect_expr(p) for p in node[2]),
                                *(effect_expr(p) for _, p in node[3]),
                                f"(.effect {lean_string(node[1])})"])
    raise ValueError(f"unprojectable expression {kind}")


def effect_stmts(body):
    parts = []
    for node in body:
        kind = node[0]
        if kind in {"return", "expression"}:
            parts.append(effect_expr(node[1]))
        elif kind == "assign":
            parts.append(effect_expr(node[2]))
        elif kind == "if":
            parts.append(f"(.seq {effect_expr(node[1])} (.choice {effect_stmts(node[2])} {effect_stmts(node[3])}))")
        elif kind == "while":
            test, loop, otherwise = effect_expr(node[1]), effect_stmts(node[2]), effect_stmts(node[3])
            parts.append(f"(.seq (.repeat (.seq {test} {loop})) (.seq {test} {otherwise}))")
        else:
            raise ValueError(f"unprojectable statement {kind}")
    return effect_sequence(parts)


EFFECT_USEFUL = {
    **USEFUL,
    "while_reads": "def reads(path, count):\n    i = 0\n    while i < int(count):\n        read_text(path)\n        i += 1\n    return path\n",
    "for_reads": "def reads(path, count):\n    for i in range(int(count)):\n        read_text(path)\n    return path\n",
    "string_loop": "def count(path):\n    text = read_text(path)\n    n = 0\n    for c in text:\n        if c == 'x':\n            n += 1\n    return str(n)\n",
    "infinite": "def infinite(path):\n    while True:\n        read_text(path)\n",
}


def generate_effect_controls():
    from langgraph.prebuilt.security._language_sandbox import LanguageProgram
    from langgraph.prebuilt.security.language_verification import TerminalContract
    contracts = {"read_text": TerminalContract((("path", "str"),), frozenset({"str"}))}
    lines = ["import LanguageEffects", "namespace LanguageEffects.Controls", "open LanguageEffects", ""]
    for name, source in EFFECT_USEFUL.items():
        program = LanguageProgram.lower(ast.parse(source).body[0], {"read_text": lambda path: path}, (), {}, contracts=contracts)
        lines.append(f"def {name} : Code := {effect_stmts(program.body)}")
        lines.append(f'example : check ["read_text"] {name} = true := by decide')
    bad = (("while", ("constant", True), (("expression", ("call", "open", (), ())),), ()),)
    lines.append(f"def loop_escape : Code := {effect_stmts(bad)}")
    lines.append('example : check ["read_text"] loop_escape = false := by decide')
    lines.append("end LanguageEffects.Controls")
    return "\n".join(lines) + "\n"


def run(command, log: Path, timeout: int) -> int:
    done = subprocess.run(command, cwd=HERE, capture_output=True, text=True, timeout=timeout)
    log.write_text(f"$ {' '.join(map(str, command))}\nexit={done.returncode}\n{done.stdout}\n{done.stderr}")
    return done.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--lake", type=Path, default=Path.home() / ".elan/bin/lake")
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args()
    out = args.output
    out.mkdir(parents=True, exist_ok=False)
    report = {
        "kind": "language-route-lean-audit",
        "passed": False,
        "model_proved": False,
        "kernel_typecheck_passed": False,
        "kernel_replay_checked": False,
        "scope": "Straight-line value/type model plus an effect-projection theorem for all finite prefixes of unrestricted loops; generated controls check correspondence with Python lowering. The effect projection overapproximates branches, returns and loop iteration counts. The interpreter, terminals, admission code and Lean toolchain are trusted (docs/security/threat-model.md).",
        "theorems": list(THEOREMS),
        "issues": [],
    }
    issues = report["issues"]
    sources = sorted(HERE.glob("*.lean")) + [HERE / "check.py"]
    report["source_before"] = {p.name: {"sha256": sha256(p)} for p in sources}

    generated, verdicts = generate_controls()
    report["controls"] = verdicts
    if (HERE / "Controls.lean").read_text() != generated:
        (out / "Controls.expected.lean").write_text(generated)
        issues.append("Controls.lean drifted from the current Python lowering/checker")
    for name, v in verdicts["useful"].items():
        if v["python"] != "accepted":
            issues.append(f"Python refused useful control {name}")
    for name, v in verdicts["forged"].items():
        if v["python"] == "accepted":
            issues.append(f"Python accepted forged control {name}")

    effects = generate_effect_controls()
    if (HERE / "EffectControls.lean").read_text() != effects:
        (out / "EffectControls.expected.lean").write_text(effects)
        issues.append("EffectControls.lean drifted from the extended Python lowering")
    report["effect_controls"] = list(EFFECT_USEFUL)

    for path in sorted(HERE.glob("*.lean")):
        text = re.sub(r"/-.*?-/|--[^\n]*", "", path.read_text(), flags=re.S)
        for token in FORBIDDEN_TOKENS:
            if re.search(rf"\b{token}\b", text):
                issues.append(f"{path.name} uses {token}")
        if re.search(r"^\s*axiom\b", text, flags=re.M):
            issues.append(f"{path.name} declares an axiom")

    lake = str(args.lake)
    build = run([lake, "build"], out / "build.log", args.timeout)
    report["kernel_typecheck_passed"] = build == 0
    if build != 0:
        issues.append("lake build failed; see build.log")
    else:
        checker = Path(lake).parent / "leanchecker"
        replay = all(
            run([lake, "env", str(checker), "--fresh", module], out / f"replay-{module}.log", args.timeout) == 0
            for module in ("LanguageRoute", "Controls", "LanguageEffects", "EffectControls")
        )
        report["kernel_replay_checked"] = replay
        if not replay:
            issues.append("leanchecker replay failed")
        audit = out / "Axioms.lean"
        audit.write_text("import LanguageRoute\nimport LanguageEffects\n" + "".join(f"#print axioms {t}\n" for t in THEOREMS))
        code = run([lake, "env", "lean", str(audit)], out / "axioms.log", args.timeout)
        text = (out / "axioms.log").read_text()
        used = set(re.findall(r"depends on axioms: \[([^\]]*)\]", text))
        names = {a.strip() for group in used for a in group.split(",") if a.strip()}
        report["axioms"] = sorted(names)
        if code != 0 or "does not depend on any axioms" not in text and not used:
            issues.append("axiom audit did not run")
        if names - ALLOWED_AXIOMS:
            issues.append(f"non-standard axioms: {sorted(names - ALLOWED_AXIOMS)}")

    report["source_after"] = {p.name: {"sha256": sha256(p)} for p in sources}
    if report["source_after"] != report["source_before"]:
        issues.append("sources changed during the audit")
    report["model_proved"] = report["kernel_typecheck_passed"] and report["kernel_replay_checked"] and not issues
    report["passed"] = report["model_proved"]
    (out / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"passed": report["passed"], "issues": issues}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
