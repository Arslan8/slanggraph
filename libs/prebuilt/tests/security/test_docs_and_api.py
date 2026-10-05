"""Documentation invariants and frozen public API snapshot."""

from __future__ import annotations

import json
from pathlib import Path

from langgraph.prebuilt import security

_REPOSITORY = Path(__file__).parents[4]
_SECURITY_DOCS = _REPOSITORY / "docs" / "security"


def test_public_api_matches_snapshot() -> None:
    """Require an explicit snapshot update for every public API change."""
    snapshot = json.loads((Path(__file__).parent / "api_snapshot.json").read_text())
    assert list(security.__all__) == snapshot
    assert all(hasattr(security, name) for name in snapshot)


def test_howto_contains_exactly_ten_code_lines() -> None:
    """Keep the promised quick-start example genuinely compact."""
    document = (_SECURITY_DOCS / "HOWTO.md").read_text()
    code = document.split("```python\n", 1)[1].split("\n```", 1)[0]
    assert len(code.splitlines()) == 10


def test_security_docs_use_single_backticks() -> None:
    """Repository documentation follows the inline-code formatting rule."""
    for document in _SECURITY_DOCS.rglob("*.md"):
        assert "``" not in document.read_text().replace("```", "")
