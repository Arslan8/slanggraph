"""Worker-side frozen search implementation."""

import json

from .api import search


def frozen_search(query: str) -> list[dict]:
    """Search the registered frozen corpus."""
    return json.loads(search.search(query))
