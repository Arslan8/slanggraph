"""Tool-side frozen search operation over a registered mediator client."""

from langgraph.prebuilt.security.mediators.retrieval import json_search as search


def frozen_search(query: str) -> str:
    """Search the registered frozen corpus."""
    return search.search(query)
