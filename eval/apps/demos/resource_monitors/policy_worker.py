"""Worker-side policy retrieval operation."""

from langgraph.prebuilt.security.mediators.retrieval import (
    text_retrieval as policy_index,
)


def lookup_policy(query: str) -> str:
    """Consult the frozen airline policy corpus."""
    return policy_index.search(query)
