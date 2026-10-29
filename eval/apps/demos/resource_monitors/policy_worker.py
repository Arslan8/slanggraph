"""Worker-side policy retrieval operation."""

from .api import policy_index


def lookup_policy(query: str) -> str:
    """Consult the frozen airline policy corpus."""
    return policy_index.search(query)
