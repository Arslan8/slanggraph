"""Worker-side retrieval tool implementation."""

from langgraph.prebuilt.security.mediators.retrieval import (
    text_retrieval as retriever,
)


def retrieve_blog_posts(query: str) -> str:
    """Search Lilian Weng posts on agents, prompting, and adversarial attacks."""
    return retriever.search(query)
