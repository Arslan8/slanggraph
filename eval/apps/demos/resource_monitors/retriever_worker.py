"""Worker-side retrieval tool implementation."""

from .api import retriever


def retrieve_blog_posts(query: str) -> str:
    """Search Lilian Weng posts on agents, prompting, and adversarial attacks."""
    return retriever.search(query)
