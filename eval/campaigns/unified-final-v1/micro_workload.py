"""Shared useful bodies for baseline and forced-language microbenchmarks."""

from langgraph.prebuilt.security.language_sandbox import read_text, write_text


def read_file(path: str) -> str:
    """Read the complete designated UTF-8 fixture once."""
    return read_text(path)


def write_file(path: str, value: str) -> str:
    """Overwrite and close the complete designated UTF-8 fixture once."""
    return write_text(path, value)
