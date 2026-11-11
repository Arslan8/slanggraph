"""Shared useful bodies for all three microbenchmark routes."""

from langgraph.prebuilt.security.language_sandbox import read_text, write_text


def read_file(path: str) -> str:
    """Read the complete designated UTF-8 fixture once."""
    return read_text(path)


def write_file(path: str, value: str) -> str:
    """Overwrite and close the complete designated UTF-8 fixture once."""
    return write_text(path, value)


def _direct_read(path: str) -> str:
    with open(path, encoding="utf-8") as stream:
        return stream.read()


def _direct_write(path: str, value: str) -> str:
    with open(path, "w", encoding="utf-8") as stream:
        stream.write(value)
    return value


def host_read_file(path: str) -> str:
    """Launch adapter for the shared read body inside a native worker."""
    previous = read_file.__globals__["read_text"]
    read_file.__globals__["read_text"] = _direct_read
    try:
        return read_file(path)
    finally:
        read_file.__globals__["read_text"] = previous


def host_write_file(path: str, value: str) -> str:
    """Launch adapter for the shared write body inside a native worker."""
    previous = write_file.__globals__["write_text"]
    write_file.__globals__["write_text"] = _direct_write
    try:
        return write_file(path, value)
    finally:
        write_file.__globals__["write_text"] = previous
