"""Minimal native adapter for the same file operations as `micro_workload`."""


def host_read_file(path: str) -> str:
    """Read the complete designated UTF-8 fixture once."""
    with open(path, encoding="utf-8") as stream:
        return stream.read()


def host_write_file(path: str, value: str) -> str:
    """Overwrite and close the complete designated UTF-8 fixture once."""
    with open(path, "w", encoding="utf-8") as stream:
        stream.write(value)
    return value
