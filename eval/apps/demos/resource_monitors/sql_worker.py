"""Worker-side SQL toolkit-compatible operations."""

from .api import sql_database


def list_tables() -> str:
    """Return the database's table names."""
    return sql_database.list_tables()


def schema(table_names: str = "") -> str:
    """Return schemas and samples. Input is a comma-separated table-name string."""
    return sql_database.schema(table_names)


def query(query: str) -> str:
    """Execute one read-only SQL query."""
    return sql_database.query(query)
