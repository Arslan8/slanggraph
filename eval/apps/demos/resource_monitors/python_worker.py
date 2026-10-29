"""Worker-side stateful Python execution tool."""

import json

from .api import python_session


def python_repl_tool(code: str) -> str:
    """Execute chart code in the isolated persistent Python session."""
    result = json.loads(python_session.execute(code))
    if result.get("error"):
        return f"Failed to execute. Error: {result['error']}"
    return (
        f"Successfully executed:\n```python\n{code}\n```\n"
        f"Stdout: {result.get('stdout', '')}\n\n"
        "If complete, respond with FINAL ANSWER."
    )
