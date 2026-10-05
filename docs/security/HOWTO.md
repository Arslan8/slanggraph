# Secure a tool in 10 lines

This complete example declares effects and author DAC, enables mandatory
mediation, and binds an authenticated principal outside graph state.

```python
from langgraph.prebuilt.security import Effect, Principal, SecurityConfig, dac, effects, guarded_tool, with_principal
security = SecurityConfig()
@guarded_tool(security=security)
@dac(owner="ops", grants={"ops": "x"}, required_scopes={"files:read"})
@effects(Effect.READ)
def read_file(path: str) -> str:
    """Read a file."""; return open(path).read()
principal = Principal("alice", frozenset({"ops"}), frozenset({"files:read"}), "session-1")
config = with_principal({}, principal, modules=security.modules)
result = read_file.invoke({"path": "README.md"}, config=config)
```

For normal graph execution, pass `security` to `ToolNode` or
`StateGraph.compile` and supply the same bound config when invoking the graph.
