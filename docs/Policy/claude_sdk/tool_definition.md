# Policy Rationale: Claude SDK Tool Definition Hygiene

**Policy ID:** `claude_sdk_tool_definition`  
**File:** `internal/rules/policies/claude_sdk/tool_definition.yaml`  
**Rules:** CSDK-001, CSDK-002, CSDK-007  
**Severities:** Low, Medium, Low

---

## What this policy covers

Tool definition hygiene governs how a Claude Agent SDK tool presents itself to the model — its name, description (docstring), and parameter shape. These are not cosmetic concerns. They are the interface contract between the developer and the model's tool-selection logic.

---

## Why tool definition quality is a security and reliability concern

The Claude Agent SDK exposes tools to the model through a machine-readable schema. That schema is derived entirely from three sources: the function name, the docstring, and the Python type annotations. If any of these are absent or misleading, the model's ability to decide *when* and *how* to call the tool degrades — causing:

- **Mis-selection:** calling the wrong tool for a request, potentially triggering unintended side effects.
- **Hallucinated parameters:** the model invents arguments the tool does not accept, surfacing as runtime TypeErrors.
- **Refused invocation:** the model declines to call a useful tool because it cannot determine what the tool is for.

These failures are distinct from bugs in the tool's implementation. They occur at the *interface boundary* between natural language and code.

---

## Rule-by-rule defense

### CSDK-001 — Tool has no description (Severity: Low, Confidence: 0.95)

**What we detect:** `@tool`-decorated functions with no docstring.

**Why it is flaggable:**  
The Claude Agent SDK passes the docstring verbatim to the model as the tool's description field. With no docstring, the model receives an empty description and must rely solely on the function name. Under ambiguous prompts — where multiple tools could apply — the model cannot differentiate between them and either picks arbitrarily or refuses to act.

**Real-world consequence:**  
A tool named `fetch_record` with no description will be called for any "get me something" request regardless of whether it applies. Conversely, a tool named `process_refund` with no description may be skipped when the user asks to "handle the charge issue" because the model has no supporting context.

**Why severity is Low:**  
This is a quality issue, not an exploitable vulnerability. The model degrades gracefully — it may call the wrong tool, but it will not execute arbitrary code. Low severity signals "fix this before shipping" rather than "block deployment."

**Confidence 0.95:**  
Docstring presence is deterministic. The 5% gap accounts for edge cases where docstrings are dynamically injected via decorators that our AST analysis misses.

---

### CSDK-002 — Tool parameters are not type-annotated (Severity: Medium, Confidence: 0.90)

**What we detect:** Tools with parameters that carry no Python type annotations.

**Why it is flaggable:**  
Without type annotations, the SDK cannot generate a JSON Schema for the tool's input. The model then has no machine-readable contract to validate its output against before invoking the tool. This means:

1. The model can hallucinate parameter shapes that don't exist.
2. The tool receives structurally wrong input and fails at runtime with a TypeError.
3. The failure arrives as an opaque exception, not a pre-call validation error that the model could correct.

**Real-world consequence:**  
A tool with `def send_email(to, subject, body)` (no types) leaves the model free to pass `to` as a list, a dict, or an integer. The function will fail at the SMTP layer with a message the model cannot parse. With annotations (`to: str, subject: str, body: str`), the SDK validates the model's output before dispatch and returns a structured validation error the model can retry with.

**Why severity is Medium:**  
Unlike missing descriptions (model picks wrong tool), missing type annotations can cause runtime failures in production with real side effects. If the tool sends emails, a runtime failure mid-execution may leave the email partially sent or the state ambiguous.

**Gaps:**  
We only check that annotations exist, not that they are *correct* or *specific enough*. A tool annotated `def tool(x: Any)` satisfies this rule but gives the model no schema guidance. We accept this limitation — checking annotation quality would require semantic analysis beyond our current AST predicates.

---

### CSDK-007 — Ambiguous tool name (Severity: Low, Confidence: 0.90)

**What we detect:** Tools whose names match a blocklist of generic verbs: `process`, `handle`, `run`, `do`, `execute`, `perform`, `work`, `go`, `thing`, `stuff`.

**Why it is flaggable:**  
Tool names are the primary disambiguation signal the model uses when multiple tools are available. A name like `process` is semantically empty — it does not tell the model what entity is being processed, in what direction, or with what outcome. This is especially problematic in multi-tool agents where the model must choose between five or ten available tools.

**Real-world consequence:**  
In an agent with tools `process`, `send_invoice`, and `fetch_customer`, the model will correctly identify `send_invoice` and `fetch_customer` but will struggle to decide when `process` applies. It may over-call it (treating it as a catch-all) or under-call it (avoiding it because the name gives no confidence). Neither is the developer's intent.

**Why the blocklist approach:**  
A semantic analysis of name ambiguity would require an LLM call. We use a conservative blocklist of the most common offending names — ones that appear frequently in production code reviews and cause documented tool routing failures. The list is intentionally small to avoid false positives on names like `run_migration` (which is specific enough).

**Gaps:**  
`execute_command`, `do_thing`, or `handle_request` would all evade this rule because they have a second word. The compound forms are still ambiguous but are outside our current detection scope. Extend the blocklist or add a compound-name analysis pass for future coverage.

---

## What this policy does not cover

- Whether tool descriptions are *accurate* (we only check presence).
- Whether type annotations are *semantically correct* (we only check presence).
- Whether tool names are *unique* across the agent's tool set (collision detection is not implemented).
- Whether parameter names are self-documenting (e.g., `x` vs `customer_id`).

---

## Recommendations beyond the fix

1. Write descriptions that name both the trigger condition and the output format: "Call this tool when the user asks to retrieve order details. Returns a JSON object with `order_id`, `status`, and `line_items`."
2. Use Pydantic models for complex parameter shapes — they produce richer JSON schemas and provide runtime coercion.
3. Adopt a naming convention: verb-object-modifier (`fetch_customer_by_id`, `send_refund_email`). This naturally avoids the ambiguous-name class of issues.
4. Review tool descriptions with the model itself — run a few prompt variations and verify the model selects the expected tool.
