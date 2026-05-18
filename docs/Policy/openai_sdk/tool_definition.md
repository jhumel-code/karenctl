# Policy Rationale: OpenAI Agents SDK Tool Definition Hygiene

**Policy ID:** `openai_sdk_tool_definition`  
**File:** `internal/rules/policies/openai_sdk/tool_definition.yaml`  
**Rules:** OAIS-001, OAIS-002, OAIS-007  
**Severities:** Low, Medium, Low

---

## What this policy covers

How `@function_tool`-decorated functions in the OpenAI Agents SDK present themselves to the model — name, description (docstring), and parameter type annotations.

---

## Relationship to the Claude SDK equivalent

These rules mirror CSDK-001, CSDK-002, and CSDK-007 in structure and rationale. The threat model is identical: the model uses the tool's name, description, and parameter schema to decide when and how to call the tool. Gaps in any of these degrade routing accuracy and enable runtime failures.

The key difference is the decorator: `@function_tool` (OpenAI) vs. `@tool` (Claude). The detection predicates are the same; the `applies_to` target differs.

**Read [claude_sdk/tool_definition.md](../claude_sdk/tool_definition.md) for the full rationale.** This document covers OpenAI SDK-specific differences only.

---

## OpenAI Agents SDK-specific behavior

### How the SDK uses the docstring (OAIS-001)

The OpenAI Agents SDK passes the `@function_tool` function's docstring to the model as the tool's description in the same manner as the Claude SDK. The model sees this description when deciding whether to invoke the tool.

One difference: the OpenAI Agents SDK also uses Pydantic model docstrings and field descriptions if the parameters are typed with Pydantic. This means a tool with a rich Pydantic input model but no function-level docstring *may* still give the model useful schema information. However, it does not provide the call-trigger guidance ("when to use this tool") that a docstring supplies. The rule correctly fires regardless — both the schema and the call guidance are required.

### How the SDK uses type annotations (OAIS-002)

The OpenAI Agents SDK derives a JSON Schema from Python type annotations to validate the model's output before the tool is called. This is the same mechanism as the Claude SDK. Without annotations, no schema is generated, and the model can hallucinate any parameter shape.

One OpenAI-specific nuance: the SDK supports Pydantic BaseModel subclasses as parameter types, which generate richer schemas with field descriptions, constraints (min/max length, regex patterns), and nested structures. Simple Python types (`str`, `int`, `list`) work but produce minimal schemas. A tool that uses `def tool(args: dict)` technically satisfies the annotation requirement (the rule would not fire) but gives the model a useless schema. This is a known gap.

### Ambiguous name list (OAIS-007)

The blocked names are identical to CSDK-007: `process`, `handle`, `run`, `do`, `execute`, `perform`, `work`, `go`, `thing`, `stuff`. The rationale is the same — these names provide no routing signal to the model.

---

## Rules not yet defined: OAIS-003 and OAIS-004

The policy index notes: "OAIS-003 and OAIS-004 are not yet defined — IDs reserved."

These IDs are reserved for:
- **OAIS-003:** Network call without timeout (OpenAI tools) — currently covered by CSDK-003 which lists `openai_tool` in its `applies_to`. A dedicated OAIS-003 would separate the ownership.
- **OAIS-004:** Path parameter without validation (OpenAI tools) — currently covered by CSDK-004 similarly.

The shared coverage is intentional for now — adding OAIS-003/004 would require either duplicating the rules or refactoring the policy structure to support shared rules across categories. Reserve these IDs to avoid conflicts when that work is done.

---

## What this policy does not cover

Same gaps as CSDK tool_definition:
- Accuracy of descriptions (only checks presence).
- Quality/specificity of type annotations (only checks presence).
- Name uniqueness within the agent's tool set.
- Parameter naming quality.

---

## Recommendations beyond the fix

Same as CSDK-001/002/007 recommendations. Additionally, for OpenAI Agents SDK:

1. Use Pydantic `BaseModel` subclasses with `Field(description=...)` for complex parameters — this provides both runtime validation and richer model schema than plain Python types.
2. Consider adding `instructions` to the `Agent` constructor alongside individual tool descriptions — the agent-level instructions give the model context about the tool set as a whole.
3. Test tool routing using `Runner.run()` with varied prompts in a staging environment before shipping. Tool description gaps often surface only under ambiguous inputs that production users generate.
