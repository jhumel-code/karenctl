# Policy Rationale: OpenAI Agents SDK Error Contract Hygiene

**Policy ID:** `openai_sdk_error_handling`  
**File:** `internal/rules/policies/openai_sdk/error_handling.yaml`  
**Rules:** OAIS-005  
**Severity:** Medium

---

## What this policy covers

How `@function_tool`-decorated functions in the OpenAI Agents SDK surface failures to the model — specifically, tools that raise exceptions without a try/except block to convert them into structured error return values.

---

## Relationship to the Claude SDK equivalent

OAIS-005 mirrors CSDK-005 exactly in detection logic and threat model. The detection (`has_raise: true` + `has_try_except: false`) and the fix (`return {"error": ..., "retryable": bool}`) are the same.

**Read [claude_sdk/error_handling.md](../claude_sdk/error_handling.md) for the full rationale and code examples.** This document covers OpenAI Agents SDK-specific differences only.

---

## OpenAI Agents SDK-specific behavior

### How the SDK surfaces exceptions to the model

When a `@function_tool` raises an unhandled exception, the OpenAI Agents SDK catches it internally and formats it as a tool result string. The exact format depends on the SDK version, but it typically looks like:

```
Tool call failed: ValueError('Invalid customer ID format')
```

The model receives this as the tool's output and must decide how to proceed. The same limitations apply as in the Claude SDK: the model cannot reliably distinguish retryable from non-retryable errors from a raw exception string.

### Differences in retry behavior

The OpenAI Agents SDK has documented retry behavior for tool calls in some configurations. This makes structured error contracts *more* important than in vanilla Claude SDK usage, because:

1. If the SDK retries automatically on certain exception types, a structured `{"retryable": false}` return prevents unnecessary retries that the code-level retry logic might otherwise execute.
2. If the model drives retries (by calling the tool again in its next turn), a structured error gives it the signal to stop.

---

## What this policy does not cover

Same as CSDK-005 gaps:
- Transitive exceptions from called functions.
- Whether the existing try/except catches the right exceptions.
- Quality of the structured error payload returned.

---

## Confidence rationale (0.60)

Same as CSDK-005: a `raise` statement in the body does not guarantee the exception is reachable in practice, and tools with try/except that re-raise are not fully covered. The fix is low-cost and always improves code quality, so the lower confidence is acceptable.
