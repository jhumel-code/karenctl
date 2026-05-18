# Policy Rationale: Claude SDK Error Contract Hygiene

**Policy ID:** `claude_sdk_error_handling`  
**File:** `internal/rules/policies/claude_sdk/error_handling.yaml`  
**Rules:** CSDK-005  
**Severity:** Medium

---

## What this policy covers

How Claude Agent SDK tool functions surface failures back to the model. Specifically: tools that raise exceptions without wrapping them in a structured error return value.

---

## Why error contract design matters for agent reliability

In a traditional function call, the caller handles exceptions in a `try/except` block and decides how to proceed. In an agent tool call, the "caller" is the Claude model. The model cannot write `try/except` — it can only read the string representation of whatever the tool returns.

When a tool raises an unhandled exception, the SDK catches it and converts it to a string that appears in the model's context as the tool result. What the model receives looks like:

```
ToolError: ConnectionRefusedError('Connection refused')
```

The model then has to decide: Is this retryable? Should I inform the user? Should I try a different approach? With a raw exception string, it has almost no signal to answer those questions. It cannot distinguish a transient network failure (retry in 1 second) from an invalid input error (do not retry, inform the user) from a permissions failure (escalate to human).

A structured error contract changes this:

```json
{"error": "connection_refused", "retryable": true, "retry_after_seconds": 2}
```

Now the model can branch deterministically on the failure type.

---

## Rule-by-rule defense

### CSDK-005 — Tool raises exceptions without a structured error contract (Severity: Medium, Confidence: 0.60)

**What we detect:**  
Tool functions that:
1. Contain a `raise` statement (indicating they may throw exceptions).
2. Do NOT contain a `try/except` block (indicating exceptions are not caught and converted).

**Why it is flaggable:**  
A tool with `raise` but no `try/except` will propagate all exceptions as opaque strings to the model. The model has no structured way to reason about the failure. This leads to:

- Unnecessary retries: the model retries a permanently-failed call because it can't tell it's permanent.
- Missing retries: the model gives up on a transient failure because it can't tell it's transient.
- Unhelpful user messages: the model surfaces `KeyError: 'id'` to the user instead of "the record was not found."
- Agent loops: the model retries a failing tool in a loop because it interprets each failure as a new situation.

**Real-world consequence:**  
A `send_email` tool that raises `smtplib.SMTPAuthenticationError` unhandled causes the model to tell the user "I encountered an error" with no actionable information. The user cannot tell whether to retry, check credentials, or contact support. A structured `{"error": "smtp_auth_failed", "retryable": false, "action": "check_api_key"}` gives the model everything it needs to guide the user correctly.

**Why severity is Medium:**  
This is a reliability and usability issue, not a security vulnerability. It does not expose data or allow exploitation. The cost of a poor error contract is a degraded agent experience and potential agent loops — both are real costs but not security incidents.

**Confidence 0.60:**  
This is the second-lowest confidence rule because:

- The detection checks for `raise` presence, not whether the raise is actually reachable (a tool might have `raise NotImplementedError` as a stub that is never called in practice).
- A tool with `try/except` at the top level but re-raises with `raise` inside satisfies neither condition and would be missed.
- A tool with no `raise` can still fail — if it calls a function that raises, we do not detect that.

The 0.60 confidence means roughly 4 in 10 flagged tools may not actually have a meaningful exception contract gap. The rule is set conservatively because the fix (wrapping in try/except and returning a dict) is low cost and always improves code quality regardless of whether the exact pattern fires.

---

## What this policy does not cover

- Exceptions raised by called functions (transitive exceptions) — we only check the tool's own body.
- Whether the `try/except` that exists actually catches the *right* exceptions (a bare `except: pass` would satisfy this rule but is arguably worse than letting the exception propagate).
- Whether the structured error return value the tool returns is *useful* to the model (we do not parse the return value).

---

## Recommendations beyond the fix

```python
# Recommended error contract pattern
@tool
def send_email(to: str, subject: str, body: str) -> dict:
    """Send an email. Returns success or a structured error."""
    try:
        _smtp_send(to, subject, body)
        return {"success": True}
    except smtplib.SMTPAuthenticationError:
        return {"error": "auth_failed", "retryable": False, "action": "check_api_key"}
    except smtplib.SMTPConnectError:
        return {"error": "connection_failed", "retryable": True, "retry_after_seconds": 5}
    except Exception as e:
        return {"error": "unexpected", "retryable": False, "message": str(e)}
```

1. Distinguish retryable vs. non-retryable errors explicitly. The model will use this.
2. Catch specific exceptions before the broad `except Exception` fallback. Broad catches that return the raw `str(e)` are an improvement but not sufficient.
3. Never return stack traces to the model — they may contain internal paths, credentials, or environment details. Log the full traceback server-side; return a sanitized message to the model.
4. Consider a shared `ToolError` dataclass across all tools in your agent so the model can rely on a consistent schema for all failures.
