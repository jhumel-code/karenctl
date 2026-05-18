# Policy Rationale: Claude SDK Mutating-Tool Idempotency

**Policy ID:** `claude_sdk_idempotency`  
**File:** `internal/rules/policies/claude_sdk/idempotency.yaml`  
**Rules:** CSDK-006  
**Severity:** Medium

---

## What this policy covers

Mutating tool functions — those whose names begin with `create_`, `send_`, `delete_`, `post_`, `update_`, `refund_`, `charge_`, `issue_` — that do not accept an idempotency key parameter.

---

## Why idempotency is a first-class concern in agentic systems

In a conventional web application, requests come from a user clicking a button. If the request fails, the user sees an error message and decides whether to retry. The human is the idempotency guard.

In an agent, the model is the one deciding whether to retry. The model will retry when:

- A tool returns an ambiguous error (not a clear success or failure).
- The model's context is lost or truncated mid-conversation.
- The orchestrator restarts the agent loop after a crash.
- The model infers from context that the tool "probably" didn't succeed and tries again.

The model does not know (and cannot know) whether the tool *actually* executed on the first attempt. If the tool's network call succeeded but the response was lost, the model sees a failure and retries — but the downstream system already processed the original request.

Without an idempotency key, this retry creates a duplicate action: two emails sent, two charges made, two records created.

---

## Rule-by-rule defense

### CSDK-006 — Mutating tool has no idempotency key (Severity: Medium, Confidence: 0.55)

**What we detect:**  
Tool functions where:
1. The function name starts with a mutation prefix: `create_`, `send_`, `delete_`, `post_`, `update_`, `refund_`, `charge_`, `issue_`.
2. No parameter name contains `idempot` (substring), or equals `request_id` or `txn_id` (exact).

**Why it is flaggable:**  
The name prefixes are the strongest available static signal that a tool performs a side-effecting operation. A tool named `send_invoice` almost certainly calls an email or payment API. A tool named `refund_charge` almost certainly calls a payment processor. These are operations that most payment, communication, and data APIs provide idempotency key support for — precisely because the developers of those APIs know retries happen.

**Real-world consequence:**  
- `send_invoice` retried twice: customer receives two invoices, calls support.
- `charge_card` retried twice: customer is charged twice; company faces chargebacks, fraud flags.
- `refund_charge` retried twice: customer is refunded twice; company loses money.
- `create_account` retried twice: duplicate account in the system, support ticket, data integrity issue.

These are production incidents that have happened at companies running agents in agentic loops without idempotency controls.

**Why severity is Medium and not High:**  
Duplicate side effects are serious but not security vulnerabilities. They require both a retry scenario and a failure to occur. Many integrations are naturally idempotent (reads), and the rule only fires on name prefixes — so it already targets the highest-risk subset.

**Confidence 0.55:**  
This is our lowest-confidence rule for good reason:

- Name prefix matching is a heuristic. `create_session` may not be a mutating operation in the traditional sense. `send_notification` to a logging system may be idempotent by design.
- The parameter scan (`contains: idempot`, `exact: request_id`) is also heuristic. A tool might use `correlation_id` or `idem_key` as its idempotency parameter and would not be detected as safe.
- The 0.55 confidence reflects that roughly half of flagged tools may either not need idempotency or already implement it via a pattern we don't recognize.

The fix is the right call regardless: even if a tool's underlying API does not support idempotency keys, documenting that explicitly (and handling the no-key case) is a meaningful improvement.

---

## What this policy does not cover

- Tools that achieve idempotency via database `INSERT ... ON CONFLICT DO NOTHING` or similar — we do not analyze the body for idempotency logic, only parameter names.
- Tools with non-prefixed names that are still mutating (e.g., `email_customer`, `bill_account`).
- Whether the idempotency_key parameter is *actually used* in the downstream API call — a tool can have the parameter and ignore it.

---

## Limitation: downstream API support required

**This is the most important gap in this policy.** An idempotency key parameter in the tool is useless if the downstream API does not honor it. Before claiming this fix is effective, verify:

1. The API you are calling documents idempotency key support (Stripe: yes; most REST APIs: maybe; some internal APIs: no).
2. You are passing the key to the API in the request (in a header, body field, or URL parameter per the API's spec).
3. The API's idempotency window is longer than the agent's maximum retry window.

If the API does not support idempotency keys, document this explicitly in the tool's docstring and consider an alternative approach (e.g., pre-flight deduplication check against a database).

---

## Recommendations beyond the fix

```python
@tool
def send_invoice(
    customer_id: str,
    amount_cents: int,
    idempotency_key: str,
) -> dict:
    """
    Send an invoice to a customer. Pass a unique idempotency_key per invoice
    to prevent duplicate sends on retry.
    """
    response = stripe.Invoice.create(
        customer=customer_id,
        amount=amount_cents,
        idempotency_key=idempotency_key,
    )
    return {"invoice_id": response.id, "status": response.status}
```

1. Let the orchestrator (or the pre-tool-use hook) generate the idempotency key from a hash of the tool name + parameters. This ensures the same logical call always produces the same key.
2. Expose `idempotency_key` as a required parameter (not optional with a default) — forcing the caller to think about it.
3. Log idempotency key usage server-side so you can audit duplicate calls and verify the API is honoring them.
