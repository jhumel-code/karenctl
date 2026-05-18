# Policy Rationale: OpenAI Agents SDK Mutating-Tool Idempotency

**Policy ID:** `openai_sdk_idempotency`  
**File:** `internal/rules/policies/openai_sdk/idempotency.yaml`  
**Rules:** OAIS-006  
**Severity:** Medium

---

## What this policy covers

`@function_tool`-decorated functions in the OpenAI Agents SDK whose names begin with mutation prefixes (`create_`, `send_`, `delete_`, `post_`, `update_`, `refund_`, `charge_`, `issue_`) and do not accept an idempotency key parameter.

---

## Relationship to the Claude SDK equivalent

OAIS-006 mirrors CSDK-006 exactly. The detection logic (name prefix matching + parameter name scan) and the fix are identical.

**Read [claude_sdk/idempotency.md](../claude_sdk/idempotency.md) for the full rationale, consequences, and recommendations.** This document covers OpenAI Agents SDK-specific differences only.

---

## OpenAI Agents SDK-specific behavior

### Retry and handoff patterns increase duplicate action risk

The OpenAI Agents SDK supports agent handoffs — one agent calling another via the `handoff` mechanism. When a handoff occurs, the receiving agent can call tools that the sending agent already called (if it needs to continue an action). Without idempotency keys, the same mutating tool call may fire in both the sending and receiving agent's context.

Similarly, the SDK's built-in tool call retry on error (configurable via `RunConfig`) increases the window in which duplicate calls can occur. A mutating tool that fails transiently will be retried, potentially executing the side effect twice if the failure occurred *after* the side effect but *before* the success response was received.

### Streaming and partial results

In streaming mode, the OpenAI Agents SDK may re-invoke tool calls if the stream is interrupted mid-response. This is an additional vector for duplicate execution not present in non-streaming Claude SDK usage. Idempotency keys are especially important in streaming agent deployments.

---

## Confidence rationale (0.55)

Identical to CSDK-006. Name prefix matching is a heuristic; the actual duplicate risk depends on the retry configuration and orchestration pattern of the specific deployment. The low confidence is intentional — the rule is a prompt to evaluate idempotency, not a definitive finding that the tool is broken.

---

## The downstream API requirement

As with CSDK-006: an idempotency key parameter in the tool is only effective if the downstream API honors it. See [claude_sdk/idempotency.md](../claude_sdk/idempotency.md) for the full discussion of this limitation.
