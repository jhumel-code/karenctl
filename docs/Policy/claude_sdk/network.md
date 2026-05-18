# Policy Rationale: Claude SDK Network Call Hygiene

**Policy ID:** `claude_sdk_network`  
**File:** `internal/rules/policies/claude_sdk/network.yaml`  
**Rules:** CSDK-003  
**Severity:** High

---

## What this policy covers

Outbound HTTP calls made from inside Claude Agent SDK tool functions. Specifically: calls to `requests`, `httpx`, `aiohttp`, and `urllib.request` without a `timeout` keyword argument.

---

## Why network timeouts in agent tools are a distinct concern

In a conventional web application, a hanging HTTP call blocks one request thread. The impact is bounded — the user sees a slow response, a circuit breaker trips, or a load balancer kills the connection.

In an agent tool, the failure mode is different:

- The tool is called synchronously inside the agent's reasoning loop.
- The model waits for the tool to return before it can continue generating.
- There is no external circuit breaker between the tool call and the conversation loop.
- The agent's wall-clock budget (and token budget) runs down while waiting.
- The user sees a frozen, unresponsive agent — not a slow page load.

The Claude Agent SDK does not impose a default timeout on tool calls. If the tool does not set one, the connection inherits the OS-level TCP timeout, which is typically 60–120 seconds on Linux and longer on some cloud runtimes.

---

## Rule-by-rule defense

### CSDK-003 — Network call has no timeout (Severity: High, Confidence: 0.85)

**What we detect:**  
Calls to the following functions where the `timeout` keyword argument is absent:

- `requests.get`, `requests.post`, `requests.put`, `requests.delete`, `requests.patch`, `requests.head`, `requests.request`, `requests.Session.get`, `requests.Session.post`
- `httpx.get`, `httpx.post`, `httpx.put`, `httpx.delete`, `httpx.patch`, `httpx.head`, `httpx.request`
- `urllib.request.urlopen`
- `aiohttp.ClientSession.get`, `aiohttp.ClientSession.post`

**Why it is flaggable:**  
The `requests` library defaults to no timeout unless explicitly set. `httpx` defaults to 5 seconds in its default client but this default is easy to override silently or may not apply to session-level calls. `aiohttp` has no default timeout. A call to any of these without an explicit `timeout=` argument is a latent hang risk.

**Real-world consequence:**  
If the upstream API a tool calls goes down or responds slowly, the agent stops responding to the user for the full OS-TCP timeout period. In agentic pipelines running multiple tool calls in sequence, one hanging call blocks all subsequent steps. In the worst case, the agent appears to succeed (the call eventually completes) but took 90 seconds — burning the user's session budget and producing a degraded experience.

**Why severity is High:**  
A hang is not a silent failure — it produces observable, negative user experience and can exhaust API credits. It is not Critical because the tool eventually recovers (or the orchestrator kills it), and there is no security vulnerability.

**Confidence 0.85:**  
We perform static call analysis. The 15% gap accounts for:
- `timeout` passed via a `**kwargs` dict we cannot statically resolve.
- `timeout` set at the `Session` constructor level (not per-call), which we do not currently trace.
- Dynamic call wrappers that add a timeout in a decorator the tool doesn't see.

---

## What this policy does not cover

- Whether the timeout value is *appropriate* (we do not flag `timeout=3600`).
- Retries with backoff — a tool can have a timeout and still retry indefinitely. See CATL-008 for rate limit/backoff coverage.
- Non-HTTP network calls (e.g., raw sockets, gRPC without a deadline, database queries).
- `aiohttp.ClientSession.put`, `aiohttp.ClientSession.delete` — the callee list covers the most common HTTP verbs but is not exhaustive. Extend as needed.

---

## Known false positives

- A `requests.Session` configured with `timeout` at creation and reused across calls will fire this rule on each `.get()`/`.post()` call. The per-call methods do inherit the session timeout, so the rule is technically a false positive in this case. Mitigation: pass `timeout` explicitly per call for clarity, or suppress the rule with a comment.

---

## Recommendations beyond the fix

1. Use `timeout=(connect_timeout, read_timeout)` tuples for granular control. A 5-second connect timeout with a 30-second read timeout is a reasonable default for most API integrations.
2. Combine with retry logic using `tenacity` or `urllib3.util.retry` — but cap total retry time, not just per-call time.
3. Surface network failures as structured error payloads the model can reason about: `{"error": "upstream_timeout", "retryable": True}`. This enables the model to decide whether to retry, escalate, or inform the user.
4. For `aiohttp`, set a `ClientTimeout` at the session level AND a per-request timeout — session-level timeouts apply to the whole session and are easy to misconfigure.
