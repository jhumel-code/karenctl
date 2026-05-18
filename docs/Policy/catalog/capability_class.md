# Policy Rationale: Catalog Capability-Class Safety Rules

**Policy ID:** `catalog_capability_class`  
**File:** `internal/rules/policies/catalog/capability_class.yaml`  
**Rules:** CATL-001 through CATL-009  
**Severities:** Critical, Critical, High, High, High, Critical, Medium, Medium, Low

---

## What this policy covers

Cross-framework rules that fire based on a tool's capability class as assigned by the embedded tool catalog. These rules apply regardless of which SDK decorated the tool — the capability class (what the tool *does*) determines the required safety guard.

---

## Why capability-class rules are necessary

SDK-specific rules (CSDK-*, OAIS-*, MCP-*) catch framework-level implementation gaps. But some risks are *universal* to what a tool does, not how it's decorated. A tool that executes code is dangerous whether it's a Claude SDK tool, an MCP tool, or a LangChain tool. The required safety guard (a sandbox) is the same in all cases.

The catalog maps tool names and descriptions to capability classes. This enables a single rule set to cover:
- All code execution tools (`code_execution` class), regardless of SDK.
- All file write tools (`file_write` class), regardless of SDK.
- All agent spawn tools (`agent_spawn` class), regardless of SDK.

This prevents the situation where a tool escapes all rules by using an unusual SDK or by not being decorated at all.

---

## Rule-by-rule defense

### CATL-001 — Code execution tool has no sandbox guard (Severity: Critical, Confidence: 0.80)

**Capability class:** `code_execution`

**What we detect:**  
Tools classified as code execution surfaces that do not contain any of: `sandbox`, `restrict`, `jail`, `seccomp`, `nsjail` in their body.

**Why it is flaggable:**  
A code execution tool runs user-supplied (or model-supplied) code. The model generates the code string; the tool executes it. Without a sandbox, an adversarially-crafted code string runs with the tool's full process privileges.

The canonical attack: `__import__('os').system('rm -rf /')` is a valid Python expression. If the tool passes any model-generated string to `eval()` or `exec()` without restriction, this executes.

Note: MCP-002 also catches eval/exec — CATL-001 complements it by catching tools that are semantically code execution surfaces (as classified by the catalog) even if they don't literally call `eval()` (e.g., they compile to bytecode and run it, or they use `RestrictedPython` but forgot to apply the restriction).

**Why Critical:**  
Unsandboxed code execution in an agent tool is unconditional RCE via prompt injection. No partial mitigation exists — the sandbox is required.

**Confidence 0.80:**  
The body text search (`has_body_text`) is a heuristic. A tool that imports a sandbox library under a different name, or that runs code inside a subprocess that itself is sandboxed, would be a false positive. 20% gap acknowledges this.

---

### CATL-002 — Shell execution tool has no command allowlist (Severity: Critical, Confidence: 0.80)

**Capability class:** `shell_execution`

**What we detect:**  
Tools classified as shell execution surfaces with no `ALLOWED_COMMANDS`, `allowlist`, `ALLOWED_CMDS`, or `allowed_commands` in their body.

**Why it is flaggable and why Critical:**  
Same rationale as OSH-001/002, but applies cross-framework. A shell execution tool without a command allowlist allows the model to invoke any installed binary. See [openshell/shell.md](../openshell/shell.md) for the full rationale.

CATL-002 and OSH-002 may both fire on the same tool — this is expected. OSH-002 fires because the tool calls a shell function; CATL-002 fires because the tool is catalog-classified as a shell execution surface. The two findings reinforce each other.

---

### CATL-003 — File write tool has no path validation (Severity: High, Confidence: 0.75)

**Capability class:** `file_write`

**What we detect:**  
Tools classified as file write surfaces that pass a path-like parameter to a file operation without `.resolve()`.

**Why it is flaggable:**  
Same rationale as CSDK-004, but cross-framework. A file write tool without path validation enables path traversal. See [claude_sdk/path_safety.md](../claude_sdk/path_safety.md) for the full rationale.

CATL-003 and CSDK-004 (or the equivalent OSH-003) may fire together on the same tool. This is expected — the findings are reinforcing.

---

### CATL-004 — Agent spawn tool has no privilege scoping guard (Severity: High, Confidence: 0.70)

**Capability class:** `agent_spawn`

**What we detect:**  
Tools classified as agent spawn surfaces that do not reference `allowed_tools`, `tool_choice`, `permissions`, or `scope` in their body.

**Why it is flaggable:**  
A tool that spawns a subagent passes the subagent some set of tools and a context. If it passes no restriction on which tools the subagent can use, the subagent inherits all available tools — including destructive ones the orchestrator would not have directly invoked.

This is the **privilege escalation** vector in multi-agent systems. A prompt injection in the subagent's context causes the subagent to invoke a tool the orchestrator would have blocked. The orchestrator's pre-tool-use hooks and filters do not apply to the subagent if the subagent runs with its own full tool set.

**Real-world consequence:**  
An orchestrator that only calls `read_*` tools spawns a subagent to summarize a document. The document contains a prompt injection that causes the subagent to call `delete_file`. If the subagent has `delete_file` in its tool set (because the spawn call didn't restrict it), the deletion succeeds.

**Why High (not Critical):**  
Exploitation requires a subagent to be spawned with elevated tools AND a prompt injection to succeed inside the subagent's context — two preconditions. The cascade of conditions makes this High rather than Critical.

**Confidence 0.70:**  
Tools may pass tool restrictions through a variable or imported config object rather than literal strings. The body text search misses these cases.

---

### CATL-005 — Auth tool has no secure credential handling (Severity: High, Confidence: 0.70)

**Capability class:** `auth_action`

**What we detect:**  
Tools classified as authentication surfaces that do not reference `vault`, `keyring`, `secret`, `secure`, `getenv`, or `environ` in their body.

**Why it is flaggable:**  
An authentication tool that does not reference any secrets management mechanism is a strong signal that credentials may be hardcoded, passed as plaintext parameters, or returned to the model in plaintext.

Each of these is a credential exposure vector:
- **Hardcoded credentials:** appear in source control, logs, and exception messages.
- **Plaintext parameters:** model-generated tool calls are logged. If `password` is a parameter, it appears in every tool call log.
- **Returned to model:** if the tool returns the credential as part of its response, it enters the model's context window — which may be logged, cached, or visible in conversation history.

**Why High (not Critical):**  
Credential exposure is serious but requires the credential to be discovered (read from source, logs, or context). It is not an immediate exploit — an attacker must first gain access to the exposure channel.

**Confidence 0.70:**  
A tool may use a custom secrets manager that doesn't match any of the keyword list. Tools that use AWS SDK's built-in credential chain (which reads from environment variables transparently) would be incorrectly flagged. The review step ("confirm before applying the fix") is important here.

---

### CATL-006 — Computer use tool has no confirmation gate (Severity: Critical, Confidence: 0.75)

**Capability class:** `computer_use`

**What we detect:**  
Tools classified as computer use surfaces (GUI automation, browser control) that do not reference `confirm`, `approve`, `checkpoint`, `human_in_the_loop`, or `require_approval` in their body.

**Why it is flaggable:**  
Computer use tools can take irreversible actions: clicking "submit" on a form, confirming a purchase, deleting an account, sending an email on behalf of the user. Unlike API calls (which may have rollback mechanisms), GUI actions are final when the UI accepts them.

Without a human confirmation gate, the model autonomously performs irreversible actions based on its interpretation of the user's intent. Even without prompt injection, model misinterpretation (the model thinks the user wants to "confirm the order" when they meant to "preview the order") can cause unrecoverable actions.

With prompt injection (via content on the webpage the agent is viewing), an adversary can cause the model to perform arbitrary UI actions on any web application the agent is logged into.

**Why Critical:**  
Irreversible real-world actions (financial transactions, account deletions, form submissions) performed without human confirmation are among the highest-impact failure modes in agentic AI systems. Unlike data exposure (which may have remediation paths), some computer use actions cannot be undone.

**Confidence 0.75:**  
Confirmation logic may exist in a wrapper or orchestrator layer above the tool, not in the tool body itself. A tool that is always called via an `ask_user_to_confirm()` wrapper would be a false positive.

---

### CATL-007 — Data mutation tool has no dry-run or rollback support (Severity: Medium, Confidence: 0.65)

**Capability class:** `data_mutate`

**What we detect:**  
Tools classified as data mutation surfaces that do not reference `dry_run`, `rollback`, `transaction`, `savepoint`, or `BEGIN` in their body.

**Why it is flaggable:**  
Agent tools that mutate database state are called in a retry-prone environment. A transaction that commits partially — either due to a network failure mid-execution or an agent retry that re-executes some but not all operations — leaves the database in an inconsistent state.

A `dry_run` parameter allows the model to preview the effect of a mutation before committing. This is especially valuable for bulk operations (delete all orders older than X, update all prices by Y%) where the model cannot be certain of the selection criteria.

**Why Medium:**  
Data inconsistency is a reliability concern but not a security vulnerability. The consequence is a support incident, not a security breach. Medium severity correctly signals "address before production" without blocking deployment.

---

### CATL-008 — External API tool has no rate limit guard (Severity: Medium, Confidence: 0.60)

**Capability class:** `external_api`

**What we detect:**  
Tools classified as external API surfaces that do not reference `rate_limit`, `backoff`, `retry`, `throttle`, or `sleep` in their body.

**Why it is flaggable:**  
Agents can call tools in tight loops. A tool that calls Stripe, Slack, SendGrid, or any rate-limited API without throttling can exhaust the API's rate limit in a few seconds of agent operation. Consequences:

- API quota exhaustion: the tool starts returning 429 errors, the agent retries aggressively (making it worse), and the service is effectively unavailable for the rest of the billing period.
- Cost overruns: pay-per-call APIs (SMS, email, payment processing) can accumulate significant costs during a runaway agent loop.
- Abuse detection: APIs may flag the account for abuse and suspend it.

**Why Medium:**  
Rate limit exhaustion is an availability and cost concern, not a security vulnerability. It is Medium (not Low) because cost overruns can be material in production.

**Confidence 0.60:**  
The lowest-confidence rule in the catalog category. Rate limiting may be enforced at a client library level (the Stripe SDK handles backoff automatically), at the orchestrator level, or via infrastructure (API gateway). A tool that relies on these mechanisms without in-code rate limiting would be a false positive.

---

### CATL-009 — Memory write tool has no size or scope limit (Severity: Low, Confidence: 0.60)

**Capability class:** `memory_write`

**What we detect:**  
Tools classified as memory write surfaces (writing to vector stores, long-term memory databases, session stores) that do not reference `max_size`, `limit`, `scope`, `max_tokens`, or `truncate` in their body.

**Why it is flaggable:**  
An unconstrained memory writer lets the model accumulate unbounded data across sessions:

1. **Storage inflation:** token-charging vector databases become expensive if the model writes without limits.
2. **Cross-user data leakage:** in multi-tenant agents with shared memory stores and no scope restriction, memories from one user's session can appear in another user's context.
3. **Retrieval degradation:** an unbounded memory store with millions of entries produces noisy retrieval results that degrade the agent's effectiveness over time.
4. **Poisoning:** without scope limits, a prompt injection can cause the agent to write adversarial memories that persist across sessions and influence future behavior.

**Why Low:**  
Memory unboundedness is a long-term reliability and privacy concern, not an immediate exploit. The consequences accumulate over time rather than occurring in a single agent run.

---

## Gaps common to all CATL rules

1. **Catalog accuracy:** the capability class assignment depends on the catalog. If a tool is not in the catalog or is assigned the wrong class, the rules will not fire. Maintain catalog coverage as new tool categories emerge.
2. **Body text search limitations:** all CATL rules use `has_body_text` for guard detection. Guards implemented in separate modules, base classes, or decorators are not detected.
3. **Layered enforcement:** CATL rules check for in-code evidence of guards. Guards implemented at the orchestrator, infrastructure, or deployment layer satisfy the requirement but do not satisfy the detection. Add explicit code-level documentation of the external guard to suppress these findings.

---

## How CATL rules relate to SDK-specific rules

CATL rules are additive — they fire in addition to SDK-specific rules, not instead of them. A Claude SDK `file_write` tool may be flagged by both CSDK-004 (path validation) and CATL-003 (file write tool has no path validation). This is intentional: the two rules detect the same gap from different angles (SDK-level heuristic vs. catalog-level classification), and both findings in the report reinforce the signal.
