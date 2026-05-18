# Policy Rationale: OpenShell Resource Limits

**Policy ID:** `openshell_resources`  
**File:** `internal/rules/policies/openshell/resources.yaml`  
**Rules:** OSH-004  
**Severity:** Medium

---

## What this policy covers

A manifest-level check that fires once per scan — not against a specific tool, but against the *absence* of an OpenShell policy file that defines resource limits (CPU, memory, wall-clock time) for the agent's tool execution environment.

---

## Why resource limits are a safety concern in agentic systems

Agent tools run in a loop. The model can call a tool multiple times — in sequence, in parallel (with multi-agent orchestrators), or recursively (if a tool spawns a subagent that calls another tool). Unlike a web request handler that serves one request and exits, a tool execution environment can have dozens of tool calls in flight.

Without resource limits:

- A tool with an infinite loop (bug, not exploit) consumes CPU indefinitely and blocks the agent process.
- A tool that builds a large in-memory structure (e.g., loading a large file into memory) can exhaust available RAM and cause the process to be OOM-killed.
- A tool that runs an expensive subprocess (e.g., video encoding, numerical computation) can consume all available CPU for longer than the agent's intended budget.
- A runaway agent loop (where the model keeps calling a tool because each call appears to partially succeed) can consume quota and incur unbounded cost.

These are not primarily security vulnerabilities — they are reliability and availability concerns. But in a shared hosting environment (multi-tenant agent platforms, cloud functions with shared CPU), a runaway tool in one tenant's agent can degrade performance for others.

---

## Rule-by-rule defense

### OSH-004 — No OpenShell resource limits configured (Severity: Medium, Confidence: 0.95)

**What we detect:**  
This rule is a singleton — it fires at most once per scan, against the first applicable tool found. The match condition is vacuously true (`match: {}`), meaning it fires whenever the scan includes tools in its `applies_to` categories. The actual check is whether an OpenShell policy file with `cpu`, `memory`, or `time` limits exists in the project.

**Why it is flaggable:**  
The absence of a resource limits configuration is a gap in the defense-in-depth stack. The OpenShell sandbox's primary value is as a constraint layer that operates independent of the tool's Python code. Without resource limits in the sandbox policy, a tool implementation bug (or a prompt-injection-induced runaway) has no runtime governor.

**Why singleton:**  
Resource limits are configured at the sandbox policy level, not per tool. Firing once per scan (not once per tool) correctly models this: the fix is to add a policy section, not to change 20 tool functions. Repeating the finding once per tool would be noise.

**Confidence 0.95:**  
Very high confidence because the detection is structural (presence/absence of a config section), not heuristic. The 5% gap accounts for projects that configure resource limits through a separate mechanism not recognized by our scanner (e.g., cgroup configuration set at the deployment layer, not the OpenShell policy file).

**Why Medium (not High or Critical):**  
Resource exhaustion is rarely exploitable directly — an attacker would need to cause a runaway tool call via prompt injection, and the consequence is denial of service rather than data exfiltration or code execution. The severity is Medium to ensure developers address it before production, without treating it as a blocking security issue.

---

## What this policy does not cover

- **Per-tool resource limits:** the OpenShell policy typically sets global limits for the agent's sandbox. Per-tool limits (e.g., "the media processing tool gets 2 CPU but the text tool gets 0.5") require separate configuration that we do not currently validate.
- **Network bandwidth limits:** OpenShell's resource limits cover CPU, memory, and wall-clock time but not network throughput. A tool that downloads a large file can consume significant bandwidth without triggering this rule.
- **Token budget:** the agent's total API token consumption is not bounded by the OpenShell sandbox. Token budget governance is a separate concern at the orchestrator level.

---

## Recommendations for resource limit values

The fix hint (`policy_emit: default_resource_limits`) generates conservative defaults. Review these defaults against your specific workloads:

```yaml
# openshell/policy.yaml — generated defaults, review before committing
resources:
  cpu_limit: 1.0          # 1 CPU core
  memory_limit_mb: 512    # 512 MB RAM
  wall_clock_timeout_s: 30  # 30 seconds per tool call
  max_open_files: 64
  max_processes: 4
```

**Calibration guidance:**

| Tool category | CPU | Memory | Timeout |
|---|---|---|---|
| Text processing | 0.5 | 256 MB | 15s |
| File I/O (small files) | 0.5 | 512 MB | 10s |
| HTTP API calls | 0.1 | 128 MB | 30s |
| Media/image processing | 2.0 | 1 GB | 120s |
| Code execution (sandboxed) | 1.0 | 512 MB | 30s |

Tighten limits progressively after observing actual p95 resource usage in staging. Do not use the defaults as permanent values — they are starting points.

---

## Interaction with CATL-001 (code execution sandbox)

For tools in the `code_execution` capability class, CATL-001 requires an in-code sandbox guard. OSH-004 requires OS-level resource limits. These are complementary, not redundant:

- The in-code sandbox (CATL-001) prevents malicious code from escaping to the Python environment.
- The OS-level resource limits (OSH-004) prevent legitimate code that happens to be expensive from consuming all available resources.

Both are required for code execution tools.
