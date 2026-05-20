# Policy index

All detection rules shipped in `internal/rules/policies/`, grouped by category.
Each rule links to its source file. Severity abbreviations: **C** = critical, **H** = high, **M** = medium, **L** = low.

Scores are Base Scores (0–100) derived from `Severity_Weight × Confidence × 100`. See [scoring.md](scoring.md) for the full formula and rationale.

Every rule cites one or more entries from the **OWASP LLM Top 10:2025** — the `references:` field in each YAML is the authoritative mapping. The "Standard" column below lists the primary OWASP LLM ID(s) each rule is grounded in.

---

## Claude Agent SDK (`claude_sdk`) — CSDK-NNN

Rules targeting `@tool`-decorated Python functions and `AgentDefinition(...)` calls in the Claude Agent SDK.

### Tool-scope rules

| ID | Title | Sev | Conf | Score | Standard | File |
|----|-------|-----|------|-------|----------|------|
| CSDK-001 | Tool has no description | L | 0.95 | 14.3 | LLM06 | [tool_definition.yaml](../internal/rules/policies/claude_sdk/tool_definition.yaml) |
| CSDK-002 | Tool parameters are not type-annotated | M | 0.90 | 36.0 | LLM06 | [tool_definition.yaml](../internal/rules/policies/claude_sdk/tool_definition.yaml) |
| CSDK-003 | Network call has no timeout | H | 0.85 | 59.5 | LLM10 | [network.yaml](../internal/rules/policies/claude_sdk/network.yaml) |
| CSDK-004 | Path parameter used in I/O without validation | H | 0.70 | 49.0 | LLM01, LLM06 | [path_safety.yaml](../internal/rules/policies/claude_sdk/path_safety.yaml) |
| CSDK-005 | Tool raises exceptions without a structured error contract | M | 0.60 | 24.0 | LLM05 | [error_handling.yaml](../internal/rules/policies/claude_sdk/error_handling.yaml) |
| CSDK-006 | Mutating tool has no idempotency key | M | 0.55 | 22.0 | LLM06 | [idempotency.yaml](../internal/rules/policies/claude_sdk/idempotency.yaml) |
| CSDK-007 | Ambiguous tool name | L | 0.90 | 13.5 | LLM06 | [tool_definition.yaml](../internal/rules/policies/claude_sdk/tool_definition.yaml) |

### Agent-scope rules

| ID | Title | Sev | Conf | Score | Standard | File |
|----|-------|-----|------|-------|----------|------|
| CSDK-101 | Claude subagent is granted the Bash tool | H | 0.80 | 56.0 | LLM01, LLM06 | [agent_safety.yaml](../internal/rules/policies/claude_sdk/agent_safety.yaml) |

### Topic files

| File | Rules | What it covers | Rationale |
|------|-------|----------------|-----------|
| `claude_sdk/tool_definition.yaml` | CSDK-001, 002, 007 | Name, description, parameter shape | [Policy/claude_sdk/tool_definition.md](Policy/claude_sdk/tool_definition.md) |
| `claude_sdk/network.yaml` | CSDK-003 | Outbound HTTP — timeout enforcement | [Policy/claude_sdk/network.md](Policy/claude_sdk/network.md) |
| `claude_sdk/path_safety.yaml` | CSDK-004 | Filesystem path traversal | [Policy/claude_sdk/path_safety.md](Policy/claude_sdk/path_safety.md) |
| `claude_sdk/error_handling.yaml` | CSDK-005 | Exception contract | [Policy/claude_sdk/error_handling.md](Policy/claude_sdk/error_handling.md) |
| `claude_sdk/idempotency.yaml` | CSDK-006 | Retry-safe side effects | [Policy/claude_sdk/idempotency.md](Policy/claude_sdk/idempotency.md) |
| `claude_sdk/agent_safety.yaml` | CSDK-101 | Subagent built-in tool privilege | [Policy/claude_sdk/agent_safety.md](Policy/claude_sdk/agent_safety.md) |

---

## OpenShell (`openshell`) — OSH-NNN

Rules targeting subprocess invocations, filesystem writes, network egress, and sandbox configuration.
Feeds the generated `openshell/policy.yaml` sandbox config.

### Tool-scope rules

| ID | Title | Sev | Conf | Score | Standard | File |
|----|-------|-----|------|-------|----------|------|
| OSH-001 | subprocess called with `shell=True` | C | 0.99 | 99.0 | LLM01 | [shell.yaml](../internal/rules/policies/openshell/shell.yaml) |
| OSH-002 | Shell invocation without an allowed-command list | H | 0.85 | 59.5 | LLM06 | [shell.yaml](../internal/rules/policies/openshell/shell.yaml) |
| OSH-003 | Filesystem write without sandbox restriction | H | 0.80 | 56.0 | LLM01, LLM06 | [filesystem.yaml](../internal/rules/policies/openshell/filesystem.yaml) |
| OSH-005 | Network egress is unrestricted | H | 0.70 | 49.0 | LLM06, LLM10 | [network.yaml](../internal/rules/policies/openshell/network.yaml) |

### Repo-scope rules (singleton — fire once per scan)

| ID | Title | Sev | Conf | Score | Standard | File |
|----|-------|-----|------|-------|----------|------|
| OSH-004 | No OpenShell resource limits configured | M | 0.95 | 38.0 | LLM10 | [resources.yaml](../internal/rules/policies/openshell/resources.yaml) |
| OSH-006 | No sandbox process identity configured | H | 0.90 | 63.0 | LLM06 | [resources.yaml](../internal/rules/policies/openshell/resources.yaml) |
| OSH-007 | Landlock filesystem isolation not enforced strictly | H | 0.90 | 63.0 | LLM06 | [resources.yaml](../internal/rules/policies/openshell/resources.yaml) |

### Topic files

| File | Rules | What it covers | Rationale |
|------|-------|----------------|-----------|
| `openshell/shell.yaml` | OSH-001, 002 | `shell=True`, missing command allowlist | [Policy/openshell/shell.md](Policy/openshell/shell.md) |
| `openshell/filesystem.yaml` | OSH-003 | Unrestricted filesystem writes | [Policy/openshell/filesystem.md](Policy/openshell/filesystem.md) |
| `openshell/resources.yaml` | OSH-004, 006, 007 | Resource limits, process identity, Landlock | [Policy/openshell/resources.md](Policy/openshell/resources.md) |
| `openshell/network.yaml` | OSH-005 | Dynamic URL calls with no host allowlist | [Policy/openshell/network.md](Policy/openshell/network.md) |

---

## OpenAI Agents SDK (`openai_sdk`) — OAI-NNN / OAIS-NNN

Rules targeting `@function_tool`-decorated functions and `Agent(...)`/`SandboxAgent(...)` calls in the OpenAI Agents SDK.

### Tool-scope rules

| ID | Title | Sev | Conf | Score | Standard | File |
|----|-------|-----|------|-------|----------|------|
| OAIS-001 | OpenAI tool has no description | L | 0.95 | 14.3 | LLM06 | [tool_definition.yaml](../internal/rules/policies/openai_sdk/tool_definition.yaml) |
| OAIS-002 | OpenAI tool parameters are not type-annotated | M | 0.90 | 36.0 | LLM06 | [tool_definition.yaml](../internal/rules/policies/openai_sdk/tool_definition.yaml) |
| OAIS-005 | OpenAI tool raises exceptions without a structured error contract | M | 0.60 | 24.0 | LLM05 | [error_handling.yaml](../internal/rules/policies/openai_sdk/error_handling.yaml) |
| OAIS-006 | Mutating OpenAI tool has no idempotency key | M | 0.55 | 22.0 | LLM06 | [idempotency.yaml](../internal/rules/policies/openai_sdk/idempotency.yaml) |
| OAIS-007 | Ambiguous OpenAI tool name | L | 0.90 | 13.5 | LLM06 | [tool_definition.yaml](../internal/rules/policies/openai_sdk/tool_definition.yaml) |
| OAI-003 | Tool sets strict_mode=False | M | 0.95 | 38.0 | LLM06 | [decorator_config.yaml](../internal/rules/policies/openai_sdk/decorator_config.yaml) |
| OAI-004 | Tool has no failure_error_function | M | 0.70 | 28.0 | LLM05 | [decorator_config.yaml](../internal/rules/policies/openai_sdk/decorator_config.yaml) |
| OAI-005 | Network call has no timeout | H | 0.85 | 59.5 | LLM10 | [network.yaml](../internal/rules/policies/openai_sdk/network.yaml) |
| OAI-006 | Tool accepts path without normalization | H | 0.70 | 49.0 | LLM01, LLM06 | [path_safety.yaml](../internal/rules/policies/openai_sdk/path_safety.yaml) |

### Agent-scope rules

| ID | Title | Sev | Conf | Score | Standard | File |
|----|-------|-----|------|-------|----------|------|
| OAI-101 | Agent has no input_guardrails AND wires shell tools | H | 0.85 | 59.5 | LLM01, LLM06 | [agent_safety.yaml](../internal/rules/policies/openai_sdk/agent_safety.yaml) |
| OAI-102 | Agent uses tool_use_behavior="stop_on_first_tool" | H | 0.95 | 66.5 | LLM05, LLM06 | [agent_safety.yaml](../internal/rules/policies/openai_sdk/agent_safety.yaml) |
| OAI-103 | tool_choice="required" combined with reset_tool_choice=False | H | 0.95 | 66.5 | LLM10, LLM06 | [agent_safety.yaml](../internal/rules/policies/openai_sdk/agent_safety.yaml) |
| OAI-104 | Raw Agent (not SandboxAgent) wires shell tools | M | 0.75 | 30.0 | LLM06 | [agent_safety.yaml](../internal/rules/policies/openai_sdk/agent_safety.yaml) |
| OAI-105 | Agent has mcp_servers configured AND no input_guardrails | H | 0.85 | 59.5 | LLM01 | [mcp_safety.yaml](../internal/rules/policies/openai_sdk/mcp_safety.yaml) |

### Repo-scope rules (singleton — fire once per scan)

| ID | Title | Sev | Conf | Score | Standard | File |
|----|-------|-----|------|-------|----------|------|
| OAI-201 | Project uses default OpenAI tracing | M | 0.80 | 32.0 | LLM02 | [tracing.yaml](../internal/rules/policies/openai_sdk/tracing.yaml) |

### Topic files

| File | Rules | What it covers | Rationale |
|------|-------|----------------|-----------|
| `openai_sdk/tool_definition.yaml` | OAIS-001, 002, 007 | Name, description, parameter shape | [Policy/openai_sdk/tool_definition.md](Policy/openai_sdk/tool_definition.md) |
| `openai_sdk/error_handling.yaml` | OAIS-005 | Exception contract | [Policy/openai_sdk/error_handling.md](Policy/openai_sdk/error_handling.md) |
| `openai_sdk/idempotency.yaml` | OAIS-006 | Retry-safe side effects | [Policy/openai_sdk/idempotency.md](Policy/openai_sdk/idempotency.md) |
| `openai_sdk/decorator_config.yaml` | OAI-003, 004 | `@function_tool` decorator kwargs | [Policy/openai_sdk/decorator_config.md](Policy/openai_sdk/decorator_config.md) |
| `openai_sdk/network.yaml` | OAI-005 | Outbound HTTP — timeout enforcement | [Policy/openai_sdk/network.md](Policy/openai_sdk/network.md) |
| `openai_sdk/path_safety.yaml` | OAI-006 | Filesystem path traversal | [Policy/openai_sdk/path_safety.md](Policy/openai_sdk/path_safety.md) |
| `openai_sdk/agent_safety.yaml` | OAI-101, 102, 103, 104 | Agent constructor wiring safety | [Policy/openai_sdk/agent_safety.md](Policy/openai_sdk/agent_safety.md) |
| `openai_sdk/mcp_safety.yaml` | OAI-105 | MCP server integration guardrails | [Policy/openai_sdk/mcp_safety.md](Policy/openai_sdk/mcp_safety.md) |
| `openai_sdk/tracing.yaml` | OAI-201 | Default tracing data egress | [Policy/openai_sdk/tracing.md](Policy/openai_sdk/tracing.md) |

---

## MCP (`mcp`) — MCP-NNN

Rules targeting `@server.tool`-decorated MCP server tools. Focus on injection and unsafe deserialization — MCP tools receive model-controlled inputs from external orchestrators.

| ID | Title | Sev | Conf | Score | Standard | File |
|----|-------|-----|------|-------|----------|------|
| MCP-001 | MCP tool accepts injection-prone parameter names | H | 0.75 | 52.5 | LLM01 | [injection.yaml](../internal/rules/policies/mcp/injection.yaml) |
| MCP-002 | MCP tool contains eval or exec call | C | 0.90 | 90.0 | LLM01 | [injection.yaml](../internal/rules/policies/mcp/injection.yaml) |
| MCP-003 | MCP tool deserializes data with pickle or marshal | C | 0.95 | 95.0 | LLM01 | [injection.yaml](../internal/rules/policies/mcp/injection.yaml) |
| MCP-004 | MCP tool has no description | L | 0.95 | 14.3 | LLM06 | [injection.yaml](../internal/rules/policies/mcp/injection.yaml) |

### Topic files

| File | Rules | What it covers | Rationale |
|------|-------|----------------|-----------|
| `mcp/injection.yaml` | MCP-001, 002, 003, 004 | Param injection, eval/exec, unsafe deserialization, missing description | [Policy/mcp/injection.md](Policy/mcp/injection.md) |

---

## Catalog capability-class (`catalog`) — CATL-NNN

Cross-framework rules. Fire based on catalog-assigned capability class — apply regardless of SDK. Each rule checks that a capability class carries its required safety guard.

| ID | Title | Capability class | Sev | Conf | Score | Standard | File |
|----|-------|-----------------|-----|------|-------|----------|------|
| CATL-001 | Code execution tool has no sandbox guard | `code_execution` | C | 0.80 | 80.0 | LLM01, LLM06 | [capability_class.yaml](../internal/rules/policies/catalog/capability_class.yaml) |
| CATL-002 | Shell execution tool has no command allowlist | `shell_execution` | C | 0.80 | 80.0 | LLM01, LLM06 | [capability_class.yaml](../internal/rules/policies/catalog/capability_class.yaml) |
| CATL-003 | File write tool has no path validation | `file_write` | H | 0.75 | 52.5 | LLM01, LLM06 | [capability_class.yaml](../internal/rules/policies/catalog/capability_class.yaml) |
| CATL-004 | Agent spawn tool has no privilege scoping guard | `agent_spawn` | H | 0.70 | 49.0 | LLM06 | [capability_class.yaml](../internal/rules/policies/catalog/capability_class.yaml) |
| CATL-005 | Auth tool has no secure credential handling | `auth_action` | H | 0.70 | 49.0 | LLM02 | [capability_class.yaml](../internal/rules/policies/catalog/capability_class.yaml) |
| CATL-006 | Computer use tool has no confirmation gate | `computer_use` | C | 0.75 | 75.0 | LLM06 | [capability_class.yaml](../internal/rules/policies/catalog/capability_class.yaml) |
| CATL-007 | Data mutation tool has no dry-run or rollback support | `data_mutate` | M | 0.65 | 26.0 | LLM06 | [capability_class.yaml](../internal/rules/policies/catalog/capability_class.yaml) |
| CATL-008 | External API tool has no rate limit guard | `external_api` | M | 0.60 | 24.0 | LLM10 | [capability_class.yaml](../internal/rules/policies/catalog/capability_class.yaml) |
| CATL-009 | Memory write tool has no size or scope limit | `memory_write` | L | 0.60 | 9.0 | LLM10 | [capability_class.yaml](../internal/rules/policies/catalog/capability_class.yaml) |

### Topic files

| File | Rules | What it covers | Rationale |
|------|-------|----------------|-----------|
| `catalog/capability_class.yaml` | CATL-001 through 009 | All capability-class safety checks | [Policy/catalog/capability_class.md](Policy/catalog/capability_class.md) |

---

## Google Agent Development Kit (`google_adk`) — GADK-NNN

Rules targeting `@adk.tool`-decorated functions and `Agent(...)` calls in the Google ADK.

### Tool-scope rules

| ID | Title | Sev | Conf | Score | Standard | File |
|----|-------|-----|------|-------|----------|------|
| GADK-001 | Tool has no description | L | 0.95 | 14.3 | LLM06 | [tool_definition.yaml](../internal/rules/policies/google_adk/tool_definition.yaml) |
| GADK-002 | Tool parameters are not type-annotated | M | 0.90 | 36.0 | LLM06 | [tool_definition.yaml](../internal/rules/policies/google_adk/tool_definition.yaml) |
| GADK-003 | Network call has no timeout | H | 0.85 | 59.5 | LLM10 | [network.yaml](../internal/rules/policies/google_adk/network.yaml) |
| GADK-004 | Path parameter used in I/O without validation | H | 0.70 | 49.0 | LLM01, LLM06 | [path_safety.yaml](../internal/rules/policies/google_adk/path_safety.yaml) |
| GADK-005 | Tool raises exceptions without a structured error contract | M | 0.60 | 24.0 | LLM05 | [error_handling.yaml](../internal/rules/policies/google_adk/error_handling.yaml) |
| GADK-006 | Mutating tool has no idempotency key | M | 0.55 | 22.0 | LLM06 | [idempotency.yaml](../internal/rules/policies/google_adk/idempotency.yaml) |
| GADK-007 | Ambiguous tool name | L | 0.90 | 13.5 | LLM06 | [tool_definition.yaml](../internal/rules/policies/google_adk/tool_definition.yaml) |
| GADK-008 | BashTool missing shell metacharacter blocking | H | 0.90 | 63.0 | LLM01 | [builtin_tools.yaml](../internal/rules/policies/google_adk/builtin_tools.yaml) |

### Agent-scope rules

| ID | Title | Sev | Conf | Score | Standard | File |
|----|-------|-----|------|-------|----------|------|
| GADK-101 | Agent has no before_tool_callback | H | 0.80 | 56.0 | LLM01, LLM06 | [agent_safety.yaml](../internal/rules/policies/google_adk/agent_safety.yaml) |
| GADK-102 | Agent has no safety_settings | M | 0.75 | 30.0 | LLM06, LLM05 | [agent_safety.yaml](../internal/rules/policies/google_adk/agent_safety.yaml) |

### Topic files

| File | Rules | What it covers | Rationale |
|------|-------|----------------|-----------|
| `google_adk/tool_definition.yaml` | GADK-001, 002, 007 | Name, description, parameter shape | [Policy/google_adk/tool_definition.md](Policy/google_adk/tool_definition.md) |
| `google_adk/network.yaml` | GADK-003 | Outbound HTTP — timeout enforcement | [Policy/google_adk/network.md](Policy/google_adk/network.md) |
| `google_adk/path_safety.yaml` | GADK-004 | Filesystem path traversal | [Policy/google_adk/path_safety.md](Policy/google_adk/path_safety.md) |
| `google_adk/error_handling.yaml` | GADK-005 | Exception contract | [Policy/google_adk/error_handling.md](Policy/google_adk/error_handling.md) |
| `google_adk/idempotency.yaml` | GADK-006 | Retry-safe side effects | [Policy/google_adk/idempotency.md](Policy/google_adk/idempotency.md) |
| `google_adk/builtin_tools.yaml` | GADK-008 | Built-in tool safety configuration | [Policy/google_adk/builtin_tools.md](Policy/google_adk/builtin_tools.md) |
| `google_adk/agent_safety.yaml` | GADK-101, 102 | Agent constructor safety kwargs | [Policy/google_adk/agent_safety.md](Policy/google_adk/agent_safety.md) |

---

## OWASP LLM Top 10:2025 coverage map

All rules cite at least one OWASP LLM Top 10:2025 entry. Coverage by standard ID:

| OWASP LLM ID | Name | Rules |
|---|---|---|
| LLM01 | Prompt Injection | CSDK-004, CSDK-101, OAI-006, OAI-101, OAI-105, OSH-001, OSH-003, MCP-001, MCP-002, MCP-003, CATL-001, CATL-002, CATL-003, GADK-004, GADK-008, GADK-101 |
| LLM02 | Sensitive Information Disclosure | OAI-201, CATL-005 |
| LLM05 | Improper Output Handling | CSDK-005, OAI-004, OAI-102, OAIS-005, GADK-005, GADK-102 |
| LLM06 | Excessive Agency | CSDK-001, CSDK-002, CSDK-004, CSDK-006, CSDK-007, CSDK-101, OAI-003, OAI-101, OAI-102, OAI-103, OAI-104, OAI-006, OAIS-001, OAIS-002, OAIS-006, OAIS-007, OSH-002, OSH-003, OSH-005, OSH-006, OSH-007, MCP-004, CATL-001, CATL-002, CATL-003, CATL-004, CATL-006, CATL-007, GADK-001, GADK-002, GADK-004, GADK-006, GADK-007, GADK-101, GADK-102 |
| LLM10 | Unbounded Consumption | CSDK-003, OAI-103, OAI-005, OAI-201, OSH-004, OSH-005, CATL-008, CATL-009, GADK-003 |

---

## Summary

| Category | Tool rules | Agent rules | Repo rules | Total | IDs |
|----------|-----------|-------------|------------|-------|-----|
| Claude Agent SDK | 7 | 1 | 0 | 8 | CSDK-001–007, CSDK-101 |
| OpenShell | 4 | 0 | 3 | 7 | OSH-001–007 |
| OpenAI Agents SDK | 9 | 5 | 1 | 15 | OAIS-001–007, OAI-003–006, OAI-101–105, OAI-201 |
| MCP | 4 | 0 | 0 | 4 | MCP-001–004 |
| Catalog | 9 | 0 | 0 | 9 | CATL-001–009 |
| Google ADK | 8 | 2 | 0 | 10 | GADK-001–008, GADK-101–102 |
| **Total** | **41** | **8** | **4** | **53** | |

---

## Severity distribution

| Severity | Count | Rules |
|----------|-------|-------|
| Critical | 7 | OSH-001, MCP-002, MCP-003, CATL-001, CATL-002, CATL-006, GADK-008 (via score) |
| High | 22 | CSDK-003, CSDK-004, CSDK-101, OAI-005, OAI-006, OAI-101, OAI-102, OAI-103, OSH-002, OSH-003, OSH-005, OSH-006, OSH-007, MCP-001, CATL-003, CATL-004, CATL-005, GADK-003, GADK-004, GADK-008, GADK-101 |
| Medium | 16 | CSDK-002, CSDK-005, CSDK-006, OAI-003, OAI-004, OAI-104, OAI-201, OAIS-002, OAIS-005, OAIS-006, OSH-004, CATL-007, CATL-008, GADK-005, GADK-006, GADK-102 |
| Low | 8 | CSDK-001, CSDK-007, OAIS-001, OAIS-007, MCP-004, CATL-009, GADK-001, GADK-007 |
