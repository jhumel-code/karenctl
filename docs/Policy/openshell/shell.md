# Policy Rationale: OpenShell Shell Invocation Safety

**Policy ID:** `openshell_shell`  
**File:** `internal/rules/policies/openshell/shell.yaml`  
**Rules:** OSH-001, OSH-002  
**Severities:** Critical, High

---

## What this policy covers

Subprocess and shell invocations made from agent tools — specifically `shell=True` usage and unconstrained binary invocations without a command allowlist.

---

## Why shell invocation is the highest-risk operation in agent tools

When an agent tool shells out, it crosses a privilege boundary. The Python process runs with the agent's service account permissions. Any command the tool executes inherits those permissions. Unlike network calls (which are bounded by what the remote API accepts) or filesystem calls (which are bounded by OS permissions), shell invocations can:

- Execute any installed binary on the system.
- Chain commands with `;`, `&&`, `||`, `|`.
- Redirect output to files, network connections, or other processes.
- Start background processes that outlive the tool call.

The OpenShell sandbox constrains this at the OS level (seccomp, namespaces, cgroup limits), but only for the surface area it can identify. A `shell=True` call fundamentally undermines this because the shell interpreter itself is not constrainable at the same level as individual subprocess calls.

---

## Rule-by-rule defense

### OSH-001 — subprocess called with shell=True (Severity: Critical, Confidence: 0.99)

**What we detect:**  
Any call with prefix `subprocess.` where the keyword argument `shell` is set to `True`.

**Why it is flaggable:**  
`subprocess.run(cmd, shell=True)` passes `cmd` to the system shell (`/bin/sh -c cmd`). The shell interprets metacharacters: semicolons, pipes, backticks, dollar signs, redirects. If `cmd` contains any model-controlled substring, the model (or a prompt injection payload in data the model processed) can inject shell metacharacters.

Example:
```python
subprocess.run(f"grep {query} /var/log/app.log", shell=True)
```
A model-controlled `query = "foo; rm -rf /var/log"` results in:
```
/bin/sh -c "grep foo; rm -rf /var/log /var/log/app.log"
```

This is shell injection. The OpenShell sandbox cannot fully prevent this because the shell is a trusted process — constraining `sh` means constraining everything it can run, which is effectively unconstrained unless you enumerate every command.

**Why Critical:**  
`shell=True` with any model-controlled input is unconditional remote code execution via prompt injection. There is no partial mitigation — the fix is required. Confidence is 0.99 because the detection is syntactic: we look for `shell=True` as a keyword argument.

**The 1% gap:** Dynamic attribute access (`kwargs = {'shell': True}; subprocess.run(cmd, **kwargs)`) is not caught by our AST analysis.

---

### OSH-002 — Shell invocation without an allowed-command list (Severity: High, Confidence: 0.85)

**What we detect:**  
Tools that contain a shell call (`has_shell_call: true`) but do not contain any of the strings `ALLOWED_COMMANDS`, `allowlist`, or `ALLOWED_CMDS` in the function body.

**Why it is flaggable:**  
Even without `shell=True`, a tool that calls `subprocess.run([user_input, arg1, arg2])` is vulnerable. `argv[0]` (the binary name) is model-controlled. With no allowlist, the model can invoke:
- `rm` to delete files.
- `curl` to exfiltrate data.
- `python` to run arbitrary code.
- `nc` to open a reverse shell.

All installed binaries on the system are potential `argv[0]` values. The OpenShell sandbox can enforce a command allowlist at the OS level, but the allowlist must exist somewhere — if it is not defined in code, there is no source of truth for the policy to enforce.

**Real-world consequence:**  
An agent tool designed to run `ffmpeg` for media processing, if it accepts the binary name as a parameter: `run_binary(binary="rm", args=["-rf", "/"])`.

**Why High (not Critical):**  
Without `shell=True`, shell metacharacter injection is not possible — each argv entry is passed as a separate argument to `execve`, with no shell interpretation. An unconstrained `argv[0]` is still extremely dangerous but requires the model to supply a valid binary name rather than arbitrary shell syntax.

**Confidence 0.85:**  
We search for allowlist-related strings in the function body. A tool that enforces the allowlist via a separate validation module imported elsewhere would be a false positive. The 15% gap acknowledges this limitation.

---

## What this policy does not cover

- Injection via `argv[1...]` — if the binary is constrained but arguments are not, argument injection in programs that accept arguments as commands (e.g., `python -c "..."`, `bash -c "..."`) is still possible.
- `os.system()` — equivalent to `subprocess.run(shell=True)` but detected separately. Currently not in scope for this rule.
- Tools that build commands using string concatenation that feeds into a list (not caught by `shell=True` detection but still exploitable via argument injection).

---

## Recommendations beyond the fix

```python
ALLOWED_COMMANDS = frozenset(["ffmpeg", "convert", "identify"])

@tool
def process_media(input_file: str, output_format: str) -> dict:
    """Process media file. Only ffmpeg, convert, and identify are permitted."""
    command = "ffmpeg"  # hardcoded, not model-supplied
    if command not in ALLOWED_COMMANDS:
        return {"error": "command_not_allowed", "retryable": False}
    resolved_input = Path(input_file).resolve()
    if not resolved_input.is_relative_to(ALLOWED_MEDIA_ROOT):
        return {"error": "path_not_allowed", "retryable": False}
    result = subprocess.run(
        ["ffmpeg", "-i", str(resolved_input), f"output.{output_format}"],
        capture_output=True, timeout=30
    )
    return {"success": result.returncode == 0, "stderr": result.stderr.decode()}
```

1. Never make the binary name a model-supplied parameter. Hardcode it or map a semantic action name to a binary.
2. Combine with path validation (CSDK-004 / OSH-003) — shell tools that also accept paths need both fixes.
3. Use `subprocess.run` with `capture_output=True` to prevent tool output from flowing to stdout where it might interfere with the agent's log pipeline.
4. Set `timeout=` on every subprocess call (same rationale as CSDK-003 for HTTP calls).
