# Policy Rationale: OpenShell Filesystem Write Containment

**Policy ID:** `openshell_filesystem`  
**File:** `internal/rules/policies/openshell/filesystem.yaml`  
**Rules:** OSH-003  
**Severity:** High

---

## What this policy covers

Tool functions that perform filesystem write or delete operations without an OpenShell write-prefix restriction. This covers any call detected as a write operation (`has_write_call: true`), including `open(..., 'w')`, `shutil.copy`, `shutil.move`, `os.remove`, `os.unlink`, `os.rename`, and similar.

---

## Why filesystem write containment matters

A tool that writes to the filesystem is operating on shared, persistent state. Unlike a failed network call (which leaves no residue), a bad write:

- Persists after the agent run ends.
- Affects other processes, users, or services sharing the same filesystem.
- May be irreversible (overwriting a file, deleting a directory).
- Can affect system integrity if the write reaches outside the tool's intended scope.

In an agent context, the path that determines *where* the write lands often originates from model output — which is, in turn, influenced by the content the model read during the conversation. Prompt injection can influence this path.

---

## Rule-by-rule defense

### OSH-003 — Filesystem write without sandbox restriction (Severity: High, Confidence: 0.80)

**What we detect:**  
Any tool function containing a write call (`has_write_call: true`) — currently covering `open` with write/append mode, `shutil.copy`, `shutil.move`, `shutil.copytree`, `os.remove`, `os.unlink`, `os.rename`, `os.makedirs`, and `Path.write_text` / `Path.write_bytes`.

**Why it is flaggable:**  
Without a write-prefix restriction in the OpenShell sandbox policy, the tool's filesystem writes are bounded only by the OS user permissions under which the agent runs. If the agent runs as a service account with write access to `/app`, the tool can write anywhere under `/app` — including configuration files, templates, code, and log files.

This matters because:
1. **Path traversal** (see CSDK-004/CATL-003): model-controlled paths can escape the intended working directory.
2. **Accidental writes**: even without an adversary, a model generating filenames can produce paths that conflict with system files if the write root is not bounded.
3. **Cross-user contamination**: in multi-tenant agent deployments, one user's agent writing to a shared filesystem without scope boundaries can read or overwrite another user's files.

**Real-world consequence:**  
An agent tool `save_report(path, content)` that writes to an unbounded filesystem:
- In a single-tenant deployment: model hallucinates `path = "../../etc/cron.d/backdoor"` via prompt injection → scheduled job is planted.
- In a multi-tenant deployment: model constructs `path = "../user_B/reports/latest.pdf"` → user A's agent overwrites user B's file.

**Why High (not Critical):**  
Exploitation via path traversal requires a prompt injection attack to succeed first. Without injection, the tool writes correctly. The sandbox restriction is a defense-in-depth measure that constrains the blast radius of a traversal even when the code-level validation (CSDK-004) is present.

**Confidence 0.80:**  
Write call detection is broad but not exhaustive. Custom file-writing libraries, database file writes, or writes via subprocess are not caught. The 20% gap accounts for these cases.

---

## What this policy does not cover

- **Reads:** OSH-003 fires on writes; read-only operations with no validation are covered by CSDK-004/CATL-003.
- **Writes via subprocess:** a tool that calls `subprocess.run(["cp", src, dst])` writes to the filesystem but is not caught by this rule (covered by OSH-001/002 instead).
- **Database writes:** writing to SQLite or another file-backed database via a driver is not detected as a write call.
- **Atomicity:** even within a restricted prefix, non-atomic writes (write to final path directly rather than write-then-rename) can produce inconsistent state under concurrent access.

---

## The OpenShell policy layer

This rule's fix_hint (`policy_emit: fs_write_prefix`) instructs the generator to emit a write-prefix restriction in the OpenShell sandbox config:

```yaml
filesystem:
  write_prefix: /app/agent_workdir/
```

This means the OS-level sandbox enforces the prefix even if the Python code has a bug in its path validation. The two layers (code-level `resolve()` + OS-level prefix) are intended to be defense-in-depth, not alternatives.

---

## Recommendations beyond the fix

1. Designate a single write root per agent deployment (e.g., `/app/data/<session_id>/`) and create it fresh for each conversation session.
2. Use a session-scoped directory as the write root so files from different conversations cannot interfere.
3. Validate that the write root exists and is writable at tool startup — surface a clear error if it is not, rather than failing at the first write.
4. For tools that produce output files the model will later read back (e.g., `generate_report` → `read_report`), use stable, predictable filenames within the scope rather than model-supplied names.
5. Consider write auditing: log every write (path + size + session_id) to a separate append-only log for incident investigation.
