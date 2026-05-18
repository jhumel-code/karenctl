# Policy Rationale: Claude SDK Filesystem Path Safety

**Policy ID:** `claude_sdk_path_safety`  
**File:** `internal/rules/policies/claude_sdk/path_safety.yaml`  
**Rules:** CSDK-004  
**Severity:** High

---

## What this policy covers

Model-supplied filesystem path parameters flowing into file I/O calls (`open`, `Path`, `shutil.*`, `os.*`) without first being resolved and validated against an allowed root directory.

---

## Why path traversal in agent tools is a distinct threat

Path traversal (`../../etc/passwd`) is a well-understood class of vulnerability in web applications. In agent tools, the attack surface is wider for two reasons:

**1. The model, not the user, supplies the path.**  
An attacker does not need to craft a malicious HTTP request. They need to craft a malicious *prompt* that causes the model to pass a traversal payload as a tool argument. This is prompt injection — a class of attack that is increasingly documented against production agents. The model acts in good faith; the adversarial input comes from data the model reads (a webpage, a document, an email).

**2. The tool has filesystem access the model's context window does not.**  
The model cannot "see" `/etc/passwd` unless the tool reads it and returns it. But once a `read_file` or `write_file` tool is in scope, the model becomes an indirection layer through which an attacker can read or write arbitrary files — as long as the path is not validated.

---

## Rule-by-rule defense

### CSDK-004 — Path parameter used in I/O without validation (Severity: High, Confidence: 0.70)

**What we detect:**  
A tool function that:
1. Has a parameter whose name contains `path`, `file`, `dir`, `directory`, or `filepath` (heuristic for "this is a path").
2. Passes that parameter to `open()`, `Path()`, or any `shutil.*` or `os.*` call.
3. Does not call `.resolve()` on the path before using it in the I/O call.

**Why it is flaggable:**  
`open("../../etc/passwd")` and `Path("../../etc/passwd").read_text()` both work. Python's file I/O layer does not constrain paths to any root — it resolves relative paths against the process working directory. A tool that accepts a path from the model and passes it directly to `open()` is exploitable via any path traversal string that the model can be induced to supply.

**Real-world consequence:**  
- A `read_file(path)` tool with no validation: prompt inject `../../../../etc/shadow` and the tool returns the shadow password file.
- A `write_file(path, content)` tool with no validation: prompt inject `../../app/templates/index.html` and overwrite the web application's HTML.
- A `delete_file(path)` tool: prompt inject `../../.env` and delete the credentials file.

These are not theoretical. In red-team exercises against production agent deployments, path traversal via prompt injection is consistently one of the first successful attack paths found.

**Why severity is High and not Critical:**  
Exploitation requires a prompt injection attack to succeed first — the attacker must cause the model to use a malicious path. This is a meaningful barrier compared to direct user input. High (not Critical) reflects this dependency, while still requiring a fix before shipping.

**Confidence 0.70:**  
This is the lowest-confidence rule in the claude_sdk category because the detection is heuristic:

- We look for parameter names containing path-like substrings. A parameter named `target` that receives a path will evade this rule.
- We check for `.resolve()` absence, but `.resolve()` is not the only valid mitigation — `os.path.realpath()` is equivalent, and pattern-matching validation (`re.match(r'^/safe/root/.*', path)`) also works, though less robustly.
- A tool may receive a path from a non-parameter source (e.g., constructed from another return value) and we would miss it.

The 30% false-negative and false-positive rate is acceptable because: (a) high confidence at the cost of false positives would spam users; (b) the fix is cheap (one `.resolve()` call + an assert); and (c) the rule text explicitly says "confirm the parameter is genuinely user-supplied before applying the fix."

---

## What this policy does not cover

- Paths constructed from multiple parameters (e.g., `os.path.join(base, user_part)`).
- Paths supplied via environment variables or config files rather than parameters.
- Symlink attacks: `.resolve()` resolves symlinks, but a race condition between the resolve and the open (TOCTOU) can still be exploited in adversarial environments.
- `tempfile` usage — a tool that writes to a tempfile and returns the path may expose data even if the write path is safe.

---

## Known false positives

- Tools that accept `path` as a parameter but validate it via a regex or allowlist before the I/O call: the rule fires, but the tool is already safe. Suppress by adding `.resolve()` anyway (it is not harmful and makes the safety explicit).
- Tools that accept `path` as a parameter name for non-filesystem purposes (e.g., a URL path component). The fix does not apply — suppress the rule with a comment and document why.

---

## Recommendations beyond the fix

```python
# Robust path validation pattern
from pathlib import Path

ALLOWED_ROOT = Path("/app/data").resolve()

def read_file(path: str) -> str:
    resolved = Path(path).resolve()
    if not resolved.is_relative_to(ALLOWED_ROOT):
        return {"error": "path_not_allowed", "retryable": False}
    return resolved.read_text()
```

1. `.resolve()` alone is not enough — always assert the resolved path is *under* an allowed root.
2. Use `Path.is_relative_to()` (Python 3.9+) rather than string prefix matching — string matching can be fooled by directory names that share prefixes.
3. Consider using `ALLOWED_ROOT` as a constant that appears in code review and code search, making the sandbox boundary explicit and auditable.
4. For write tools, create the allowed root at startup and validate it exists — do not let the tool create directories outside the allowed root.
