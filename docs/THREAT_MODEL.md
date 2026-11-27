# Threat model: dangerous model-generated tool-call arguments

## Honesty statement

This project is a **defensive argument validator**. It does not disclose a new
vulnerability, does not claim a new CVE, and does not make a dangerous tool call
safe. Command injection (CWE-78), path traversal (CWE-22) and server-side request
forgery (CWE-918) are long-standing public classes of bugs. The validator reduces
the chance that a model-generated argument reaches a shell, file API or HTTP
client in a damaging form; it is not a sandbox and not a model-level guard.

## 1. The threat

An LLM agent turns user/tool content into structured tool calls. The model is not
a security boundary: prompt injection, hallucination or a malicious tool output
can steer it to call a dangerous tool with a dangerous argument. Typical cases:

```
{"tool": "shell.run",  "arguments": {"command": "ls; rm -rf /data"}}
{"tool": "file.read",  "arguments": {"path": "../../etc/passwd"}}
{"tool": "http.fetch", "arguments": {"url": "http://169.254.169.254/latest/meta-data/"}}
```

The application (not the model) decides whether to execute. The validator is the
cheap, deterministic first line of that decision.

## 2. Layers and severity rationale

### 2.1 Shape validation (JSON Schema subset)

Malformed arguments are a functional and security risk: a missing required field
may make a tool fall back to an implicit default; an unexpected `mode` flag may
select a dangerous code path. Schema findings are **medium** severity because a
correctly implemented tool rejects them anyway — the schema is the contract, not
the exploit. Supported keywords are listed in the README; unsupported keywords
are ignored rather than silently enforced.

### 2.2 Value rules

| Class | Rule | Severity | Rationale |
| --- | --- | --- | --- |
| shell chaining | `ARG-COMMAND-CHAIN` | high | `; rm -rf` turns a read-only command into data loss |
| substitution | `ARG-COMMAND-SUBST` | high | backticks/`$()` execute nested commands |
| newline | `ARG-NEWLINE` | high | a newline starts a second command in a shell |
| redirection | `ARG-REDIRECT` | medium | `>` can overwrite files; needs a shell to act |
| env expansion | `ARG-ENV-EXPANSION` | low | expands secrets/paths, useful for recon |
| traversal | `ARG-PATH-TRAVERSAL` | high | escapes the intended directory root |
| sensitive path | `ARG-ABS-SENSITIVE-PATH` | high | credentials, system and autostart locations |
| non-http scheme | `ARG-URL-SCHEME` | high | `file:` reads local files; `gopher:`/`dict:` bypass naive fetch filters |
| loopback | `ARG-SSRF-LOOPBACK` | high | reaches admin panels not exposed to the internet |
| metadata | `ARG-SSRF-METADATA` | high | cloud metadata endpoints hand out credentials |
| private ranges | `ARG-SSRF-PRIVATE` | medium | internal services; context-dependent impact |
| obfuscated IP | `ARG-SSRF-OBFUSCATED` | high | integer/hex forms defeat string checks in other layers |
| URL credentials | `ARG-URL-CREDENTIALS` | medium | leaks credentials to the destination and logs |
| NUL/control | `ARG-CONTROL-CHARS` | high | truncates C strings, confuses parsers |
| size | `ARG-OVERSIZED*` | medium | memory/DoS and accidental prompt-stuffing |

**Context split.** Shell rules are applied only to command-like tools or argument
names (`command`, `cmd`, `script`, `shell`, `exec`, `code`, `argv`, ...). Path and
URL rules apply to every string. A semicolon inside a translation text is not a
command chain; flagging it would make the tool unusable. This trade-off is
intentional and is itself a documented limitation (recall is not 100%).

## 3. What this does not claim

* Not a sandbox and not a policy engine: it validates arguments, not effect.
* Not a model-level guard: prompt injection can still choose a legitimate-but-
  harmful call (e.g. deleting a file inside the allowed root).
* A clean scan is not proof of safety; crafted quoting/encodings can evade any
  pattern validator.
* The JSON-Schema subset is not full Draft 2020-12; unsupported keywords are
  ignored (documented rather than enforced silently).
* No new CVE and no vulnerability disclosure process.

## 4. Limitations, explicitly

* Shell-rule context detection is name-based; a tool that runs shell commands but
  names its argument `query` will not receive shell rules (its path/URL rules
  still run).
* Quoting heuristics understand simple single/double quotes only; nested or
  escaped quoting may produce false positives/negatives.
* Sensitive-path matching is a curated list, not exhaustive; extend it for your
  own platform and deployment.
* URL checks inspect the literal string; DNS rebinding and redirect chains are
  runtime problems that must be solved in the HTTP client.
* Argument size limits are conservative defaults; tune them for your tools.

## 5. Recommended architecture

1. Validate arguments with this tool (or equivalent) before execution.
2. Implement tools with parameterised APIs — an argv list, no `shell=True`, no
   string interpolation into SQL/shell/paths.
3. Confine filesystem access to an explicit root and verify with
   `realpath`/`commonpath`/`is_relative_to`.
4. Force egress through a proxy with an allowlist; block link-local/metadata
   ranges at the network layer.
5. Require human approval for destructive or externally visible actions.
6. Log the tool call parameters (redacted) for audit.

## 6. Prior art

* MITRE CWE-78 (OS Command Injection), CWE-22 (Path Traversal), CWE-918 (SSRF).
* OWASP Top 10 and the OWASP SSRF Prevention Cheat Sheet.
* Public cloud metadata credential-theft research (169.254.169.254).
* General LLM agent/tool-calling security literature and prompt-injection work.
