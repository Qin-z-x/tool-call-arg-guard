## tool-call-arg-guard v0.1.0

Validate model-generated tool-call arguments before they reach a shell, a file
API or an HTTP client. Stdlib-only Python.

### Included

- `python -m toolarg_guard scan|report` with `--json`, `--fail-on` and optional
  `--tools schema.json` for argument-shape validation (exit codes 0/1/2).
- A strict JSON-Schema subset: type, properties, required, additionalProperties,
  items, enum, minLength/maxLength, pattern, minimum/maximum, anyOf/oneOf.
- Safety rules: unquoted shell chaining/substitution in command-like arguments,
  path traversal (`../`, `..\`, `%2e%2e`), sensitive absolute paths
  (System32, /etc, .ssh, .aws), SSRF-ish URLs (localhost, RFC1918, cloud metadata,
  integer/obfuscated IP forms, file:/gopher:/dict:), null/control bytes and
  oversized argument values/calls.
- 42 unit tests, GitHub Actions CI on Python 3.10/3.12, real captured evidence.

### Honest notes

- This is a defensive argument validator, not a sandbox and not a model-level
  guard. It does not disclose a new vulnerability and does not claim a new CVE;
  command injection, path traversal and SSRF are public prior art (CWE-78,
  CWE-22, CWE-918).
- Rules are heuristic and context-aware: shell rules run on command-like
  arguments/tools, path and URL rules run on every string. A determined argument
  can evade a pattern validator; the real fix is least privilege and
  parameterised tool implementations.
