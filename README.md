# tool-call-arg-guard

[![CI](https://github.com/Qin-z-x/tool-call-arg-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/Qin-z-x/tool-call-arg-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![stdlib-only core](https://img.shields.io/badge/core-stdlib%20only-brightgreen.svg)](scripts/check_core_deps.py)

**Validate model-generated tool-call arguments before they reach a shell, a file
API or an HTTP client.** An LLM agent decides *which* tool to call and *with what
arguments*; the application decides whether those arguments are safe. This
project is a standard-library-only validator with two independent layers:

1. a JSON-Schema subset for the tool's argument **shape**;
2. heuristic safety rules for argument **values** — shell chaining/substitution,
   path traversal, sensitive absolute paths, SSRF-ish URLs (localhost, RFC1918,
   cloud metadata, integer IP forms), NUL/control bytes and oversized arguments.

```console
$ python -m toolarg_guard scan examples/dangerous_call.json
toolarg-guard 0.1.0  scan  examples/dangerous_call.json  (4 call(s))
call 1/4  tool=shell.run  findings=3  max_severity=high
  HIGH   ARG-SSRF-METADATA          arguments.command            URL targets a cloud metadata endpoint (169.254.169.254)
  HIGH   ARG-COMMAND-CHAIN          arguments.command            unquoted command chaining (; && ||) in a shell argument
  HIGH   ARG-PATH-TRAVERSAL         arguments.cwd                path traversal sequence escapes the working directory
call 2/4  tool=file.read  findings=1  max_severity=high
  HIGH   ARG-ABS-SENSITIVE-PATH     arguments.path               sensitive absolute path (credentials, system or autostart location)
call 3/4  tool=http.fetch  findings=1  max_severity=high
  HIGH   ARG-SSRF-LOOPBACK          arguments.url                URL targets loopback/unspecified host '127.0.0.1'
call 4/4  tool=shell.run  findings=1  max_severity=high
  HIGH   ARG-ABS-SENSITIVE-PATH     arguments.command            sensitive absolute path (credentials, system or autostart location)
summary: 6 finding(s): 6 high, 0 medium, 0 low
```

The clean example contains a benign semicolon inside a text argument and a
public HTTPS URL — neither is flagged:

```console
$ python -m toolarg_guard scan examples/clean_call.json --fail-on low
PASS: no finding at or above severity 'low'
```

## The two layers

### 1. Argument shape (JSON Schema subset)

`--tools tools.json` accepts either `{tool_name: schema}` or
`{"tools": [{"name": ..., "parameters": ...}]}`. Supported keywords: `type`,
`properties`, `required`, `additionalProperties`, `items`, `enum`, `minLength`,
`maxLength`, `pattern`, `minimum`, `maximum`, `anyOf`/`oneOf`. Unsupported
keywords are ignored (documented honestly, not silently enforced).

```console
$ python -m toolarg_guard scan examples/bad_schema_call.json --tools examples/tools.json
call 1/3  tool=weather.get  findings=2  max_severity=medium
  MEDIUM TOOL-SCHEMA-TYPE           arguments.city               expected type string, got integer
  MEDIUM TOOL-SCHEMA-ENUM           arguments.units              value 'kelvin' is not one of ['metric', 'imperial']
...
```

### 2. Argument values (safety rules)

| Rule | Severity | Detects |
| --- | --- | --- |
| `ARG-COMMAND-CHAIN` | high | unquoted `;`, `&&`, `||` in a command-like argument |
| `ARG-COMMAND-SUBST` | high | backticks / `$(` substitution |
| `ARG-NEWLINE` | high | newline in a command argument |
| `ARG-CONTROL-CHARS` | high | NUL / control characters (any argument) |
| `ARG-REDIRECT` | medium | unquoted `<`, `>`, `>>` |
| `ARG-SHELL-METACHAR` | medium | other unquoted shell metacharacters |
| `ARG-ENV-EXPANSION` | low | `$VAR`, `${VAR}`, `%VAR%` in a command argument |
| `ARG-PATH-TRAVERSAL` | high | `../`, `..\`, `%2e%2e` and mixed-separator traversal |
| `ARG-ABS-SENSITIVE-PATH` | high | System32, /etc/passwd, .ssh/.aws/.kube, macOS launch agents, AppData autostart |
| `ARG-URL-SCHEME` | high | `file:`, `gopher:`, `dict:` (non-HTTP fetch schemes) |
| `ARG-SSRF-LOOPBACK` | high | localhost, 127.0.0.0/8, 0.0.0.0, `[::1]` |
| `ARG-SSRF-METADATA` | high | 169.254.169.254, metadata.google.internal, 100.100.100.200 |
| `ARG-SSRF-PRIVATE` | medium | RFC1918 / CGNAT / `.internal` / `.local` |
| `ARG-SSRF-OBFUSCATED` | high | integer and hex IP forms for a private address |
| `ARG-URL-CREDENTIALS` | medium | `user:password@host` userinfo in a URL |
| `ARG-OVERSIZED` / `ARG-OVERSIZED-CALL` | medium | argument length / serialized call size above the limit |

Shell rules are applied only to **command-like** tools or argument names
(`command`, `cmd`, `script`, `shell`, `exec`, `code`, ...); path and URL rules are
applied to every string. This context split keeps false positives low (a
semicolon in a translation text is not a command chain) and is documented in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Install

```bash
git clone https://github.com/Qin-z-x/tool-call-arg-guard.git
cd tool-call-arg-guard
python -m pip install -e .       # optional: installs the toolarg-guard CLI
```

No runtime dependencies. Python 3.10+.

## CLI

```text
python -m toolarg_guard scan   <call.json|-> [--tools SCHEMA.json] [--json] [--fail-on {low,medium,high}]
                                              [--max-arg-len N] [--max-call-bytes N]
python -m toolarg_guard report <call.json|-> [--tools SCHEMA.json] [--json]
```

Exit codes: `0` success / gate not reached, `1` `--fail-on` threshold reached,
`2` usage error, missing file, invalid JSON or invalid payload shape.

Input shapes accepted: a single `{"tool": ..., "arguments": {...}}` object, a
list of such objects, or `{"calls": [...]}`.

Typical integration:

```python
from toolarg_guard import scan_payload

report = scan_payload({"calls": model_tool_calls}, schemas=tool_schemas)
if report["summary"]["counts"]["high"]:
    raise RuntimeError("tool call rejected: %s" % report["calls"])
execute_only_after_approval(model_tool_calls)
```

## Why this matters (public prior art)

* **CWE-78 OS command injection** — model-generated `command` strings passed to
  a shell; command chaining and substitution are the classic exploit primitives.
* **CWE-22 path traversal** — `path`/`file` arguments escaping a sandbox root.
* **CWE-918 server-side request forgery** — `url` arguments aimed at localhost,
  private networks or cloud metadata services (the 169.254.169.254 metadata
  endpoint is a well-known credential-theft target).
* **Tool-call argument confusion** — malformed or unexpected arguments that the
  tool implementation does not validate.

This project is a **validator**, not a sandbox: it gives the application a cheap,
dependency-free first line of defence and a machine-readable report for approval
UIs and CI.

## Tests and CI

```bash
python scripts/check_core_deps.py            # stdlib-only core check
python -m unittest discover -s tests -t .    # 42 tests
python scripts/capture_evidence.py           # regenerate docs/EVIDENCE.md + captures
```

CI (`.github/workflows/ci.yml`) runs on GitHub Actions for Python 3.10 and 3.12:
stdlib-only check, the unit tests, a JSON smoke test, the clean-call gate, the
schema-validation exit code and both expected outcomes of the `--fail-on high` gate.

## Honest scope and limits

* **Heuristic, not a proof.** Crafted quoting, encodings and argument shapes can
  evade pattern checks. A clean result is not a safety guarantee.
* The JSON-Schema support is a deliberate subset, not full Draft 2020-12.
* Shell rules are context-aware by design (see above); path/URL rules run on all
  strings. Document the residual risk in your own threat model.
* This does not disclose a new vulnerability and does not claim a new CVE;
  CWE-78/22/918 are long-standing public classes.
* The real mitigation is **least privilege**: parameterised tool
  implementations, no `shell=True` string interpolation, filesystem root
  confinement, an egress allowlist and human approval for destructive actions.
* The validator checks arguments, not tool output or the model's intent.

## Suggested GitHub topics

`security`, `llm`, `tool-calling`, `json-schema`, `command-injection`, `ssrf`,
`validation`, `python`, `cli`, `ai-agents`

## 中文简介

**tool-call-arg-guard** 在模型生成的工具调用参数真正执行前做校验，分两层：

1. **参数结构**：JSON-Schema 子集（type/properties/required/additionalProperties/
   items/enum/length/pattern/min/max/anyOf/oneOf）；
2. **参数取值安全规则**：命令拼接/替换（`;`、`&&`、`||`、反引号、`$()`）、换行注入、
   路径穿越（`../`、`%2e%2e`）、敏感绝对路径（System32、/etc、.ssh、.aws）、
   SSRF 型 URL（localhost、内网段、云元数据 IP、整数/十六进制 IP 变形、file/gopher/dict
   协议）、NUL 控制字符以及超大参数。

核心库**仅使用 Python 标准库**，提供 `scan` / `report` 两个 CLI 子命令，支持
`--json`、`--tools schema.json` 与 `--fail-on` CI 门禁（发现高危返回退出码 1）。
安全规则按上下文区分：命令类参数才做 shell 规则，路径/URL 规则对所有字符串生效，
以减少误报（例如翻译文本里的分号不会被误判）。本项目是防御性参数校验器，不是沙箱，
也不声称发现新漏洞或新 CVE；真正的修复是最小权限 + 参数化工具实现。

## 视频演示

B站：https://www.bilibili.com/video/BV1BE1pztEYA（66 秒）

视频使用本仓库自带的合成/无害样例与真实命令输出；本项目是启发式检测工具，边界见上文说明。

## License

MIT -- see [LICENSE](LICENSE). Prior art acknowledged: CWE-78, CWE-22, CWE-918,
cloud metadata SSRF research, and the general LLM tool-calling security literature.

## 系列：LLM 安全防护工具

本项目是「LLM 安全 7 件套」之一：[llm-markdown-xss-guard](https://github.com/Qin-Z-x/llm-markdown-xss-guard)（模型输出 XSS 净化）、[model-pii-redactor](https://github.com/Qin-Z-x/model-pii-redactor)（模型输出 PII/密钥脱敏）、[rag-poison-guard](https://github.com/Qin-Z-x/rag-poison-guard)（RAG 语料投毒扫描）、[llm-sql-injection-guard](https://github.com/Qin-Z-x/llm-sql-injection-guard)（模型生成 SQL 注入 lint）、[ai-agent-permission-guard](https://github.com/Qin-Z-x/ai-agent-permission-guard)（Agent 工具权限审计）、[llm-file-path-guard](https://github.com/Qin-Z-x/llm-file-path-guard)（生成代码路径穿越扫描）

- GitHub 主页（全部 14 个项目）：https://github.com/Qin-Z-x
- B站演示合集（7 工具 4 分钟）：https://www.bilibili.com/video/BV1jH1pz4ED7

- 7 件套在线索引：https://github.com/Qin-Z-x/llm-security-toolkit （页面：https://qin-z-x.github.io/llm-security-toolkit/）
