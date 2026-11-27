"""toolarg_guard core: validate model-generated tool-call arguments.

The validator has two independent layers:

1. a small JSON-Schema subset for the tool's argument shape;
2. heuristic safety checks on the argument values: shell chaining/substitution,
   path traversal, sensitive absolute paths, SSRF-ish URLs, null bytes and
   oversized arguments.

Both layers return ``Finding`` objects with a stable ``code``, a severity and the
JSON path of the argument that triggered them.
"""

from __future__ import annotations

import json
import posixpath
import re
from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit

VERSION = "0.1.0"

SEVERITIES = ("low", "medium", "high")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES, start=1)}

COMMAND_KEYS = frozenset({"argv", "args", "cmd", "command", "commands", "code", "exec", "script", "shell"})
SHELL_TOOL_RE = re.compile(r"(?i)(shell|exec|command|bash|powershell|terminal|\bcmd\b|script|run_command)")
PRIVATE_HOST_SUFFIXES = (".internal", ".local", ".localhost")

SHELL_META_RE = re.compile(r"[;|&`]|\$\(|\$\{")
CHAIN_RE = re.compile(r"&&|\|\||;")
BACKTICK_RE = re.compile(r"`|\$\(")
REDIRECT_RE = re.compile(r"(?<![<>=])>>?(?![>=])|<(?![<=])")
ENV_EXPANSION_RE = re.compile(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|%[A-Za-z_][A-Za-z0-9_]*%")
TRAVERSAL_RE = re.compile(r"(?:^|[\\/])\.\.(?:[\\/]|$)")
URLENCODED_TRAVERSAL_RE = re.compile(r"%2e%2e(?:%2f|%5c|/|$)", re.IGNORECASE)
SENSITIVE_PATH_RE = re.compile(
    r"(?i)(?:"
    r"/etc/(?:passwd|shadow|sudoers)|\betc/passwd\b|"
    r"/root/|/proc/self|/proc/1/|/var/run/docker\.sock|"
    r"/\.ssh/|/\.aws/|/\.gnupg/|/\.kube/|id_rsa|id_ed25519|authorized_keys|\.aws/credentials|"
    r"[a-z]:[\\/]+windows[\\/]+(?:system32|syswow64)|\bwindows[\\/]+system32\b|"
    r"%userprofile%|%appdata%|%systemroot%|%windir%|"
    r"\\appdata\\roaming\\microsoft\\windows\\start menu|"
    r"/library/launchagents|/library/launchdaemons"
    r")"
)
EMBEDDED_URL_RE = re.compile(r"(?:https?|file|gopher|dict|ftp)://[^\s'\"<>]+", re.IGNORECASE)
CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")

FIXES = {
    "ARG-COMMAND-CHAIN": "Never pass a model-generated string to a shell. Use an argv list with no shell=True and reject unquoted ; && ||.",
    "ARG-COMMAND-SUBST": "Remove backticks and $(...) substitution; build commands from a fixed argv template, not from model text.",
    "ARG-REDIRECT": "Remove shell redirection from model arguments; write files through a scoped API instead of `>`/`<`.",
    "ARG-NEWLINE": "Reject newlines in command arguments; they can start a second command in a shell.",
    "ARG-ENV-EXPANSION": "Do not let model arguments expand environment variables; resolve paths in application code with an explicit allowlist.",
    "ARG-SHELL-METACHAR": "Reject unquoted shell metacharacters; use the tool's structured API instead of a shell string.",
    "ARG-PATH-TRAVERSAL": "Normalise the path, join it under a fixed root and verify the resolved path stays inside that root (realpath/commonpath/is_relative_to).",
    "ARG-ABS-SENSITIVE-PATH": "Deny sensitive absolute paths explicitly; run the tool in a sandbox with only the needed directories mounted.",
    "ARG-URL-SCHEME": "Allow only http(s) for fetch tools; reject file:, gopher:, dict: and other unexpected schemes.",
    "ARG-SSRF-LOOPBACK": "Resolve the hostname, reject loopback/link-local/private ranges, and use an egress proxy with an allowlist.",
    "ARG-SSRF-PRIVATE": "Reject private and link-local destination ranges; keep an explicit egress allowlist instead of a blocklist.",
    "ARG-SSRF-METADATA": "Block cloud metadata endpoints (169.254.169.254, metadata.google.internal, 100.100.100.200) at the network layer, not only in the validator.",
    "ARG-SSRF-OBFUSCATED": "Normalise integer/hex/obfuscated IP forms before the address-family check.",
    "ARG-URL-CREDENTIALS": "Strip username/password from URLs; credentials in a model-generated URL leak to the destination and into logs.",
    "ARG-CONTROL-CHARS": "Reject NUL and control characters in arguments; they truncate C strings and confuse downstream parsers.",
    "ARG-OVERSIZED": "Cap argument length and reject oversized values; chunk large content through a dedicated upload path.",
    "ARG-OVERSIZED-CALL": "Cap the serialized tool call size and stream large payloads out of band.",
    "TOOL-SCHEMA-REQUIRED": "Reject the call when a required argument is missing; the tool contract is the first line of defence.",
    "TOOL-SCHEMA-TYPE": "Validate the argument type at the tool boundary; coerce only deliberately and document it.",
    "TOOL-SCHEMA-ENUM": "Reject values outside the declared enum; never pass an unexpected mode/flag to the tool.",
    "TOOL-SCHEMA-PROPERTY": "Declare additionalProperties: false and reject unknown arguments instead of forwarding them.",
    "TOOL-SCHEMA-LENGTH": "Enforce length bounds in the schema and in the tool implementation.",
    "TOOL-SCHEMA-PATTERN": "Enforce a strict pattern for structured identifiers and paths.",
    "TOOL-SCHEMA-RANGE": "Enforce numeric bounds in the schema and in the tool implementation.",
    "TOOL-SCHEMA-ANYOF": "Require at least one declared argument shape to validate.",
}

SUGGESTED_SCHEMA = (
    'Example hardening: {"type": "object", "required": ["command"], '
    '"properties": {"command": {"type": "string", "maxLength": 512}}, "additionalProperties": false}'
)


@dataclass(frozen=True)
class Limits:
    max_arg_len: int = 4096
    max_call_bytes: int = 65536


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    message: str
    path: str = "arguments"
    data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "path": self.path,
            "fix": FIXES.get(self.code, ""),
            "data": self.data,
        }


def load_calls(payload) -> list:
    """Normalise a parsed JSON payload into a list of tool calls."""
    if isinstance(payload, dict) and isinstance(payload.get("calls"), list):
        return payload["calls"]
    if isinstance(payload, dict) and ("tool" in payload or "arguments" in payload or "args" in payload):
        return [payload]
    if isinstance(payload, list):
        return payload
    raise ValueError("expected a tool call object, a list of calls, or {'calls': [...]}")


def _walk_strings(value, path: str):
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _walk_strings(item, "%s.%s" % (path, key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _walk_strings(item, "%s[%d]" % (path, index))


def _unquoted(text: str) -> str:
    out = []
    quote = None
    for char in text:
        if quote:
            out.append(" ")
            if char == quote:
                quote = None
        elif char in "'\"":
            quote = char
            out.append(" ")
        else:
            out.append(char)
    return "".join(out)


def _type_name(value) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    return type(value).__name__


def _type_ok(value, expected: str) -> bool:
    if expected == "null":
        return value is None
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return True


def _schema_errors(value, schema, path: str) -> list:
    if not isinstance(schema, dict):
        return []
    errors = []
    for combinator, need_all in (("anyOf", False), ("oneOf", False)):
        options = schema.get(combinator)
        if isinstance(options, list) and options:
            matches = [not _schema_errors(value, option, path) for option in options]
            if not any(matches):
                errors.append((path, "%s: value matched none of the declared shapes" % combinator, "TOOL-SCHEMA-ANYOF"))
            return errors
    expected = schema.get("type")
    if expected is not None:
        types = expected if isinstance(expected, list) else [expected]
        if not any(_type_ok(value, name) for name in types):
            errors.append((path, "expected type %s, got %s" % ("/".join(types), _type_name(value)), "TOOL-SCHEMA-TYPE"))
            return errors
    if isinstance(value, dict):
        for required in schema.get("required", []) or []:
            if required not in value:
                errors.append(("%s.%s" % (path, required), "required property is missing", "TOOL-SCHEMA-REQUIRED"))
        properties = schema.get("properties") or {}
        additional = schema.get("additionalProperties", True)
        for key, item in value.items():
            if key in properties:
                errors.extend(_schema_errors(item, properties[key], "%s.%s" % (path, key)))
            elif additional is False:
                errors.append(("%s.%s" % (path, key), "property is not allowed by additionalProperties: false", "TOOL-SCHEMA-PROPERTY"))
            elif isinstance(additional, dict):
                errors.extend(_schema_errors(item, additional, "%s.%s" % (path, key)))
    if isinstance(value, list) and isinstance(schema.get("items"), dict):
        for index, item in enumerate(value):
            errors.extend(_schema_errors(item, schema["items"], "%s[%d]" % (path, index)))
    if isinstance(value, str):
        if "enum" in schema and value not in schema["enum"]:
            errors.append((path, "value %r is not one of %r" % (value, schema["enum"]), "TOOL-SCHEMA-ENUM"))
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append((path, "string shorter than minLength %d" % schema["minLength"], "TOOL-SCHEMA-LENGTH"))
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append((path, "string longer than maxLength %d" % schema["maxLength"], "TOOL-SCHEMA-LENGTH"))
        if "pattern" in schema:
            try:
                if not re.search(schema["pattern"], value):
                    errors.append((path, "string does not match pattern %r" % schema["pattern"], "TOOL-SCHEMA-PATTERN"))
            except re.error:
                pass
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append((path, "value below minimum %s" % schema["minimum"], "TOOL-SCHEMA-RANGE"))
        if "maximum" in schema and value > schema["maximum"]:
            errors.append((path, "value above maximum %s" % schema["maximum"], "TOOL-SCHEMA-RANGE"))
    return errors


def _looks_like_url(text: str) -> bool:
    return bool(re.match(r"(?i)^(?:https?|file|gopher|dict|ftp)://", text.strip()))


def _is_private_ip(host: str) -> int:
    """Return 2 for loopback/link-local, 1 for RFC1918-style private, 0 otherwise."""
    host = host.strip("[]").lower()
    parts = host.split(".")
    if not all(part.isdigit() for part in parts) or len(parts) != 4:
        return 0
    octets = [int(part) for part in parts]
    if any(octet > 255 for octet in octets):
        return 0
    if octets[0] == 127 or host == "0.0.0.0":
        return 2
    if octets[0] == 169 and octets[1] == 254:
        return 2
    if octets[0] == 10:
        return 1
    if octets[0] == 192 and octets[1] == 168:
        return 1
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return 1
    if octets[0] == 100 and 64 <= octets[1] <= 127:
        return 1
    return 0


def _url_findings(url: str, path: str) -> list:
    findings = []
    try:
        parts = urlsplit(url)
    except ValueError:
        return findings
    scheme = (parts.scheme or "").lower()
    if scheme in ("file", "gopher", "dict"):
        findings.append(Finding("ARG-URL-SCHEME", "high", "URL scheme %r is not an http(s) fetch scheme" % scheme, path, {"url": url[:200]}))
        return findings
    host = (parts.hostname or "").lower()
    if parts.username or parts.password:
        findings.append(Finding("ARG-URL-CREDENTIALS", "medium", "URL embeds username/password credentials", path, {"url": url[:200]}))
    if not host:
        return findings
    host_no_brackets = host.strip("[]")
    metadata_hosts = {"169.254.169.254", "metadata.google.internal", "100.100.100.200", "fd00:ec2::254"}
    if host_no_brackets in metadata_hosts or host_no_brackets.endswith(".metadata.google.internal"):
        findings.append(Finding("ARG-SSRF-METADATA", "high", "URL targets a cloud metadata endpoint (%s)" % host_no_brackets, path, {"url": url[:200]}))
    elif host_no_brackets in ("localhost", "::1", "0.0.0.0") or host_no_brackets.startswith("127."):
        findings.append(Finding("ARG-SSRF-LOOPBACK", "high", "URL targets loopback/unspecified host %r" % host_no_brackets, path, {"url": url[:200]}))
    elif _is_private_ip(host_no_brackets) == 1:
        findings.append(Finding("ARG-SSRF-PRIVATE", "medium", "URL targets a private address range (%s)" % host_no_brackets, path, {"url": url[:200]}))
    elif host_no_brackets.endswith(PRIVATE_HOST_SUFFIXES):
        findings.append(Finding("ARG-SSRF-PRIVATE", "medium", "URL targets an internal hostname suffix (%s)" % host_no_brackets, path, {"url": url[:200]}))
    elif host_no_brackets.isdigit():
        number = int(host_no_brackets)
        if number <= 0xFFFFFFFF and _is_private_ip(".".join(str((number >> shift) & 0xFF) for shift in (24, 16, 8, 0))):
            findings.append(Finding("ARG-SSRF-OBFUSCATED", "high", "URL uses an integer IP form for a private address (%s)" % host_no_brackets, path, {"url": url[:200]}))
    elif re.fullmatch(r"0x[0-9a-f]+", host_no_brackets):
        findings.append(Finding("ARG-SSRF-OBFUSCATED", "high", "URL uses a hex IP form (%s)" % host_no_brackets, path, {"url": url[:200]}))
    if parts.port and scheme == "http" and parts.port not in (80, 8080, 8000, 3000):
        pass  # ports are not inherently unsafe; kept for documentation
    return findings


def _path_findings(value: str, path: str) -> list:
    findings = []
    normalised = value.replace("\\", "/")
    decoded = unquote(normalised)
    if TRAVERSAL_RE.search(normalised) or TRAVERSAL_RE.search(decoded) or URLENCODED_TRAVERSAL_RE.search(value):
        findings.append(Finding("ARG-PATH-TRAVERSAL", "high", "path traversal sequence escapes the working directory", path, {"value": value[:200]}))
    if SENSITIVE_PATH_RE.search(normalised) or SENSITIVE_PATH_RE.search(decoded):
        findings.append(
            Finding("ARG-ABS-SENSITIVE-PATH", "high", "sensitive absolute path (credentials, system or autostart location)", path, {"value": value[:200]})
        )
    return findings


def _shell_findings(value: str, path: str) -> list:
    findings = []
    if CONTROL_CHAR_RE.search(value):
        findings.append(Finding("ARG-CONTROL-CHARS", "high", "argument contains NUL/control characters", path, {"value": value[:120]}))
    if "\n" in value or "\r" in value:
        findings.append(Finding("ARG-NEWLINE", "high", "command argument contains a newline (second command on the next line)", path, {"value": value[:120]}))
    unquoted = _unquoted(value)
    if BACKTICK_RE.search(unquoted):
        findings.append(Finding("ARG-COMMAND-SUBST", "high", "unquoted command substitution (` or $()) in a shell argument", path, {"value": value[:200]}))
    if CHAIN_RE.search(unquoted):
        findings.append(Finding("ARG-COMMAND-CHAIN", "high", "unquoted command chaining (; && ||) in a shell argument", path, {"value": value[:200]}))
    if REDIRECT_RE.search(unquoted):
        findings.append(Finding("ARG-REDIRECT", "medium", "unquoted shell redirection (< > >>) in an argument", path, {"value": value[:200]}))
    if ENV_EXPANSION_RE.search(unquoted):
        findings.append(Finding("ARG-ENV-EXPANSION", "low", "argument expands environment variables", path, {"value": value[:200]}))
    if not findings and SHELL_META_RE.search(unquoted):
        findings.append(Finding("ARG-SHELL-METACHAR", "medium", "unquoted shell metacharacter in an argument", path, {"value": value[:200]}))
    return findings


def _is_shell_context(tool: str, path: str) -> bool:
    if SHELL_TOOL_RE.search(tool or ""):
        return True
    leaf = path.rsplit(".", 1)[-1]
    leaf = re.sub(r"\[\d+\]$", "", leaf).lower()
    return leaf in COMMAND_KEYS


def scan_call(call, schema=None, limits: Limits = None) -> list:
    """Return findings for one tool call; ``schema`` validates the arguments shape."""
    limits = limits or Limits()
    findings = []
    tool = str(call.get("tool") or call.get("name") or "")
    arguments = call.get("arguments", call.get("args", {}))
    try:
        serialised = json.dumps(arguments, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        serialised = ""
    if len(serialised.encode("utf-8")) > limits.max_call_bytes:
        findings.append(
            Finding(
                "ARG-OVERSIZED-CALL",
                "medium",
                "serialized arguments exceed %d bytes" % limits.max_call_bytes,
                "arguments",
                {"bytes": len(serialised.encode("utf-8"))},
            )
        )
    if schema is not None:
        for path, message, code in _schema_errors(arguments, schema, "arguments"):
            findings.append(Finding(code, "medium", message, path, {}))
    for path, value in _walk_strings(arguments, "arguments"):
        if len(value) > limits.max_arg_len:
            findings.append(
                Finding(
                    "ARG-OVERSIZED",
                    "medium",
                    "argument is %d characters (limit %d)" % (len(value), limits.max_arg_len),
                    path,
                    {"length": len(value)},
                )
            )
        if CONTROL_CHAR_RE.search(value):
            findings.append(Finding("ARG-CONTROL-CHARS", "high", "argument contains NUL/control characters", path, {"value": value[:120]}))
        findings.extend(_path_findings(value, path))
        urls = []
        if _looks_like_url(value):
            urls.append(value.strip())
        urls.extend(match.group(0) for match in EMBEDDED_URL_RE.finditer(value))
        seen = set()
        for url in urls:
            if url in seen:
                continue
            seen.add(url)
            findings.extend(_url_findings(url, path))
        if _is_shell_context(tool, path):
            findings.extend(_shell_findings(value, path))
    return findings


def scan_payload(payload, schemas=None, limits: Limits = None) -> dict:
    """Validate every call in a parsed payload; returns a report dict."""
    calls = load_calls(payload)
    schemas = schemas or {}
    per_call = []
    counts = {severity: 0 for severity in SEVERITIES}
    for index, call in enumerate(calls):
        tool = str(call.get("tool") or call.get("name") or "")
        schema = schemas.get(tool) if isinstance(schemas, dict) else None
        findings = scan_call(call, schema=schema, limits=limits)
        for finding in findings:
            counts[finding.severity] += 1
        max_severity = "none"
        for severity in SEVERITIES:
            if any(finding.severity == severity for finding in findings):
                max_severity = severity
        per_call.append(
            {
                "index": index,
                "tool": tool,
                "findings": [finding.to_dict() for finding in findings],
                "total": len(findings),
                "max_severity": max_severity,
            }
        )
    max_severity = "none"
    for severity in SEVERITIES:
        if counts[severity]:
            max_severity = severity
    return {
        "tool": "toolarg-guard",
        "version": VERSION,
        "summary": {"calls": len(calls), "total": sum(counts.values()), "counts": counts, "max_severity": max_severity},
        "calls": per_call,
        "clean": sum(counts.values()) == 0,
    }


def normalise_schemas(payload) -> dict:
    """Accept either {tool: schema} or {"tools": [{"name": ..., "parameters": ...}]}."""
    if isinstance(payload, dict):
        if isinstance(payload.get("tools"), list):
            return {str(item.get("name") or item.get("tool")): item.get("parameters", item.get("schema", {})) for item in payload["tools"] if isinstance(item, dict)}
        return payload
    return {}


def summarize(findings) -> dict:
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        counts[finding.severity] += 1
    max_severity = "none"
    for severity in SEVERITIES:
        if counts[severity]:
            max_severity = severity
    return {"total": len(findings), "counts": counts, "max_severity": max_severity}
