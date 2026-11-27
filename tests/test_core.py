"""Unit tests for the toolarg_guard core."""

from __future__ import annotations

import unittest

from toolarg_guard import Finding, Limits, load_calls, normalise_schemas, scan_call, scan_payload, summarize


def codes(text_or_findings):
    if isinstance(text_or_findings, str):
        return [finding.code for finding in scan_call({"tool": "shell.run", "arguments": {"command": text_or_findings}})]
    return [finding.code for finding in text_or_findings]


class ShellRuleTests(unittest.TestCase):
    def test_command_chaining_is_high(self):
        findings = scan_call({"tool": "shell.run", "arguments": {"command": "ls; rm -rf /data"}})
        self.assertIn("ARG-COMMAND-CHAIN", codes(findings))
        self.assertEqual([finding.severity for finding in findings if finding.code == "ARG-COMMAND-CHAIN"], ["high"])

    def test_command_substitution_is_high(self):
        findings = scan_call({"tool": "shell.run", "arguments": {"command": "echo $(cat /etc/passwd)"}})
        self.assertIn("ARG-COMMAND-SUBST", codes(findings))

    def test_newline_is_high(self):
        findings = scan_call({"tool": "shell.run", "arguments": {"command": "echo hi\nwhoami"}})
        self.assertIn("ARG-NEWLINE", codes(findings))

    def test_redirection_is_medium(self):
        findings = scan_call({"tool": "shell.run", "arguments": {"command": "echo pwn > /etc/cron.d/x"}})
        self.assertIn("ARG-REDIRECT", codes(findings))

    def test_quoted_semicolon_is_not_flagged(self):
        findings = scan_call({"tool": "shell.run", "arguments": {"command": "grep 'a;b' file.txt"}})
        self.assertEqual(findings, [])

    def test_non_command_tool_does_not_run_shell_rules(self):
        findings = scan_call({"tool": "translate.text", "arguments": {"text": "Use a semicolon; it is fine."}})
        self.assertEqual(findings, [])

    def test_control_characters_are_high(self):
        findings = scan_call({"tool": "file.write", "arguments": {"data": "ok\x00hidden"}})
        self.assertIn("ARG-CONTROL-CHARS", codes(findings))


class PathAndUrlTests(unittest.TestCase):
    def test_path_traversal_is_high(self):
        findings = scan_call({"tool": "file.read", "arguments": {"path": "../../etc/passwd"}})
        self.assertIn("ARG-PATH-TRAVERSAL", codes(findings))

    def test_windows_traversal_is_high(self):
        findings = scan_call({"tool": "file.read", "arguments": {"path": "..\\..\\boot.ini"}})
        self.assertIn("ARG-PATH-TRAVERSAL", codes(findings))

    def test_urlencoded_traversal_is_high(self):
        findings = scan_call({"tool": "file.read", "arguments": {"path": "%2e%2e%2fetc/passwd"}})
        self.assertIn("ARG-PATH-TRAVERSAL", codes(findings))

    def test_sensitive_absolute_path_is_high(self):
        findings = scan_call({"tool": "file.read", "arguments": {"path": "C:\\Windows\\System32\\config\\SAM"}})
        self.assertIn("ARG-ABS-SENSITIVE-PATH", codes(findings))

    def test_ssh_key_path_is_high(self):
        findings = scan_call({"tool": "file.read", "arguments": {"path": "~/.ssh/id_rsa"}})
        self.assertIn("ARG-ABS-SENSITIVE-PATH", codes(findings))

    def test_localhost_url_is_high(self):
        findings = scan_call({"tool": "http.fetch", "arguments": {"url": "http://127.0.0.1:8080/admin"}})
        self.assertIn("ARG-SSRF-LOOPBACK", codes(findings))

    def test_metadata_ip_is_high(self):
        findings = scan_call({"tool": "http.fetch", "arguments": {"url": "http://169.254.169.254/latest/meta-data/"}})
        self.assertIn("ARG-SSRF-METADATA", codes(findings))

    def test_private_ip_is_medium(self):
        findings = scan_call({"tool": "http.fetch", "arguments": {"url": "http://192.168.1.10/admin"}})
        self.assertIn("ARG-SSRF-PRIVATE", codes(findings))

    def test_file_scheme_is_high(self):
        findings = scan_call({"tool": "http.fetch", "arguments": {"url": "file:///etc/passwd"}})
        self.assertIn("ARG-URL-SCHEME", codes(findings))

    def test_embedded_url_in_shell_command_is_detected(self):
        findings = scan_call({"tool": "shell.run", "arguments": {"command": "curl http://169.254.169.254/latest/meta-data/"}})
        self.assertIn("ARG-SSRF-METADATA", codes(findings))

    def test_public_https_url_is_clean(self):
        findings = scan_call({"tool": "http.fetch", "arguments": {"url": "https://api.example.com/v1/status?limit=5"}})
        self.assertEqual(findings, [])

    def test_integer_ip_form_is_high(self):
        findings = scan_call({"tool": "http.fetch", "arguments": {"url": "http://2130706433/admin"}})
        self.assertIn("ARG-SSRF-OBFUSCATED", codes(findings))


class SchemaTests(unittest.TestCase):
    SCHEMA = {
        "type": "object",
        "required": ["city"],
        "properties": {
            "city": {"type": "string", "maxLength": 64},
            "units": {"type": "string", "enum": ["metric", "imperial"]},
            "days": {"type": "integer", "minimum": 1, "maximum": 14},
        },
        "additionalProperties": False,
    }

    def test_valid_call_has_no_schema_findings(self):
        findings = scan_call({"tool": "weather.get", "arguments": {"city": "Berlin", "units": "metric", "days": 3}}, schema=self.SCHEMA)
        self.assertEqual(findings, [])

    def test_missing_required_property(self):
        findings = scan_call({"tool": "weather.get", "arguments": {"units": "metric"}}, schema=self.SCHEMA)
        self.assertIn("TOOL-SCHEMA-REQUIRED", codes(findings))

    def test_wrong_type(self):
        findings = scan_call({"tool": "weather.get", "arguments": {"city": 7}}, schema=self.SCHEMA)
        self.assertIn("TOOL-SCHEMA-TYPE", codes(findings))

    def test_enum_violation(self):
        findings = scan_call({"tool": "weather.get", "arguments": {"city": "Berlin", "units": "kelvin"}}, schema=self.SCHEMA)
        self.assertIn("TOOL-SCHEMA-ENUM", codes(findings))

    def test_additional_property_rejected(self):
        findings = scan_call({"tool": "weather.get", "arguments": {"city": "Berlin", "debug": True}}, schema=self.SCHEMA)
        self.assertIn("TOOL-SCHEMA-PROPERTY", codes(findings))

    def test_numeric_range(self):
        findings = scan_call({"tool": "weather.get", "arguments": {"city": "Berlin", "days": 99}}, schema=self.SCHEMA)
        self.assertIn("TOOL-SCHEMA-RANGE", codes(findings))

    def test_pattern(self):
        findings = scan_call(
            {"tool": "lookup", "arguments": {"id": "not-a-number"}},
            schema={"type": "object", "properties": {"id": {"type": "string", "pattern": "^[0-9]+$"}}},
        )
        self.assertIn("TOOL-SCHEMA-PATTERN", codes(findings))


class SizeAndNormalisationTests(unittest.TestCase):
    def test_oversized_argument_is_medium(self):
        findings = scan_call({"tool": "translate.text", "arguments": {"text": "x" * 100}}, limits=Limits(max_arg_len=50))
        self.assertIn("ARG-OVERSIZED", codes(findings))
        self.assertEqual([finding.severity for finding in findings if finding.code == "ARG-OVERSIZED"], ["medium"])

    def test_load_calls_accepts_shape_variants(self):
        self.assertEqual(len(load_calls({"calls": [{"tool": "a"}, {"tool": "b"}]})), 2)
        self.assertEqual(len(load_calls({"tool": "a", "arguments": {}})), 1)
        self.assertEqual(len(load_calls([{"tool": "a"}])), 1)

    def test_normalise_schemas_accepts_both_shapes(self):
        flattened = normalise_schemas({"weather.get": {"type": "object"}})
        self.assertIn("weather.get", flattened)
        listed = normalise_schemas({"tools": [{"name": "weather.get", "parameters": {"type": "object"}}]})
        self.assertIn("weather.get", listed)

    def test_report_summary_counts(self):
        payload = {"calls": [{"tool": "shell.run", "arguments": {"command": "ls; id"}}, {"tool": "http.fetch", "arguments": {"url": "https://example.com"}}]}
        report = scan_payload(payload)
        self.assertEqual(report["summary"]["calls"], 2)
        self.assertGreaterEqual(report["summary"]["counts"]["high"], 1)
        self.assertFalse(report["clean"])
        self.assertEqual(report["calls"][1]["total"], 0)

    def test_finding_to_dict_has_fix(self):
        finding = scan_call({"tool": "shell.run", "arguments": {"command": "ls; id"}})[0]
        payload = finding.to_dict()
        self.assertIn("fix", payload)
        self.assertTrue(payload["fix"])

    def test_clean_call_from_examples(self):
        import json
        import pathlib

        root = pathlib.Path(__file__).resolve().parent.parent
        payload = json.loads((root / "examples" / "clean_call.json").read_text(encoding="utf-8"))
        report = scan_payload(payload)
        self.assertTrue(report["clean"], report)
