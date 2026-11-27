"""CLI behaviour tests for toolarg-guard."""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import tempfile
import unittest

from toolarg_guard.cli import main

ROOT = pathlib.Path(__file__).resolve().parent.parent
DANGEROUS = str(ROOT / "examples" / "dangerous_call.json")
CLEAN = str(ROOT / "examples" / "clean_call.json")
BAD_SCHEMA = str(ROOT / "examples" / "bad_schema_call.json")
TOOLS = str(ROOT / "examples" / "tools.json")


def run(args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(args)
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def test_scan_json_reports_high_findings(self):
        code, out, _ = run(["scan", DANGEROUS, "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertGreaterEqual(payload["summary"]["counts"]["high"], 4)
        self.assertFalse(payload["clean"])

    def test_gate_blocks_dangerous(self):
        code, _, err = run(["scan", DANGEROUS, "--fail-on", "high"])
        self.assertEqual(code, 1)
        self.assertIn("FAIL", err)

    def test_clean_passes(self):
        code, _, _ = run(["scan", CLEAN, "--fail-on", "low"])
        self.assertEqual(code, 0)

    def test_schema_validation_flags_bad_call(self):
        code, out, _ = run(["scan", BAD_SCHEMA, "--tools", TOOLS, "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        codes = {finding["code"] for call in payload["calls"] for finding in call["findings"]}
        self.assertIn("TOOL-SCHEMA-TYPE", codes)
        self.assertIn("TOOL-SCHEMA-ENUM", codes)
        self.assertIn("TOOL-SCHEMA-REQUIRED", codes)

    def test_schema_gate_returns_1(self):
        code, _, _ = run(["scan", BAD_SCHEMA, "--tools", TOOLS, "--fail-on", "medium"])
        self.assertEqual(code, 1)

    def test_report_json_contains_fixes(self):
        code, out, _ = run(["report", DANGEROUS, "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertTrue(any(finding["fix"] for call in payload["calls"] for finding in call["findings"]))

    def test_missing_file_exits_2(self):
        code, _, err = run(["scan", "nope.json"])
        self.assertEqual(code, 2)
        self.assertIn("error", err)

    def test_invalid_json_exits_2(self):
        with tempfile.TemporaryDirectory() as directory:
            bad = pathlib.Path(directory) / "bad.json"
            bad.write_text("{not json", encoding="utf-8")
            code, _, err = run(["scan", str(bad)])
            self.assertEqual(code, 2)
            self.assertIn("invalid JSON", err)

    def test_max_arg_len_option(self):
        code, out, _ = run(["scan", CLEAN, "--json", "--max-arg-len", "5"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        codes = {finding["code"] for call in payload["calls"] for finding in call["findings"]}
        self.assertIn("ARG-OVERSIZED", codes)

    def test_stdin_input(self):
        import sys

        original = sys.stdin
        sys.stdin = io.StringIO(json.dumps({"tool": "shell.run", "arguments": {"command": "ls; id"}}))
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = main(["scan", "-", "--json"])
        finally:
            sys.stdin = original
        self.assertEqual(code, 0)
        self.assertGreaterEqual(json.loads(out.getvalue())["summary"]["counts"]["high"], 1)
