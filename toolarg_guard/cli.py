"""Command line interface for toolarg-guard."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import Limits, SEVERITY_RANK, VERSION, normalise_schemas, scan_payload, summarize

TOOL = "toolarg-guard"


def _load_json(path: str):
    if path == "-":
        return json.load(sys.stdin)
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _print_json(payload) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=True))


def _print_report(path: str, report: dict) -> None:
    summary = report["summary"]
    print(
        "%s %s  scan  %s  (%d call(s))"
        % (TOOL, VERSION, path, summary["calls"])
    )
    for call in report["calls"]:
        print("call %d/%d  tool=%s  findings=%d  max_severity=%s" % (call["index"] + 1, summary["calls"], call["tool"] or "(missing)", call["total"], call["max_severity"]))
        for finding in call["findings"]:
            print(
                "  %-6s %-24s %-28s %s"
                % (finding["severity"].upper(), finding["code"], finding["path"], finding["message"])
            )
    print(
        "summary: %d finding(s): %d high, %d medium, %d low"
        % (summary["total"], summary["counts"]["high"], summary["counts"]["medium"], summary["counts"]["low"])
    )


def _gate(report: dict, fail_on: str) -> int:
    if not fail_on:
        return 0
    threshold = SEVERITY_RANK[fail_on]
    count = sum(
        1
        for call in report["calls"]
        for finding in call["findings"]
        if SEVERITY_RANK[finding["severity"]] >= threshold
    )
    if count:
        print("FAIL: %d finding(s) at or above severity %r" % (count, fail_on), file=sys.stderr)
        return 1
    print("PASS: no finding at or above severity %r" % fail_on)
    return 0


def _cmd_scan(args) -> int:
    payload = _load_json(args.path)
    schemas = normalise_schemas(_load_json(args.tools)) if args.tools else {}
    limits = Limits(max_arg_len=args.max_arg_len, max_call_bytes=args.max_call_bytes)
    report = scan_payload(payload, schemas=schemas, limits=limits)
    report["path"] = args.path
    if args.json:
        _print_json(report)
    else:
        _print_report(args.path, report)
    return _gate(report, args.fail_on)


def _cmd_report(args) -> int:
    payload = _load_json(args.path)
    schemas = normalise_schemas(_load_json(args.tools)) if args.tools else {}
    report = scan_payload(payload, schemas=schemas)
    if args.json:
        _print_json(report)
        return 0
    _print_report(args.path, report)
    fixes = []
    for call in report["calls"]:
        for finding in call["findings"]:
            if finding["fix"] and finding["fix"] not in fixes:
                fixes.append((finding["code"], finding["fix"]))
    if fixes:
        print("fix suggestions:")
        for code, fix in fixes:
            print("  %-26s %s" % (code, fix))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL,
        description="Validate model-generated tool-call arguments (stdlib-only).",
    )
    parser.add_argument("--version", action="version", version="%s %s" % (TOOL, VERSION))
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name, handler, help_text in (
        ("scan", _cmd_scan, "validate calls and print findings"),
        ("report", _cmd_report, "findings plus concrete fix suggestions"),
    ):
        sub = subparsers.add_parser(name, help=help_text)
        sub.add_argument("path", help="JSON file with one call, a list of calls, or {'calls': [...]}; - for stdin")
        sub.add_argument("--json", action="store_true", help="emit JSON")
        sub.add_argument("--tools", help="JSON file mapping tool name -> JSON Schema for the arguments")
        sub.add_argument("--fail-on", choices=["low", "medium", "high"], help="exit 1 when a finding at or above this severity exists")
        if name == "scan":
            sub.add_argument("--max-arg-len", type=int, default=4096)
            sub.add_argument("--max-call-bytes", type=int, default=65536)
        sub.set_defaults(func=handler)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print("error: file not found: %s" % exc, file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print("error: invalid JSON: %s" % exc, file=sys.stderr)
        return 2
    except OSError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    except ValueError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
