"""Fail if the toolarg_guard core imports anything outside the Python standard library.

The core promise of this project is "stdlib-only core": the package must be
usable in a locked-down CI runner or air-gapped pipeline with no third-party
packages. This checker is run by CI and can be run locally:

    python scripts/check_core_deps.py
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "toolarg_guard"


def main() -> int:
    stdlib = set(sys.stdlib_module_names)
    failures: list[str] = []
    for path in sorted(PACKAGE.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    if top not in stdlib:
                        failures.append("%s:%d imports %r" % (path.name, node.lineno, alias.name))
            elif isinstance(node, ast.ImportFrom):
                if node.level and node.level > 0:
                    continue
                top = (node.module or "").split(".")[0]
                if top and top not in stdlib:
                    failures.append("%s:%d imports from %r" % (path.name, node.lineno, node.module))
    if failures:
        print("third-party imports found in the stdlib-only core:")
        for failure in failures:
            print("  " + failure)
        return 1
    print("OK: toolarg_guard core imports only the Python standard library")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
