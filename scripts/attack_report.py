#!/usr/bin/env python3
"""Run every attack test and print the results table for the report.

Usage (from the project root):
    python scripts/attack_report.py
    python scripts/attack_report.py --out docs/attack_results.md

Reads tests/test_attack_*.py. Each test's docstring is
"<what the attacker does> -> <what detects it>"; parametrized tests are
grouped, so one row can say "7/7 detected". Tests whose name does not start
with test_attack_ (e.g. the control) are shown separately, not as attacks.
"""

import argparse
import sys
from collections import OrderedDict
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))          # so `import childvault` works from any folder


class Collector:
    """Tiny pytest plugin: remember each test's outcome and docstring."""

    def __init__(self):
        self.rows = OrderedDict()      # function name -> dict

    def pytest_collection_modifyitems(self, items):
        for item in items:
            fn = getattr(item, "function", None)
            name = item.originalname or item.name
            self.rows.setdefault(name, {
                "doc": (fn.__doc__ or "").strip().split("\n")[0] if fn else "",
                "module": Path(str(item.fspath)).name,
                "passed": 0, "total": 0,
            })["total"] += 1

    def pytest_runtest_logreport(self, report):
        if report.when == "call" or (report.when == "setup" and report.failed):
            name = report.nodeid.split("::")[1].split("[")[0]
            row = self.rows[name]
            if report.passed:
                row["passed"] += 1


def split_doc(doc: str) -> tuple[str, str]:
    attack, _, detected = doc.partition(" -> ")
    return attack.strip(), detected.strip()


def build_table(rows) -> str:
    attacks = [(n, r) for n, r in rows.items() if n.startswith("test_attack_")]
    controls = [(n, r) for n, r in rows.items() if not n.startswith("test_attack_")]

    lines = [
        "| # | Attack | How it is detected | Variants | Result |",
        "|---|---|---|---|---|",
    ]
    for i, (name, r) in enumerate(attacks, 1):
        attack, detected = split_doc(r["doc"])
        ok = r["passed"] == r["total"]
        verdict = "Detected" if ok else "**NOT DETECTED**"
        lines.append(f"| {i} | {attack or name} | {detected or '-'} | "
                     f"{r['passed']}/{r['total']} | {verdict} |")

    total = sum(r["total"] for _, r in attacks)
    passed = sum(r["passed"] for _, r in attacks)
    lines += ["", f"**{passed} of {total} attack variants detected** "
                  f"({len(attacks)} attack types).", ""]
    if controls:
        lines.append("Controls (no attack, must succeed): " +
                     ", ".join(f"{n} {r['passed']}/{r['total']}" for n, r in controls))
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", help="also write the table to this Markdown file")
    args = ap.parse_args()

    collector = Collector()
    files = sorted(str(p) for p in (ROOT / "tests").glob("test_attack_*.py"))
    code = pytest.main(["-q", "--no-header", "-p", "no:cacheprovider", *files], plugins=[collector])

    if not any(n.startswith("test_attack_") for n in collector.rows):
        print("\nNo attack tests were collected - not writing a table.", file=sys.stderr)
        return 1
    table = build_table(collector.rows)
    print("\n" + table)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("# Attack results\n\n" + table + "\n", encoding="utf-8")
        print(f"\nWritten to {out}")
    return 0 if code == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
