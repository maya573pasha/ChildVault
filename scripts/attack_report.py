#!/usr/bin/env python3
"""Run every attack test and print ONE combined results table for the report.

Usage (from the project root):
    python scripts/attack_report.py
    python scripts/attack_report.py --out docs/attack_results.md

Collects all three attack suites:
    tests/test_attack_files.py   file integrity   (Aaleen)
    tests/test_attack_log.py     audit log        (Mariyam)
    tests/attack/test_attack_*   share bundles    (Laiba)

Two ways a test can describe itself (both are read):
  * docstring   "<what the attacker does> -> <what detects it>"
  * marker      @pytest.mark.attack("<what the attacker does>", "<what must happen>")

Parametrized tests are grouped into one row ("7/7"). A test whose expected
outcome says "documented limit" records a known limit: it passes when the
limit behaves as documented, and is counted separately, never as "detected".
Tests named *control* (no attack, must succeed) are listed separately, not as attacks.
"""

import argparse
import sys
from collections import OrderedDict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))          # so `import childvault` works from any folder

import pytest  # noqa: E402

SUITES = OrderedDict([
    ("files",   ("File integrity", "Aaleen")),
    ("log",     ("Audit log", "Mariyam")),
    ("bundles", ("Share bundles", "Laiba")),
])


def suite_of(path: Path) -> str:
    if path.parent.name == "attack":
        return "bundles"
    if path.name == "test_attack_log.py":
        return "log"
    return "files"


class Collector:
    """Tiny pytest plugin: remember each test's outcome and description."""

    def __init__(self):
        self.rows = OrderedDict()      # (file, function name) -> dict
        self._key = {}                 # nodeid -> row key

    def pytest_collection_modifyitems(self, items):
        for item in items:
            fn = getattr(item, "function", None)
            name = item.originalname or item.name
            path = Path(str(item.fspath))
            key = (str(path), name)
            self._key[item.nodeid] = key

            marker = item.get_closest_marker("attack")
            if marker is not None and marker.args:
                attack = marker.args[0]
                detected = marker.args[1] if len(marker.args) > 1 else ""
            else:
                doc = (fn.__doc__ or "").strip().split("\n")[0] if fn else ""
                attack, _, detected = doc.partition(" -> ")
            is_attack = "control" not in name and (marker is not None or name.startswith("test_attack_"))
            self.rows.setdefault(key, {
                "name": name, "suite": suite_of(path), "is_attack": is_attack,
                "attack": attack.strip(), "detected": detected.strip(),
                "passed": 0, "total": 0,
            })["total"] += 1

    def pytest_runtest_logreport(self, report):
        if report.when == "call" and report.passed:
            self.rows[self._key[report.nodeid]]["passed"] += 1


def is_limit(row) -> bool:
    return "documented limit" in row["detected"].lower()


def build_table(rows) -> str:
    attacks = [r for r in rows.values() if r["is_attack"]]
    controls = [r for r in rows.values() if not r["is_attack"]]

    out = []
    n = 0
    totals = {"detected": 0, "variants": 0, "limits": 0, "types": 0}
    summary = []
    for suite, (title, owner) in SUITES.items():
        suite_rows = [r for r in attacks if r["suite"] == suite]
        if not suite_rows:
            continue
        out += [f"## {title} ({owner})", "",
                "| # | Attack | How it is detected | Variants | Result |",
                "|---|---|---|---|---|"]
        s_detected = s_variants = s_types = 0
        for r in suite_rows:
            n += 1
            ok = r["passed"] == r["total"]
            if is_limit(r):
                verdict = "Documented limit" if ok else "**LIMIT CHECK FAILED**"
                totals["limits"] += 1
            else:
                verdict = "Detected" if ok else "**NOT DETECTED**"
                s_detected += r["passed"]
                s_variants += r["total"]
                s_types += 1
            out.append(f"| {n} | {r['attack'] or r['name']} | {r['detected'] or '-'} | "
                       f"{r['passed']}/{r['total']} | {verdict} |")
        out.append("")
        summary.append((title, owner, s_types, s_detected, s_variants))
        totals["detected"] += s_detected
        totals["variants"] += s_variants
        totals["types"] += s_types

    head = ["## Summary", "",
            "| Suite | Owner | Attack types | Variants detected |",
            "|---|---|---|---|"]
    for title, owner, types, det, var in summary:
        head.append(f"| {title} | {owner} | {types} | {det}/{var} |")
    head.append(f"| **All** | | **{totals['types']}** | **{totals['detected']}/{totals['variants']}** |")
    head += ["",
             f"**{totals['detected']} of {totals['variants']} attack variants detected** "
             f"across {totals['types']} attack types."]
    if totals["limits"]:
        head.append(f"{totals['limits']} further test(s) document a known limit "
                    "(see the Limitations section of the README); they are not counted as detections.")
    if controls:
        head += ["", "Controls (no attack, must succeed): " +
                 ", ".join(f"`{r['name']}` {r['passed']}/{r['total']}" for r in controls)]
    head.append("")
    return "\n".join(head + out).rstrip() + "\n", totals


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", help="also write the table to this Markdown file")
    args = ap.parse_args()

    tests = ROOT / "tests"
    files = sorted(str(p) for p in tests.glob("test_attack_*.py"))
    files += sorted(str(p) for p in (tests / "attack").glob("test_attack_*.py"))

    collector = Collector()
    code = pytest.main(["-q", "--no-header", "-p", "no:cacheprovider", "--rootdir", str(ROOT), *files],
                       plugins=[collector])

    if not any(r["is_attack"] for r in collector.rows.values()):
        print("\nNo attack tests were collected - not writing a table.", file=sys.stderr)
        return 1
    table, totals = build_table(collector.rows)
    print("\n" + table)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            "# Attack results\n\n"
            "Generated by `python scripts/attack_report.py --out docs/attack_results.md`. "
            "Do not edit by hand.\n\n" + table,
            encoding="utf-8",
        )
        print(f"Written to {out}")
    return 0 if code == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
