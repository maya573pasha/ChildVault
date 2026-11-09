"""
demo.py - end-to-end ChildVault demo (Mariyam, Phase 6).

Runs the real CLI, step by step, in a throw-away vault, and checks that
every step does what it should (including attacks that MUST fail).

    python demo/demo.py            run straight through
    python demo/demo.py --pause    wait for Enter between sections (live presentation)
    python demo/demo.py --keep     keep the demo vault folder afterwards

Only synthetic names are used - never real child data.
Sections for teammates' features are added as their parts are finished.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PASSPHRASE = "demo vault passphrase"
REVIEWER_PASSPHRASE = "demo reviewer passphrase"
CHILDREN = ["Test Child Alpha", "Test Child Beta"]     # synthetic only


class Demo:
    def __init__(self, vault_dir: Path, pause: bool):
        self.vault_dir = vault_dir
        self.pause = pause
        self.env = {**os.environ, "CHILDVAULT_HOME": str(vault_dir)}
        self.checks_passed = 0
        self.checks_failed = 0

    # ------------------------------------------------------------ output helpers

    def section(self, title: str) -> None:
        if self.pause and self.checks_passed + self.checks_failed > 0:
            input("\n[press Enter to continue]")
        print("\n" + "=" * 70)
        print(title)
        print("=" * 70)

    def note(self, text: str) -> None:
        print(f"  # {text}")

    def check(self, ok: bool, what: str) -> None:
        if ok:
            self.checks_passed += 1
            print(f"  [OK]   {what}")
        else:
            self.checks_failed += 1
            print(f"  [FAIL] {what}")

    # ------------------------------------------------------------ running the CLI

    def cli(self, *args: str, expect_ok: bool = True, input_text: str | None = None) -> str:
        """Run `python -m childvault ...`, print it (secrets masked) and check the exit code."""
        shown = []
        hide_next = False
        for a in args:
            if hide_next:
                shown.append("****")
            else:
                shown.append(f'"{a}"' if " " in a else a)
            hide_next = a in ("--passphrase", "--name")
        print(f"\n$ childvault {' '.join(shown)}")

        result = subprocess.run(
            [sys.executable, "-m", "childvault", *args],
            cwd=REPO_ROOT, env=self.env, input=input_text,
            capture_output=True, text=True,
        )
        output = (result.stdout + result.stderr).strip()
        for line in output.splitlines():
            print(f"  {line}")

        ok = (result.returncode == 0) == expect_ok
        self.check(ok, "succeeded as expected" if expect_ok else "refused as expected")
        return output

    # ------------------------------------------------------------ the demo

    def run(self) -> None:
        pw = ["--passphrase", PASSPHRASE]
        map_path = self.vault_dir / "identity_map.enc"

        self.section("1. Create a vault (passphrase -> scrypt -> KEK)")
        self.cli("init", *pw)
        self.cli("status", *pw)

        self.section("2. A wrong passphrase is rejected")
        self.cli("status", "--passphrase", "not the right one", expect_ok=False)

        self.section("3. Pseudonymize children (random IDs, encrypted ID-name map)")
        ids = []
        for name in CHILDREN:
            out = self.cli("pseudonymize", "--name", name, *pw)
            m = re.search(r"CH-[0-9A-F]{4}", out)
            self.check(m is not None, "got a CH-XXXX pseudonym")
            ids.append(m.group(0) if m else "CH-0000")
        self.check(ids[0] != ids[1], "the two children have different pseudonyms")

        self.cli("lookup", ids[0], *pw)
        self.note("input is validated before anything else:")
        self.cli("lookup", "Ali Khan", *pw, expect_ok=False)

        self.section("4. No real name is stored in plaintext anywhere in the vault")
        leaks = [str(f.relative_to(self.vault_dir)) for f in self.vault_dir.rglob("*")
                 if f.is_file() and any(n.encode() in f.read_bytes() for n in CHILDREN)]
        self.note(f"vault files: {', '.join(sorted(p.name for p in self.vault_dir.rglob('*') if p.is_file()))}")
        self.check(not leaks, f"searched every file for the names - found in: {leaks or 'none'}")

        self.section("5. ATTACK: flip one bit of the encrypted ID-name map")
        original = map_path.read_bytes()
        tampered = bytearray(original)
        tampered[len(tampered) // 2] ^= 0x01
        map_path.write_bytes(bytes(tampered))
        self.note("one bit in the middle of identity_map.enc was flipped")
        out = self.cli("lookup", ids[0], *pw, expect_ok=False)
        self.check("integrity check" in out, "AES-GCM detected the modification")
        map_path.write_bytes(original)
        self.note("original map restored:")
        self.cli("lookup", ids[0], *pw)

        self.section("6. ATTACK: delete the ID-name map")
        backup = map_path.read_bytes()
        map_path.unlink()
        out = self.cli("pseudonymize", "--name", "Test Child Gamma", *pw, expect_ok=False)
        self.check("missing" in out, "deletion detected - vault does NOT silently start a new map")
        map_path.write_bytes(backup)

        self.section("7. Reviewer creates an X25519 key pair; owner checks the fingerprint")
        reviewer = self.vault_dir.parent / "demo_reviewer"
        out = self.cli("keygen", "--out", str(reviewer), "--passphrase", REVIEWER_PASSPHRASE)
        fp_keygen = re.search(r"([0-9a-f]{4}:){3}[0-9a-f]{4}", out)
        out = self.cli("fingerprint", str(reviewer) + ".pub")
        fp_owner = re.search(r"([0-9a-f]{4}:){3}[0-9a-f]{4}", out)
        self.check(bool(fp_keygen and fp_owner and fp_keygen.group(0) == fp_owner.group(0)),
                   "fingerprints match - the public key was not swapped")
        self.note("refusing to overwrite an existing private key:")
        self.cli("keygen", "--out", str(reviewer), "--passphrase", REVIEWER_PASSPHRASE, expect_ok=False)

        self.section("8. Web UI")
        self.note("start it with:  python -m childvault web   ->  http://127.0.0.1:8000")
        self.note("log in with the vault passphrase, then open Lookup")

        self.section("Still to come (teammates' parts)")
        for line in ("add-file / open-file + bit-flip, chunk-swap, truncation attacks  (Aaleen)",
                     "share / import-bundle: signed, expiring bundles                  (Aaleen + Mariyam)",
                     "verify / audit show + log edit, delete, reorder attacks           (Laiba + Mariyam)"):
            self.note(line)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ChildVault end-to-end demo")
    parser.add_argument("--pause", action="store_true", help="wait for Enter between sections")
    parser.add_argument("--keep", action="store_true", help="keep the demo folder afterwards")
    args = parser.parse_args(argv)

    work = Path(tempfile.mkdtemp(prefix="childvault_demo_"))
    vault_dir = work / "vault"
    demo = Demo(vault_dir, pause=args.pause)
    try:
        demo.run()
    finally:
        if args.keep:
            print(f"\nDemo files kept in {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)

    print("\n" + "=" * 70)
    print(f"RESULT: {demo.checks_passed} checks passed, {demo.checks_failed} failed")
    return 0 if demo.checks_failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
