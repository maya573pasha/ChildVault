"""
demo.py - end-to-end ChildVault demo (Mariyam, Phase 6).

Runs the real CLI, step by step, in a throw-away vault, and checks that
every step does what it should (including attacks that MUST fail).

    python demo/demo.py            run straight through
    python demo/demo.py --pause    wait for Enter between sections (live presentation)
    python demo/demo.py --keep     keep the demo vault folder afterwards

Only synthetic names are used - never real child data.
Covers the whole system: identities, files, sharing, revocation, audit log.
"""

import argparse
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from datetime import date, timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PASSPHRASE = "demo vault passphrase"
REVIEWER_PASSPHRASE = "demo reviewer passphrase"
CHILDREN = ["Test Child Alpha", "Test Child Beta"]     # synthetic only
SECRET_OPTIONS = ("--passphrase", "--name", "--key-passphrase", "--user-passphrase")
FP_RE = r"([0-9a-f]{4}:){3}[0-9a-f]{4}"


class Demo:
    def __init__(self, vault_dir: Path, pause: bool):
        self.vault_dir = vault_dir
        self.work = vault_dir.parent
        self.pause = pause
        # Commands run INSIDE the demo folder (so paths on screen are short);
        # PYTHONPATH lets `python -m childvault` still find the package.
        self.env = {**os.environ, "CHILDVAULT_HOME": str(vault_dir),
                    "PYTHONPATH": os.pathsep.join(filter(None, [str(REPO_ROOT), os.environ.get("PYTHONPATH")]))}
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

    def rel(self, path) -> str:
        """Path as typed on screen: relative to the demo folder when possible."""
        try:
            return str(Path(path).relative_to(self.work))
        except ValueError:
            return str(path)

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
            hide_next = a in SECRET_OPTIONS
        print(f"\n$ childvault {' '.join(shown)}")

        result = subprocess.run(
            [sys.executable, "-m", "childvault", *args],
            cwd=self.work, env=self.env, input=input_text,
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
        db_path = self.vault_dir / "childvault.db"
        work = self.work

        # ---------------------------------------------------------------- setup
        self.section("1. Create a vault (passphrase -> scrypt -> KEK)")
        self.cli("init", *pw)
        self.cli("status", *pw)

        self.section("2. A wrong passphrase is rejected")
        self.cli("status", "--passphrase", "not the right one", expect_ok=False)

        # ---------------------------------------------------------------- identities
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

        # ---------------------------------------------------------------- files
        self.section("4. Encrypt research files into the vault (AES-256-GCM, one key per file)")
        src = {
            "observations.csv": "time,behaviour\n0.0,looks_at_toy\n1.5,points\n",
            "session.eaf": "<ANNOTATION_DOCUMENT><TIER TIER_ID=\"gaze\"/></ANNOTATION_DOCUMENT>\n",
        }
        fids = {}
        for fname, text in src.items():
            p = work / fname
            p.write_text(text)
            ftype = "csv" if fname.endswith(".csv") else "annotation"
            out = self.cli("add-file", self.rel(p), "--type", ftype, "--child", ids[0], *pw)
            m = re.search(r"F-[0-9a-f]{16}", out)
            self.check(m is not None, "got a random file ID")
            fids[fname] = m.group(0) if m else "F-0000000000000000"
        f1, f2 = fids["observations.csv"], fids["session.eaf"]
        enc1 = self.vault_dir / "files" / f"{f1}.enc"
        enc2 = self.vault_dir / "files" / f"{f2}.enc"
        back = work / "opened.csv"
        self.cli("open-file", f1, "--out", self.rel(back), *pw)
        self.check(back.read_text() == src["observations.csv"], "decrypted file is identical to the original")

        self.section("5. Nothing readable is stored in the vault")
        needles = [n.encode() for n in CHILDREN] + [b"looks_at_toy", b"TIER_ID"]
        vault_files = [f for f in self.vault_dir.rglob("*") if f.is_file()]
        leaks = [f.name for f in vault_files if any(s in f.read_bytes() for s in needles)]
        self.note("vault files: " + ", ".join(sorted(str(f.relative_to(self.vault_dir)) for f in vault_files)))
        self.check(not leaks, f"searched every file for names and file contents - found in: {leaks or 'none'}")

        # ---------------------------------------------------------------- attacks on stored data
        self.section("6. ATTACK: flip one bit of an encrypted file")
        original = enc1.read_bytes()
        tampered = bytearray(original)
        tampered[len(tampered) // 2] ^= 0x01
        enc1.write_bytes(bytes(tampered))
        out_bad = work / "should_not_exist.csv"
        self.cli("open-file", f1, "--out", self.rel(out_bad), *pw, expect_ok=False)
        self.check(not out_bad.exists(), "no (partial) plaintext was written")
        enc1.write_bytes(original)

        self.section("7. ATTACK: flip one bit of the encrypted ID-name map")
        original = map_path.read_bytes()
        tampered = bytearray(original)
        tampered[len(tampered) // 2] ^= 0x01
        map_path.write_bytes(bytes(tampered))
        out = self.cli("lookup", ids[0], *pw, expect_ok=False)
        self.check("integrity check" in out, "AES-GCM detected the modification")
        map_path.write_bytes(original)

        self.section("8. ATTACK: delete the ID-name map")
        map_path.unlink()
        out = self.cli("pseudonymize", "--name", "Test Child Gamma", *pw, expect_ok=False)
        self.check("missing" in out, "deletion detected - vault does NOT silently start a new map")
        map_path.write_bytes(original)

        # ---------------------------------------------------------------- sharing
        self.section("9. Reviewer creates an X25519 key pair; owner checks the fingerprint")
        reviewer = work / "reviewer"
        rkey = ["--key", self.rel(reviewer) + ".key", "--key-passphrase", REVIEWER_PASSPHRASE]
        out = self.cli("keygen", "--out", self.rel(reviewer), "--passphrase", REVIEWER_PASSPHRASE)
        fp_keygen = re.search(FP_RE, out)
        out = self.cli("fingerprint", self.rel(reviewer) + ".pub")
        fp_owner = re.search(FP_RE, out)
        self.check(bool(fp_keygen and fp_owner and fp_keygen.group(0) == fp_owner.group(0)),
                   "fingerprints match - the public key was not swapped")

        self.section("10. Share ONE file with the reviewer (scoped, signed, expiring)")
        expires = (date.today() + timedelta(days=7)).isoformat()
        bundle = work / "bundle.json"
        out = self.cli("share", f1, "--reviewer-key", self.rel(reviewer) + ".pub",
                       "--expires", expires, "--out", self.rel(bundle), *pw)
        m = re.search(r"signing-key fingerprint: (" + FP_RE + ")", out)
        owner_fp = m.group(1) if m else "missing"
        self.check(m is not None, "owner's signing-key fingerprint shown (the reviewer pins it)")
        pin = ["--owner-fingerprint", owner_fp]

        self.note("reviewer side - checks the Ed25519 signature, expiry and the pinned owner:")
        self.cli("import-bundle", self.rel(bundle), *rkey, *pin)
        shared_out = work / "reviewer_copy.csv"
        self.cli("open-shared", self.rel(bundle), f1, self.rel(enc1), "--out", self.rel(shared_out), *rkey, *pin)
        self.check(shared_out.read_text() == src["observations.csv"], "reviewer decrypted the shared file")
        self.note("the other file was NOT in the bundle:")
        self.cli("open-shared", self.rel(bundle), f2, self.rel(enc2), "--out", self.rel(work / "nope.eaf"),
                 *rkey, *pin, expect_ok=False)

        self.section("11. ATTACKS on the share bundle")
        good = bundle.read_text()
        data = json.loads(good)
        data["payload"]["expires"] = "2099-12-31T23:59:59+00:00"
        bundle.write_text(json.dumps(data))
        self.note("the reviewer edits the bundle to extend its expiry:")
        self.cli("import-bundle", self.rel(bundle), *rkey, *pin, expect_ok=False)
        bundle.write_text(good)

        other = work / "other_reviewer"
        self.cli("keygen", "--out", self.rel(other), "--passphrase", REVIEWER_PASSPHRASE)
        self.note("a different reviewer tries to use the bundle:")
        self.cli("import-bundle", self.rel(bundle), "--key", self.rel(other) + ".key",
                 "--key-passphrase", REVIEWER_PASSPHRASE, *pin, expect_ok=False)

        self.section("12. Revoke: re-encrypt the file under a new key")
        self.cli("revoke", f1, *pw)
        self.note("the reviewer's old bundle no longer opens the re-encrypted file:")
        self.cli("open-shared", self.rel(bundle), f1, self.rel(enc1), "--out", self.rel(work / "after_revoke.csv"),
                 *rkey, *pin, expect_ok=False)
        self.note("the owner still can:")
        self.cli("open-file", f1, "--out", self.rel(work / "owner_after_revoke.csv"), *pw)

        # ---------------------------------------------------------------- audit log
        self.section("13. Every action above is in the hash-chained audit log")
        self.cli("audit", "show", "--limit", "8", *pw)
        self.cli("verify", *pw)

        self.section("14. ATTACK: edit the audit log to hide that files were opened")
        saved_db = db_path.read_bytes()
        conn = sqlite3.connect(db_path, isolation_level=None)
        conn.execute("DROP TRIGGER IF EXISTS audit_log_no_update")
        n = conn.execute("UPDATE audit_log SET action = 'status' WHERE action = 'open_file'").rowcount
        conn.close()
        self.note(f"attacker dropped the append-only trigger and rewrote {n} 'open_file' entries as 'status'")
        out = self.cli("verify", *pw, expect_ok=False)
        self.check("TAMPERING" in out, "the hash chain detected the edit")
        db_path.write_bytes(saved_db)

        self.section("15. ATTACK: delete the newest log entries")
        conn = sqlite3.connect(db_path, isolation_level=None)
        conn.execute("DROP TRIGGER IF EXISTS audit_log_no_delete")
        conn.execute("DELETE FROM audit_log WHERE seq > (SELECT MAX(seq) - 3 FROM audit_log)")
        conn.close()
        out = self.cli("verify", *pw, expect_ok=False)
        self.check("were deleted" in out, "the HMAC-signed head detected the missing entries")
        db_path.write_bytes(saved_db)

        # ---------------------------------------------------------------- web
        self.section("16. Web UI")
        self.note("start it with:  python -m childvault web   ->  http://127.0.0.1:8000")
        self.note("log in with the vault passphrase: Files page and Lookup page")



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
