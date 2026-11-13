"""
attack_support.py - the scenario the attack tests run in (Laiba).

Kept in its own, uniquely named module (not conftest.py) so tests can import it
without clashing with tests/conftest.py. Everything uses synthetic data only.
"""
import json
import re
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path

from typer.testing import CliRunner

from cryptography.hazmat.primitives import serialization

from childvault import config
from childvault import keyshare as ks
from childvault.cli import app

OWNER_PW = "owner-passphrase-1"
KEY_PW_A = "reviewer-A-key-pass"
KEY_PW_B = "reviewer-B-key-pass"
FILE_ID_RE = re.compile(r"F-[0-9a-f]{16}")
FP_RE = re.compile(r"signing-key fingerprint: ([0-9a-f:]+)")
runner = CliRunner()


def cli(*args):
    return runner.invoke(app, [str(a) for a in args])


# ---------------------------------------------------------------- the scenario

@dataclass
class World:
    base: Path
    fid1: str = ""
    fid2: str = ""
    plain1: bytes = b""
    plain2: bytes = b""
    enc1: Path = None
    enc2: Path = None
    key: dict = field(default_factory=dict)       # "A"/"B" -> private key path
    pub: dict = field(default_factory=dict)       # "A"/"B" -> public key path
    pw: dict = field(default_factory=lambda: {"A": KEY_PW_A, "B": KEY_PW_B})
    bundle: Path = None                           # legitimate bundle: file 1, for reviewer A
    owner_fp: str = ""

    # ---- reviewer-side commands (no vault involved, exactly as a reviewer runs them)
    def import_bundle(self, bundle, who="A", pw=None, owner_fp=None):
        args = ["import-bundle", bundle, "--key", self.key[who],
                "--key-passphrase", pw or self.pw[who]]
        if owner_fp:
            args += ["--owner-fingerprint", owner_fp]
        return cli(*args)

    def open_shared(self, bundle, file_id, enc, out, who="A", pw=None, owner_fp=None):
        args = ["open-shared", bundle, file_id, enc, "--out", out, "--key", self.key[who],
                "--key-passphrase", pw or self.pw[who]]
        if owner_fp:
            args += ["--owner-fingerprint", owner_fp]
        return cli(*args)

    def mutated_bundle(self, name, mutate):
        data = json.loads(self.bundle.read_text(encoding="utf-8"))
        mutate(data)
        path = self.base / f"{name}.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def owner(self, *args):
        return cli(*args, "--passphrase", OWNER_PW)


def build_world(base: Path) -> World:
    """Create the whole scenario under `base`. The caller must have set CHILDVAULT_HOME."""
    base.mkdir(parents=True, exist_ok=True)
    w = World(base)
    assert cli("init", "--passphrase", OWNER_PW).exit_code == 0

    w.plain1, w.plain2 = b"SYNTHETIC FILE ONE " * 500, b"SYNTHETIC FILE TWO " * 500
    for n, data in ((1, w.plain1), (2, w.plain2)):
        src = base / f"plain{n}.bin"
        src.write_bytes(data)
        r = w.owner("add-file", src, "--type", "other")
        assert r.exit_code == 0, r.output
        setattr(w, f"fid{n}", FILE_ID_RE.search(r.output).group(0))

    transfer = base / "transfer"            # what the owner sends to the reviewer
    transfer.mkdir()
    for n in (1, 2):
        fid = getattr(w, f"fid{n}")
        dst = transfer / f"{fid}.enc"
        dst.write_bytes((config.get_files_dir() / f"{fid}.enc").read_bytes())
        setattr(w, f"enc{n}", dst)

    for who in ("A", "B"):
        out = base / f"rev{who}"
        assert cli("keygen", "--out", out, "--passphrase", w.pw[who]).exit_code == 0
        w.key[who], w.pub[who] = base / f"rev{who}.key", base / f"rev{who}.pub"

    w.bundle = base / "bundle_A.json"
    expires = (date.today() + timedelta(days=30)).isoformat()
    r = w.owner("share", w.fid1, "--reviewer-key", w.pub["A"], "--expires", expires, "--out", w.bundle)
    assert r.exit_code == 0, r.output
    w.owner_fp = FP_RE.search(r.output).group(1)
    return w




def refused(result, pattern):
    """The command failed (exit code 1) and said why (pattern matched case-insensitively)."""
    assert result.exit_code == 1, result.output
    assert re.search(pattern, result.output, re.I), result.output


def raw(pub):
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def retarget_to_reviewer_b(data, world):
    """Mutation: put reviewer B's fingerprint into a bundle made for reviewer A."""
    data["payload"]["reviewer_fp"] = ks.fingerprint(ks.load_public_key(world.pub["B"]))