"""
Attack family 1 - TAMPERED BUNDLE (Laiba, Phase 5).

The attacker edits the bundle file. The owner's Ed25519 signature must make every edit
fail, in BOTH reviewer commands, with nothing decrypted and no output file written.

Run with a results table:  $env:ATTACK_REPORT="attack_results.md"; python -m pytest tests/attack -q
"""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from attack_support import raw, refused, retarget_to_reviewer_b


def _extend_expiry(d, w):
    d["payload"]["expires"] = "2099-01-01T00:00:00+00:00"


def _add_second_file(d, w):
    d["payload"]["files"][w.fid2] = d["payload"]["files"][w.fid1]


def _bump_key_version(d, w):
    d["payload"]["files"][w.fid1]["key_version"] = 99


def _swap_owner_key(d, w):
    d["payload"]["owner_pub"] = raw(Ed25519PrivateKey.generate().public_key()).hex()


def _flip_signature(d, w):
    s = d["signature"]
    d["signature"] = ("0" if s[0] != "0" else "1") + s[1:]


def _empty_signature(d, w):
    d["signature"] = ""


def _remove_files(d, w):
    d["payload"]["files"] = {}


def _extra_field(d, w):
    d["payload"]["admin"] = True


MUTATIONS = {
    "extend the expiry date":            (_extend_expiry, "signature"),
    "add a second file to the scope":    (_add_second_file, "signature"),
    "change a key version":              (_bump_key_version, "signature"),
    "put own fingerprint as reviewer":   (retarget_to_reviewer_b, "signature"),
    "swap in the attacker's owner key":  (_swap_owner_key, "signature"),
    "flip one signature byte":           (_flip_signature, "signature"),
    "empty signature":                   (_empty_signature, "signature|malformed"),
    "empty the file list":               (_remove_files, "signature"),
    "add an unexpected field":           (_extra_field, "unexpected fields"),
}


@pytest.mark.attack("Tampered bundle: edit the signed content", "Refused by import-bundle AND open-shared; nothing decrypted")
@pytest.mark.parametrize("name", MUTATIONS)
def test_tampered_bundle_is_refused(world, tmp_path, name):
    mutate, pattern = MUTATIONS[name]
    path = world.mutated_bundle("tampered", lambda d: mutate(d, world))
    refused(world.import_bundle(path), pattern)
    out = tmp_path / "plain"
    refused(world.open_shared(path, world.fid1, world.enc1, out), pattern)
    assert not out.exists()


@pytest.mark.attack("Tampered bundle: not even valid JSON", "Refused: cannot read bundle")
def test_garbage_bundle_is_refused(world, tmp_path):
    path = tmp_path / "junk.json"
    path.write_bytes(b"\x00not json at all")
    refused(world.import_bundle(path), "cannot read bundle")


@pytest.mark.attack("Tampered bundle: truncated file", "Refused: cannot read bundle")
def test_truncated_bundle_is_refused(world, tmp_path):
    path = tmp_path / "cut.json"
    path.write_text(world.bundle.read_text(encoding="utf-8")[:200], encoding="utf-8")
    refused(world.import_bundle(path), "cannot read bundle")


@pytest.mark.attack("Tampered bundle: file does not exist", "Refused: cannot read bundle")
def test_missing_bundle_is_refused(world, tmp_path):
    refused(world.import_bundle(tmp_path / "nope.json"), "cannot read bundle")


@pytest.mark.attack("Tampered bundle: control - the untouched bundle", "Accepted (proves the refusals above are not false alarms)")
def test_control_untouched_bundle_works(world, tmp_path):
    r = world.import_bundle(world.bundle, owner_fp=world.owner_fp)
    assert r.exit_code == 0 and "Bundle is valid" in r.output and world.fid1 in r.output
    out = tmp_path / "plain"
    r = world.open_shared(world.bundle, world.fid1, world.enc1, out, owner_fp=world.owner_fp)
    assert r.exit_code == 0 and out.read_bytes() == world.plain1