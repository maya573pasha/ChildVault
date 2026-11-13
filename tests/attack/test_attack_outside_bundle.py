"""
Attack family 4 - ACCESS OUTSIDE THE BUNDLE (Laiba, Phase 5).

The reviewer tries to reach files or keys the owner did not grant: other files, other
files' data under an allowed ID, bad IDs, forged bundles, and old bundles after revoke.
Two tests document honest limits (see the "Not prevented" rows in the results table).

Run with a results table:  $env:ATTACK_REPORT="attack_results.md"; python -m pytest tests/attack -q
"""
import os
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from attack_support import refused
from childvault import audit, config, db
from childvault import bundle as bnd
from childvault import keyshare as ks


@pytest.mark.attack("Outside the bundle: ask for a file that is not in it", "Refused: not in this bundle; nothing decrypted")
def test_file_not_in_bundle_is_refused(world, tmp_path):
    out = tmp_path / "plain"
    refused(world.open_shared(world.bundle, world.fid2, world.enc2, out), "not in this bundle")
    assert not out.exists()


@pytest.mark.attack("Outside the bundle: use another file's encrypted data under the allowed ID", "Refused: authentication failed; nothing decrypted")
def test_wrong_encrypted_file_for_allowed_id(world, tmp_path):
    out = tmp_path / "plain"
    refused(world.open_shared(world.bundle, world.fid1, world.enc2, out), "authentication")
    assert not out.exists()


@pytest.mark.attack("Outside the bundle: malformed or path-traversal file ID", "Refused: invalid file ID")
@pytest.mark.parametrize("bad_id", ["../../etc/passwd", "F-123", "f-0011223344556677", "F-0011223344556677/../x", "x"])
def test_bad_file_ids_are_refused(world, tmp_path, bad_id):
    out = tmp_path / "plain"
    refused(world.open_shared(world.bundle, bad_id, world.enc1, out), "invalid file id")
    assert not out.exists()


@pytest.mark.attack("Outside the bundle: overwrite an existing file via --out", "Refused: output already exists")
def test_existing_output_is_not_overwritten(world, tmp_path):
    out = tmp_path / "precious.txt"
    out.write_bytes(b"do not touch")
    refused(world.open_shared(world.bundle, world.fid1, world.enc1, out), "already exists")
    assert out.read_bytes() == b"do not touch"


def _forged_bundle(world, tmp_path, with_real_files):
    """Mallory signs a bundle with HER OWN key, granting file 2 to reviewer A."""
    mallory = Ed25519PrivateKey.generate()
    pub_a = ks.load_public_key(world.pub["A"])
    wrapped = {world.fid2: {"key_version": 1,
                            "wrapped": ks.wrap_for_reviewer(os.urandom(32), pub_a, world.fid2).hex()}}
    path = tmp_path / "forged.json"
    bnd.save_bundle(bnd.create_bundle(mallory, pub_a, wrapped,
                                      datetime.now(timezone.utc) + timedelta(days=30)), path)
    return path


@pytest.mark.attack("Outside the bundle: forged bundle signed by the attacker (owner fingerprint pinned)", "Refused: not the owner you trust")
def test_forged_bundle_with_pinned_owner_is_refused(world, tmp_path):
    path = _forged_bundle(world, tmp_path, False)
    refused(world.import_bundle(path, owner_fp=world.owner_fp), "not the owner you trust")
    out = tmp_path / "plain"
    refused(world.open_shared(path, world.fid2, world.enc2, out, owner_fp=world.owner_fp), "not the owner you trust")
    assert not out.exists()


@pytest.mark.attack("Outside the bundle: forged bundle, owner fingerprint NOT pinned", "Import accepted with a warning, but nothing decrypts (keys are random)")
def test_forged_bundle_without_pin_still_decrypts_nothing(world, tmp_path):
    path = _forged_bundle(world, tmp_path, False)
    r = world.import_bundle(path)
    assert r.exit_code == 0 and "NOT checked" in r.output          # the warning the reviewer must heed
    out = tmp_path / "plain"
    refused(world.open_shared(path, world.fid2, world.enc2, out), "authentication")
    assert not out.exists()


@pytest.mark.attack("Outside the bundle: replay an old bundle after the owner revokes the file", "Refused: old key cannot open the re-encrypted file")
def test_old_bundle_after_revoke_cannot_open_new_file(fresh_world, tmp_path):
    w = fresh_world
    r = w.owner("revoke", w.fid1)
    assert r.exit_code == 0, r.output
    new_enc = tmp_path / "new.enc"
    new_enc.write_bytes((config.get_files_dir() / f"{w.fid1}.enc").read_bytes())
    out = tmp_path / "plain"
    refused(w.open_shared(w.bundle, w.fid1, new_enc, out), "authentication")
    assert not out.exists()


@pytest.mark.attack("Outside the bundle: reviewer kept a copy of the file before revoke", "Not prevented (documented limit): an already-saved copy stays readable")
def test_limit_revoke_cannot_unread_a_saved_copy(fresh_world, tmp_path):
    w = fresh_world
    assert w.owner("revoke", w.fid1).exit_code == 0
    out = tmp_path / "plain"
    r = w.open_shared(w.bundle, w.fid1, w.enc1, out)               # enc1 = the copy saved BEFORE revoke
    assert r.exit_code == 0 and out.read_bytes() == w.plain1


@pytest.mark.attack("Reviewer-side attempts: rejected imports and opens", "Not logged (documented limit): they happen on the reviewer's machine, not in the owner's log")
def test_limit_reviewer_attempts_are_invisible_to_the_owner(world, tmp_path):
    def count():
        conn = db.connect()
        try:
            return len(audit.show(conn))
        finally:
            conn.close()

    before = count()
    world.import_bundle(world.bundle, who="B")
    world.open_shared(world.bundle, world.fid2, world.enc2, tmp_path / "x")
    assert count() == before
    assert world.owner("verify").exit_code == 0                    # and the owner's log is still intact