"""
Attack family 2 - EXPIRED BUNDLE (Laiba, Phase 5).

A bundle past its expiry is refused by the reviewer commands. One test uses the real
clock. One test documents an honest limit: expiry is enforced by the client software,
not by cryptography, so revoking the file is the real remedy.

Run with a results table:  $env:ATTACK_REPORT="attack_results.md"; python -m pytest tests/attack -q
"""
import json
import time
from datetime import datetime, timedelta, timezone

import pytest

from attack_support import OWNER_PW, refused
from childvault import db
from childvault import bundle as bnd
from childvault import keyshare as ks
from childvault import vault_crypto as vc


def _signed_bundle(world, expires, now, tmp_path):
    """A bundle the owner's REAL signing key signed, with a chosen (past) expiry."""
    conn = db.connect()
    try:
        kek = vc.unlock(OWNER_PW, db.load_header(conn))
        signing_key = bnd.get_or_create_signing_key(conn, kek)
        wrapped = ks.wrap_files_for_reviewer(conn, kek, [world.fid1], ks.load_public_key(world.pub["A"]))
    finally:
        conn.close()
    path = tmp_path / "expired.json"
    bnd.save_bundle(bnd.create_bundle(signing_key, ks.load_public_key(world.pub["A"]), wrapped, expires, now), path)
    return path


@pytest.mark.attack("Expired bundle: validly signed, expiry already passed", "Refused by import-bundle AND open-shared; nothing decrypted")
def test_expired_bundle_is_refused(world, tmp_path):
    now = datetime.now(timezone.utc)
    path = _signed_bundle(world, now - timedelta(hours=1), now - timedelta(hours=2), tmp_path)
    refused(world.import_bundle(path), "expired")
    out = tmp_path / "plain"
    refused(world.open_shared(path, world.fid1, world.enc1, out), "expired")
    assert not out.exists()


@pytest.mark.attack("Expired bundle: works now, then time runs out (real clock)", "Accepted before expiry, refused after")
def test_bundle_expires_in_real_time(world, tmp_path):
    expires = (datetime.now(timezone.utc) + timedelta(seconds=6)).isoformat(timespec="seconds")
    bundle = tmp_path / "short.json"
    r = world.owner("share", world.fid1, "--reviewer-key", world.pub["A"], "--expires", expires, "--out", bundle)
    assert r.exit_code == 0, r.output
    assert world.import_bundle(bundle).exit_code == 0           # still valid
    time.sleep(7)
    refused(world.import_bundle(bundle), "expired")
    out = tmp_path / "plain"
    refused(world.open_shared(bundle, world.fid1, world.enc1, out), "expired")
    assert not out.exists()


@pytest.mark.attack("Expired bundle: owner asks for an expiry in the past", "Refused by share: expiry must be in the future")
def test_owner_cannot_create_an_already_expired_bundle(world, tmp_path):
    r = world.owner("share", world.fid1, "--reviewer-key", world.pub["A"],
                    "--expires", "2020-01-01", "--out", tmp_path / "b.json")
    refused(r, "future")


@pytest.mark.attack("Expired bundle: dishonest client skips the expiry check", "Not prevented (documented limit): expiry is enforced by honest client software; revoke is the remedy")
def test_limit_expiry_is_not_cryptographic(world, tmp_path):
    now = datetime.now(timezone.utc)
    path = _signed_bundle(world, now - timedelta(hours=1), now - timedelta(hours=2), tmp_path)
    payload = json.loads(path.read_text(encoding="utf-8"))["payload"]
    priv = ks.load_private_key(world.key["A"], world.pw["A"])
    keys = ks.unwrap_files_for_reviewer(payload["files"], priv)        # what a patched client would do
    out = tmp_path / "plain"
    vc.decrypt_file(world.enc1, out, keys[world.fid1], world.fid1)
    assert out.read_bytes() == world.plain1