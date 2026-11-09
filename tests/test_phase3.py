"""Phase 3: signed share bundles, share / import-bundle / open-shared, revoke."""

import json
from datetime import datetime, timedelta, timezone

import pytest
from typer.testing import CliRunner

from childvault import bundle as bnd
from childvault import config, db
from childvault import keyshare as ks
from childvault.cli import app, unlock_vault

runner = CliRunner()
PW = "correct horse battery"
RPW = "reviewer passphrase"


@pytest.fixture(autouse=True)
def temp_vault(monkeypatch, tmp_path):
    monkeypatch.setenv(config.ENV_VAR, str(tmp_path / "vault"))
    return tmp_path / "vault"


# ---------------------------------------------------------------- helpers

def _add(path):
    r = runner.invoke(app, ["add-file", str(path), "--type", "video", "--passphrase", PW])
    assert r.exit_code == 0, r.output
    return r.output.split("Added ")[1].split()[0]


def _reviewer(tmp_path, name="rev"):
    base = tmp_path / name
    r = runner.invoke(app, ["keygen", "--out", str(base), "--passphrase", RPW])
    assert r.exit_code == 0, r.output
    return base


def _share(tmp_path, file_ids, reviewer, out="b.json", expires="2999-01-01"):
    return runner.invoke(app, ["share", *file_ids, "--reviewer-key", f"{reviewer}.pub",
                               "--expires", expires, "--out", str(tmp_path / out),
                               "--passphrase", PW])


def _owner_fp(result):
    return result.output.split("fingerprint: ")[1].split()[0]


def _setup(tmp_path, data=b"secret clip"):
    assert runner.invoke(app, ["init", "--passphrase", PW]).exit_code == 0
    src = tmp_path / "a.mp4"
    src.write_bytes(data)
    fid = _add(src)
    rev = _reviewer(tmp_path)
    shared = _share(tmp_path, [fid], rev)
    assert shared.exit_code == 0, shared.output
    return fid, rev, _owner_fp(shared)


def _open_shared(tmp_path, fid, rev, fp, bundle="b.json", enc=None, pw=RPW):
    enc = enc or (tmp_path / "vault" / "files" / f"{fid}.enc")
    args = ["open-shared", str(tmp_path / bundle), fid, str(enc), "--out", str(tmp_path / "o.mp4"),
            "--key", f"{rev}.key", "--key-passphrase", pw]
    if fp:
        args += ["--owner-fingerprint", fp]
    return runner.invoke(app, args)


# ---------------------------------------------------------------- share -> reviewer

def test_share_then_reviewer_opens_file(tmp_path):
    fid, rev, fp = _setup(tmp_path)
    result = _open_shared(tmp_path, fid, rev, fp)
    assert result.exit_code == 0, result.output
    assert (tmp_path / "o.mp4").read_bytes() == b"secret clip"


def test_import_bundle_lists_files_and_warns_without_pin(tmp_path):
    fid, rev, fp = _setup(tmp_path)
    base = ["import-bundle", str(tmp_path / "b.json"), "--key", f"{rev}.key", "--key-passphrase", RPW]
    ok = runner.invoke(app, base + ["--owner-fingerprint", fp])
    assert ok.exit_code == 0 and fid in ok.output and "Warning" not in ok.output
    unpinned = runner.invoke(app, base)
    assert unpinned.exit_code == 0 and "NOT checked" in unpinned.output


def test_share_is_scoped_to_chosen_files(tmp_path):
    assert runner.invoke(app, ["init", "--passphrase", PW]).exit_code == 0
    a, b = tmp_path / "a.bin", tmp_path / "b.bin"
    a.write_bytes(b"one")
    b.write_bytes(b"two")
    fa, fb = _add(a), _add(b)
    rev = _reviewer(tmp_path)
    r = _share(tmp_path, [fa], rev)
    fp = _owner_fp(r)
    assert _open_shared(tmp_path, fb, rev, fp, enc=tmp_path / "vault" / "files" / f"{fb}.enc").exit_code == 1


def test_share_input_errors(tmp_path):
    assert runner.invoke(app, ["init", "--passphrase", PW]).exit_code == 0
    rev = _reviewer(tmp_path)
    assert _share(tmp_path, ["F-ffffffffffffffff"], rev).exit_code == 1           # unknown file
    assert _share(tmp_path, ["F-ffffffffffffffff"], rev, expires="soon").exit_code == 1
    assert _share(tmp_path, ["F-ffffffffffffffff"], rev, expires="2000-01-01").exit_code == 1
    assert _share(tmp_path, ["../x"], rev).exit_code == 1
    assert not (tmp_path / "b.json").exists()


def test_signing_key_is_stable_across_shares(tmp_path):
    fid, rev, fp = _setup(tmp_path)
    assert _owner_fp(_share(tmp_path, [fid], rev, out="b2.json")) == fp


# ---------------------------------------------------------------- attacks on the bundle

def test_expired_bundle_refused(tmp_path):
    fid, rev, fp = _setup(tmp_path)
    pub = ks.load_public_key(f"{rev}.pub")
    conn, kek = unlock_vault(PW)
    try:
        sk = bnd.get_or_create_signing_key(conn, kek)
        wrapped = ks.wrap_files_for_reviewer(conn, kek, [fid], pub)
    finally:
        conn.close()
    then = datetime.now(timezone.utc) - timedelta(days=2)
    old = bnd.create_bundle(sk, pub, wrapped, then + timedelta(days=1), now=then)
    bnd.save_bundle(old, tmp_path / "old.json")
    result = _open_shared(tmp_path, fid, rev, fp, bundle="old.json")
    assert result.exit_code == 1 and "expired" in result.output
    assert not (tmp_path / "o.mp4").exists()


def test_tampered_bundle_refused(tmp_path):
    fid, rev, fp = _setup(tmp_path)
    path = tmp_path / "b.json"
    b = json.loads(path.read_text())
    b["payload"]["expires"] = "2999-12-31T00:00:00+00:00"       # try to extend access
    path.write_text(json.dumps(b))
    result = _open_shared(tmp_path, fid, rev, fp)
    assert result.exit_code == 1 and "signature" in result.output
    assert not (tmp_path / "o.mp4").exists()


def test_bundle_for_other_reviewer_refused(tmp_path):
    fid, rev, fp = _setup(tmp_path)
    other = _reviewer(tmp_path, "other")
    result = _open_shared(tmp_path, fid, other, fp)
    assert result.exit_code == 1 and "different reviewer" in result.output


def test_wrong_pinned_signer_refused(tmp_path):
    fid, rev, fp = _setup(tmp_path)
    result = _open_shared(tmp_path, fid, rev, "0000:0000:0000:0000")
    assert result.exit_code == 1 and "not the owner you trust" in result.output


def test_forged_bundle_with_attacker_key_refused(tmp_path):
    fid, rev, fp = _setup(tmp_path)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    pub = ks.load_public_key(f"{rev}.pub")
    conn, kek = unlock_vault(PW)
    try:
        wrapped = ks.wrap_files_for_reviewer(conn, kek, [fid], pub)
    finally:
        conn.close()
    forged = bnd.create_bundle(Ed25519PrivateKey.generate(), pub, wrapped,
                               datetime.now(timezone.utc) + timedelta(days=1))
    bnd.save_bundle(forged, tmp_path / "forged.json")
    result = _open_shared(tmp_path, fid, rev, fp, bundle="forged.json")
    assert result.exit_code == 1 and "not the owner you trust" in result.output


@pytest.mark.parametrize("mutate", [
    lambda b: b.pop("signature"),
    lambda b: b["payload"].update(extra="x"),
    lambda b: b.update(signature="zz"),
    lambda b: b.update(payload="not a dict"),
])
def test_malformed_bundle_refused(tmp_path, mutate):
    fid, rev, fp = _setup(tmp_path)
    path = tmp_path / "b.json"
    b = json.loads(path.read_text())
    mutate(b)
    path.write_text(json.dumps(b))
    assert _open_shared(tmp_path, fid, rev, fp).exit_code == 1


def test_file_not_in_bundle_and_wrong_key_passphrase(tmp_path):
    fid, rev, fp = _setup(tmp_path)
    assert _open_shared(tmp_path, "F-ffffffffffffffff", rev, fp, enc=tmp_path / "a.mp4").exit_code == 1
    assert _open_shared(tmp_path, fid, rev, fp, pw="wrong passphrase").exit_code == 1


def test_tampered_encrypted_file_refused_by_reviewer(tmp_path, temp_vault):
    fid, rev, fp = _setup(tmp_path, data=b"x" * 5000)
    enc = temp_vault / "files" / f"{fid}.enc"
    blob = bytearray(enc.read_bytes())
    blob[100] ^= 1
    enc.write_bytes(bytes(blob))
    assert _open_shared(tmp_path, fid, rev, fp).exit_code == 1
    assert not (tmp_path / "o.mp4").exists()


# ---------------------------------------------------------------- signing key storage

def test_tampered_signing_key_detected(tmp_path):
    _setup(tmp_path)
    conn, kek = unlock_vault(PW)
    try:
        with conn:
            conn.execute("UPDATE vault_meta SET value = ? WHERE key = 'owner_signing_pub'", ("00" * 32,))
        with pytest.raises(bnd.BundleError):
            bnd.get_or_create_signing_key(conn, kek)
    finally:
        conn.close()


def test_signing_key_seed_not_stored_in_plaintext(tmp_path, temp_vault):
    _setup(tmp_path)
    conn, kek = unlock_vault(PW)
    try:
        seed = bnd.get_or_create_signing_key(conn, kek).private_bytes_raw()
    finally:
        conn.close()
    for f in temp_vault.rglob("*"):
        if f.is_file():
            assert seed not in f.read_bytes() and seed.hex().encode() not in f.read_bytes()


def test_parse_expiry():
    assert bnd.parse_expiry("2030-05-01") == datetime(2030, 5, 1, 23, 59, 59, tzinfo=timezone.utc)
    assert bnd.parse_expiry("2030-05-01T09:00:00").tzinfo is not None
    with pytest.raises(bnd.BundleError):
        bnd.parse_expiry("tomorrow")


# ---------------------------------------------------------------- revoke

def test_revoke_rotates_key_and_old_bundle_stops_working(tmp_path, temp_vault):
    data = b"keep me" * 1000
    fid, rev, fp = _setup(tmp_path, data=data)
    enc = temp_vault / "files" / f"{fid}.enc"
    before = enc.read_bytes()
    result = runner.invoke(app, ["revoke", fid, "--passphrase", PW])
    assert result.exit_code == 0 and "key version 2" in result.output
    assert enc.read_bytes() != before
    assert not list((temp_vault / "files").glob(".revoke-*"))
    assert not list((temp_vault / "files").glob("*.new"))

    out = tmp_path / "owner.bin"                    # the owner still reads it
    r = runner.invoke(app, ["open-file", fid, "--out", str(out), "--passphrase", PW])
    assert r.exit_code == 0 and out.read_bytes() == data
    result = _open_shared(tmp_path, fid, rev, fp)   # the old bundle's key no longer fits
    assert result.exit_code == 1 and not (tmp_path / "o.mp4").exists()


def test_revoke_refuses_tampered_file_and_changes_nothing(tmp_path, temp_vault):
    fid, rev, fp = _setup(tmp_path, data=b"x" * 5000)
    enc = temp_vault / "files" / f"{fid}.enc"
    blob = bytearray(enc.read_bytes())
    blob[100] ^= 1
    enc.write_bytes(bytes(blob))
    assert runner.invoke(app, ["revoke", fid, "--passphrase", PW]).exit_code == 1
    assert enc.read_bytes() == bytes(blob)
    conn = db.connect()
    try:
        assert db.get_file(conn, fid)["key_version"] == 1
    finally:
        conn.close()
    assert not list((temp_vault / "files").glob(".revoke-*"))


def test_revoke_bad_and_unknown_ids(tmp_path):
    assert runner.invoke(app, ["init", "--passphrase", PW]).exit_code == 0
    assert runner.invoke(app, ["revoke", "../x", "--passphrase", PW]).exit_code == 1
    assert runner.invoke(app, ["revoke", "F-ffffffffffffffff", "--passphrase", PW]).exit_code == 1
