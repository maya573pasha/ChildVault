"""
Phase 5 attack suite - file integrity (Aaleen).

Every test is an attack on stored data. Each one MUST be detected: the
operation fails loudly, says why, and no plaintext output is produced.

Docstring convention (read by scripts/attack_report.py for the results table):
    "<what the attacker does> -> <what detects it>"

Layers:
  1. crypto   - real 1 MiB chunks on Laiba's synthetic files (vault_crypto)
  2. keys     - attacks on wrapped keys and key versions
  3. end-to-end - the same tampering seen through the CLI, the web page,
     revoke, and the reviewer's open-shared
"""

import json
import os
import shutil

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from childvault import config, db, ops
from childvault import keyshare as ks
from childvault import vault_crypto as vc
from childvault.cli import app as cli_app
from childvault.web import auth
from childvault.web.app import create_app

FID = "F-0123456789abcdef"
HL = vc.HEADER_LEN
REC = vc.NONCE_LEN + vc.CHUNK_SIZE + vc.TAG_LEN          # one full encrypted 1 MiB record
FAST = {"n": 2 ** 10, "r": 8, "p": 1}
PW = "attack suite passphrase"
RPW = "reviewer passphrase"
runner = CliRunner()

# Files that exercise different chunk shapes (see scripts/generate_synthetic.py).
ANY_FILE = ["big_random.bin", "exact_chunk.bin", "observations.csv", "session_1.eaf"]


# ---------------------------------------------------------------- helpers

def encrypt(src, tmp_path, file_id=FID):
    enc = tmp_path / "x.enc"
    key = vc.generate_data_key()
    vc.encrypt_file(src, enc, key, file_id)
    return key, enc


def split(blob):
    body = blob[HL:]
    return blob[:HL], [body[i:i + REC] for i in range(0, len(body), REC)]


def join(header, records):
    return header + b"".join(records)


def assert_detected(tmp_path, enc, key, file_id=FID):
    """Decrypting must raise IntegrityError and leave no output (not even a .part)."""
    out = tmp_path / "out.bin"
    with pytest.raises(vc.IntegrityError):
        vc.decrypt_file(enc, out, key, file_id)
    assert not out.exists()
    assert not (tmp_path / "out.bin.part").exists()


# ================================================================ 1. crypto layer

def test_control_untouched_files_decrypt(sample_files, tmp_path):
    """Control (no attack) -> every synthetic file round-trips, so detections below are real."""
    for name in ANY_FILE + ["empty.bin"]:
        key, enc = encrypt(sample_files[name], tmp_path)
        out = tmp_path / f"{name}.out"
        vc.decrypt_file(enc, out, key, FID)
        assert out.read_bytes() == sample_files[name].read_bytes()


@pytest.mark.parametrize("name", ANY_FILE)
@pytest.mark.parametrize("where", ["magic", "version", "chunk_size", "nonce", "ciphertext", "tag", "last_byte"])
def test_attack_bit_flip(sample_files, tmp_path, name, where):
    """Flip one bit of the encrypted file (header, nonce, data or tag) -> AES-GCM tag / header check fails."""
    key, enc = encrypt(sample_files[name], tmp_path)
    blob = bytearray(enc.read_bytes())
    pos = {
        "magic": 0, "version": 4, "chunk_size": 6,
        "nonce": HL, "ciphertext": HL + vc.NONCE_LEN,
        "tag": min(len(blob), HL + REC) - 1, "last_byte": len(blob) - 1,
    }[where]
    blob[pos] ^= 0x01
    enc.write_bytes(bytes(blob))
    assert_detected(tmp_path, enc, key)


def test_attack_bit_flip_every_chunk(sample_files, tmp_path):
    """Flip a bit in the middle of each of the 4 chunks in turn -> that chunk's GCM tag fails."""
    key, enc = encrypt(sample_files["big_random.bin"], tmp_path)
    original = enc.read_bytes()
    for i in range(4):
        blob = bytearray(original)
        blob[HL + i * REC + 100] ^= 0x80
        enc.write_bytes(bytes(blob))
        assert_detected(tmp_path, enc, key)


def test_attack_chunk_swap(sample_files, tmp_path):
    """Swap two chunks of a 4-chunk file -> chunk number in the AAD no longer matches."""
    key, enc = encrypt(sample_files["big_random.bin"], tmp_path)
    header, recs = split(enc.read_bytes())
    assert len(recs) == 4
    recs[0], recs[2] = recs[2], recs[0]
    enc.write_bytes(join(header, recs))
    assert_detected(tmp_path, enc, key)


def test_attack_chunk_reorder_whole_file(sample_files, tmp_path):
    """Reverse the chunk order -> chunk number in the AAD no longer matches."""
    key, enc = encrypt(sample_files["big_random.bin"], tmp_path)
    header, recs = split(enc.read_bytes())
    enc.write_bytes(join(header, recs[::-1]))
    assert_detected(tmp_path, enc, key)


def test_attack_chunk_duplicate(sample_files, tmp_path):
    """Overwrite chunk 2 with a copy of chunk 1 -> chunk number in the AAD no longer matches."""
    key, enc = encrypt(sample_files["big_random.bin"], tmp_path)
    header, recs = split(enc.read_bytes())
    recs[2] = recs[1]
    enc.write_bytes(join(header, recs))
    assert_detected(tmp_path, enc, key)


def test_attack_chunk_from_another_file(sample_files, tmp_path):
    """Splice in a chunk from a different file under the same key -> file ID in the AAD differs."""
    key = vc.generate_data_key()
    a, b = tmp_path / "a.enc", tmp_path / "b.enc"
    vc.encrypt_file(sample_files["big_random.bin"], a, key, "F-aaaaaaaaaaaaaaaa")
    vc.encrypt_file(sample_files["big_random.bin"], b, key, "F-bbbbbbbbbbbbbbbb")
    header, recs = split(a.read_bytes())
    recs[1] = split(b.read_bytes())[1][1]
    a.write_bytes(join(header, recs))
    assert_detected(tmp_path, a, key, "F-aaaaaaaaaaaaaaaa")


def test_attack_truncation_drop_last_chunk(sample_files, tmp_path):
    """Cut off the last (partial) chunk -> the new last chunk lacks the 'final' flag in its AAD."""
    key, enc = encrypt(sample_files["big_random.bin"], tmp_path)
    header, recs = split(enc.read_bytes())
    enc.write_bytes(join(header, recs[:-1]))
    assert_detected(tmp_path, enc, key)


def test_attack_truncation_exact_chunk_boundary(sample_files, tmp_path):
    """Cut a file at an exact chunk boundary, looking like a clean end -> missing 'final' flag."""
    key, enc = encrypt(sample_files["big_random.bin"], tmp_path)
    header, recs = split(enc.read_bytes())
    for keep in (1, 2, 3):
        enc.write_bytes(join(header, recs[:keep]))
        assert_detected(tmp_path, enc, key)


def test_attack_truncation_mid_chunk(sample_files, tmp_path):
    """Cut the file in the middle of a chunk -> the partial chunk fails authentication."""
    key, enc = encrypt(sample_files["big_random.bin"], tmp_path)
    blob = enc.read_bytes()
    for cut in (len(blob) - 1, len(blob) - 20, HL + REC + 5):
        enc.write_bytes(blob[:cut])
        assert_detected(tmp_path, enc, key)


def test_attack_truncation_to_nothing(sample_files, tmp_path):
    """Truncate to the header only, or to zero bytes -> 'no chunks' / 'too short' is reported."""
    for name in ["big_random.bin", "empty.bin"]:
        key, enc = encrypt(sample_files[name], tmp_path)
        blob = enc.read_bytes()
        for cut in (HL, 0, 3):
            enc.write_bytes(blob[:cut])
            assert_detected(tmp_path, enc, key)


def test_attack_empty_file_cannot_be_emptied_further(sample_files, tmp_path):
    """Cut the only chunk of an empty file's encryption -> detected, an empty file is not 'nothing'."""
    key, enc = encrypt(sample_files["empty.bin"], tmp_path)
    enc.write_bytes(enc.read_bytes()[:HL + vc.NONCE_LEN])
    assert_detected(tmp_path, enc, key)


@pytest.mark.parametrize("name", ANY_FILE)
def test_attack_extension_append_garbage(sample_files, tmp_path, name):
    """Append random bytes to the end of the file -> the old last chunk is no longer 'final'."""
    key, enc = encrypt(sample_files[name], tmp_path)
    enc.write_bytes(enc.read_bytes() + os.urandom(100))
    assert_detected(tmp_path, enc, key)


def test_attack_extension_append_copy_of_last_chunk(sample_files, tmp_path):
    """Append a valid copy of the last chunk -> the original last chunk loses its 'final' flag."""
    key, enc = encrypt(sample_files["big_random.bin"], tmp_path)
    header, recs = split(enc.read_bytes())
    enc.write_bytes(join(header, recs + [recs[-1]]))
    assert_detected(tmp_path, enc, key)


def test_attack_wrong_file_id(sample_files, tmp_path):
    """Present a file under another file's ID -> the file ID is bound into every chunk's AAD."""
    key, enc = encrypt(sample_files["big_random.bin"], tmp_path)
    assert_detected(tmp_path, enc, key, "F-ffffffffffffffff")


def test_attack_random_file_posing_as_vault_file(tmp_path):
    """Swap the encrypted file for random bytes -> magic / header check or first tag fails."""
    key = vc.generate_data_key()
    enc = tmp_path / "x.enc"
    enc.write_bytes(os.urandom(5000))
    assert_detected(tmp_path, enc, key)


def test_attack_failed_decrypt_leaves_existing_output_alone(sample_files, tmp_path):
    """Tamper with the last chunk while an old output file exists -> old file untouched, no partial plaintext."""
    key, enc = encrypt(sample_files["big_random.bin"], tmp_path)
    blob = bytearray(enc.read_bytes())
    blob[-1] ^= 1
    enc.write_bytes(bytes(blob))
    out = tmp_path / "out.bin"
    out.write_bytes(b"previous")
    with pytest.raises(vc.IntegrityError):
        vc.decrypt_file(enc, out, key, FID)
    assert out.read_bytes() == b"previous"
    assert not (tmp_path / "out.bin.part").exists()


# ================================================================ 2. key layer

def test_attack_wrong_data_key(sample_files, tmp_path):
    """Decrypt with a different data key -> first chunk's GCM tag fails."""
    _, enc = encrypt(sample_files["big_random.bin"], tmp_path)
    assert_detected(tmp_path, enc, vc.generate_data_key())


@pytest.mark.parametrize("pos", [0, 11, 12, 43, 44, 59])
def test_attack_wrapped_key_bit_flip(pos):
    """Flip a bit of a wrapped data key -> unwrapping under the KEK fails authentication."""
    kek = os.urandom(32)
    wrapped = bytearray(vc.wrap_key(kek, vc.generate_data_key(), FID))
    wrapped[pos] ^= 0x01
    with pytest.raises(vc.KeyUnwrapError):
        vc.unwrap_key(kek, bytes(wrapped), FID)


def test_attack_wrapped_key_moved_to_another_file():
    """Copy file A's wrapped key next to file B -> the file ID is bound into the key wrap."""
    kek = os.urandom(32)
    wrapped = vc.wrap_key(kek, vc.generate_data_key(), "F-aaaaaaaaaaaaaaaa")
    with pytest.raises(vc.KeyUnwrapError):
        vc.unwrap_key(kek, wrapped, "F-bbbbbbbbbbbbbbbb")


def test_attack_wrapped_key_truncated_or_padded():
    """Shorten or lengthen a wrapped key -> the length check rejects it before any decryption."""
    kek = os.urandom(32)
    wrapped = vc.wrap_key(kek, vc.generate_data_key(), FID)
    for bad in (wrapped[:-1], wrapped + b"\0", b""):
        with pytest.raises(vc.KeyUnwrapError):
            vc.unwrap_key(kek, bad, FID)


def test_attack_wrong_kek():
    """Unwrap with a key from the wrong passphrase -> GCM authentication fails."""
    wrapped = vc.wrap_key(os.urandom(32), vc.generate_data_key(), FID)
    with pytest.raises(vc.KeyUnwrapError):
        vc.unwrap_key(os.urandom(32), wrapped, FID)


def test_attack_wrong_passphrase_and_modified_header():
    """Wrong passphrase, or edit the vault header -> the check value fails, reported as wrong passphrase."""
    header = vc.new_vault_header("right passphrase", FAST)
    with pytest.raises(vc.WrongPassphraseError):
        vc.unlock("wrong passphrase", header)
    edited = dict(header, salt=os.urandom(16).hex())
    with pytest.raises(vc.WrongPassphraseError):
        vc.unlock("right passphrase", edited)


# ================================================================ 3. end to end

@pytest.fixture
def env(monkeypatch, tmp_path, sample_files):
    """A real vault holding one 4-chunk file, plus helpers to attack it."""
    monkeypatch.setattr(vc, "DEFAULT_SCRYPT_PARAMS", FAST)
    monkeypatch.setenv(config.ENV_VAR, str(tmp_path / "vault"))
    assert runner.invoke(cli_app, ["init", "--passphrase", PW]).exit_code == 0
    added = runner.invoke(cli_app, ["add-file", str(sample_files["big_random.bin"]),
                                    "--type", "other", "--passphrase", PW])
    assert added.exit_code == 0, added.output
    fid = added.output.split("Added ")[1].split()[0]
    enc = tmp_path / "vault" / "files" / f"{fid}.enc"

    class Env:
        pass
    e = Env()
    e.fid, e.enc, e.tmp, e.original = fid, enc, tmp_path, sample_files["big_random.bin"].read_bytes()
    e.pristine = enc.read_bytes()

    def tamper(kind):
        header, recs = split(e.pristine)
        if kind == "bit_flip":
            blob = bytearray(e.pristine)
            blob[HL + REC + 200] ^= 1
            enc.write_bytes(bytes(blob))
        elif kind == "chunk_swap":
            recs[0], recs[1] = recs[1], recs[0]
            enc.write_bytes(join(header, recs))
        elif kind == "truncate":
            enc.write_bytes(join(header, recs[:-1]))
        else:
            raise ValueError(kind)
    e.tamper = tamper
    return e


KINDS = ["bit_flip", "chunk_swap", "truncate"]


@pytest.mark.parametrize("kind", KINDS)
def test_attack_cli_open_file_refuses_tampered_file(env, kind):
    """Tamper with a stored file, then open-file -> CLI exits 1 with an integrity error, writes nothing."""
    env.tamper(kind)
    out = env.tmp / "o.bin"
    r = runner.invoke(cli_app, ["open-file", env.fid, "--out", str(out), "--passphrase", PW])
    assert r.exit_code == 1
    assert "chunk" in r.output or "short" in r.output or "truncated" in r.output
    assert not out.exists() and not (env.tmp / "o.bin.part").exists()


@pytest.mark.parametrize("kind", KINDS)
def test_attack_web_download_refuses_tampered_file(env, kind):
    """Tamper with a stored file, then download it on the Files page -> HTTP 500 page, no bytes of the file sent."""
    env.tamper(kind)
    c = TestClient(create_app(auth.SessionStore()), follow_redirects=False)
    assert c.post("/login", data={"passphrase": PW}).status_code == 303
    r = c.post(f"/files/{env.fid}/open")
    assert r.status_code == 500
    assert r.headers["content-type"].startswith("text/html")
    assert env.original[:64] not in r.content
    assert not list((env.tmp / "vault" / "files").glob(".open-*"))


@pytest.mark.parametrize("kind", KINDS)
def test_attack_revoke_refuses_tampered_file(env, kind):
    """Tamper with a stored file, then revoke it -> refused; the file and its key version stay unchanged."""
    env.tamper(kind)
    damaged = env.enc.read_bytes()
    r = runner.invoke(cli_app, ["revoke", env.fid, "--passphrase", PW])
    assert r.exit_code == 1
    assert env.enc.read_bytes() == damaged              # a bad file is never re-encrypted and 'laundered'
    conn = db.connect()
    try:
        assert db.get_file(conn, env.fid)["key_version"] == 1
    finally:
        conn.close()
    assert not list((env.tmp / "vault" / "files").glob(".revoke-*"))


def _reviewer_bundle(env):
    base = env.tmp / "rev"
    assert runner.invoke(cli_app, ["keygen", "--out", str(base), "--passphrase", RPW]).exit_code == 0
    shared = runner.invoke(cli_app, ["share", env.fid, "--reviewer-key", f"{base}.pub",
                                     "--expires", "2999-01-01", "--out", str(env.tmp / "b.json"),
                                     "--passphrase", PW])
    assert shared.exit_code == 0, shared.output
    fp = shared.output.split("fingerprint: ")[1].split()[0]
    return base, fp


@pytest.mark.parametrize("kind", KINDS)
def test_attack_reviewer_refuses_tampered_shared_file(env, kind):
    """Valid bundle but the encrypted file was tampered with in transit -> reviewer's open-shared fails, writes nothing."""
    base, fp = _reviewer_bundle(env)
    env.tamper(kind)
    out = env.tmp / "reviewed.bin"
    r = runner.invoke(cli_app, ["open-shared", str(env.tmp / "b.json"), env.fid, str(env.enc),
                                "--out", str(out), "--key", f"{base}.key",
                                "--key-passphrase", RPW, "--owner-fingerprint", fp])
    assert r.exit_code == 1
    assert not out.exists() and not (env.tmp / "reviewed.bin.part").exists()


def test_attack_wrapped_key_swap_in_database(env, sample_files):
    """Swap the wrapped keys of two files in the database -> each file ID is bound into its key wrap."""
    second = runner.invoke(cli_app, ["add-file", str(sample_files["exact_chunk.bin"]), "--passphrase", PW])
    fid2 = second.output.split("Added ")[1].split()[0]
    conn = db.connect()
    try:
        k1 = db.get_file(conn, env.fid)["wrapped_key"]
        k2 = db.get_file(conn, fid2)["wrapped_key"]
        with conn:
            conn.execute("UPDATE files SET wrapped_key = ? WHERE file_id = ?", (k2, env.fid))
            conn.execute("UPDATE files SET wrapped_key = ? WHERE file_id = ?", (k1, fid2))
    finally:
        conn.close()
    for fid in (env.fid, fid2):
        out = env.tmp / f"{fid}.out"
        r = runner.invoke(cli_app, ["open-file", fid, "--out", str(out), "--passphrase", PW])
        assert r.exit_code == 1 and not out.exists()


def test_attack_swap_encrypted_files_between_ids(env, sample_files):
    """Swap two stored .enc files so each sits under the other's ID -> file ID in the AAD no longer matches."""
    second = runner.invoke(cli_app, ["add-file", str(sample_files["exact_chunk.bin"]), "--passphrase", PW])
    fid2 = second.output.split("Added ")[1].split()[0]
    d = env.tmp / "vault" / "files"
    a, b = d / f"{env.fid}.enc", d / f"{fid2}.enc"
    ba, bb = a.read_bytes(), b.read_bytes()
    a.write_bytes(bb)
    b.write_bytes(ba)
    for fid in (env.fid, fid2):
        out = env.tmp / f"{fid}.out"
        r = runner.invoke(cli_app, ["open-file", fid, "--out", str(out), "--passphrase", PW])
        assert r.exit_code == 1 and not out.exists()


def test_attack_rollback_to_old_copy_after_revoke(env):
    """Put the pre-revoke encrypted file back after a revoke -> it no longer matches the new data key."""
    assert runner.invoke(cli_app, ["revoke", env.fid, "--passphrase", PW]).exit_code == 0
    assert env.enc.read_bytes() != env.pristine
    env.enc.write_bytes(env.pristine)                   # attacker restores the old ciphertext
    out = env.tmp / "o.bin"
    r = runner.invoke(cli_app, ["open-file", env.fid, "--out", str(out), "--passphrase", PW])
    assert r.exit_code == 1 and not out.exists()


def test_attack_deleted_encrypted_file(env):
    """Delete a stored .enc file -> open-file reports the data as missing instead of failing silently."""
    env.enc.unlink()
    r = runner.invoke(cli_app, ["open-file", env.fid, "--out", str(env.tmp / "o.bin"), "--passphrase", PW])
    assert r.exit_code == 1 and "missing" in r.output


@pytest.mark.parametrize("bad_id", ["../../etc/passwd", "F-../../x", "F-0123456789abcde", "F-0123456789ABCDEF", ""])
def test_attack_path_traversal_in_file_id(env, bad_id):
    """Pass a crafted file ID with ../ or odd characters -> the strict ID format check rejects it first."""
    with pytest.raises(ops.InvalidInputError):
        ops.check_file_id(bad_id)
    r = runner.invoke(cli_app, ["open-file", bad_id, "--out", str(env.tmp / "o.bin"), "--passphrase", PW])
    assert r.exit_code != 0 and not (env.tmp / "o.bin").exists()


def test_attack_plaintext_never_stored_on_disk(env):
    """Search every file in the vault folder for the plaintext -> it is never present (only ciphertext)."""
    needle = env.original[1000:1064]
    for f in (env.tmp / "vault").rglob("*"):
        if f.is_file():
            assert needle not in f.read_bytes(), f
