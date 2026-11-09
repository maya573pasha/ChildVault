import os

import pytest
from typer.testing import CliRunner

from childvault import __version__, config, db
from childvault import identity as idm
from childvault import keyshare as ks
from childvault import vault_crypto as vc
from childvault.cli import app

runner = CliRunner()
PW = "correct horse battery"


@pytest.fixture(autouse=True)
def temp_vault(monkeypatch, tmp_path):
    """Every CLI test gets its own empty vault folder."""
    monkeypatch.setenv(config.ENV_VAR, str(tmp_path / "vault"))
    return tmp_path / "vault"


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_no_args_shows_help():
    result = runner.invoke(app, [])
    assert "init" in result.output


def test_init_creates_vault(temp_vault):
    result = runner.invoke(app, ["init"], input=f"{PW}\n{PW}\n")
    assert result.exit_code == 0, result.output
    assert (temp_vault / "files").is_dir()
    conn = db.connect()
    try:
        assert len(vc.unlock(PW, db.load_header(conn))) == 32
    finally:
        conn.close()


def test_passphrase_not_echoed():
    result = runner.invoke(app, ["init"], input=f"{PW}\n{PW}\n")
    assert PW not in result.output


def test_init_twice_refused():
    runner.invoke(app, ["init", "--passphrase", PW])
    result = runner.invoke(app, ["init", "--passphrase", "another passphrase"])
    assert result.exit_code == 1
    assert "already exists" in result.output
    conn = db.connect()
    try:
        vc.unlock(PW, db.load_header(conn))   # original passphrase still works
    finally:
        conn.close()


def test_short_passphrase_refused(temp_vault):
    result = runner.invoke(app, ["init", "--passphrase", "short"])
    assert result.exit_code == 1
    assert not temp_vault.exists()            # nothing created


def test_mismatched_confirmation_refused():
    result = runner.invoke(app, ["init"], input=f"{PW}\nsomething else\n{PW}\n{PW}\n")
    assert "do not match" in result.output.lower()


# ---------------------------------------------------------------- stub commands

ALL_COMMANDS = ["init", "status", "web", "keygen", "fingerprint", "add-file", "open-file", "revoke", "pseudonymize",
                "lookup", "share", "import-bundle", "verify", "audit"]


def test_help_lists_every_command():
    output = runner.invoke(app, ["--help"]).output
    for name in ALL_COMMANDS:
        assert name in output


@pytest.mark.parametrize("args, owner", [
    (["revoke", "F-1"], "Aaleen"),
    (["share", "F-1", "F-2", "--reviewer-key", "r.pub", "--expires", "2026-12-31", "--out", "b.json"], "Mariyam"),
    (["import-bundle", "b.json"], "Mariyam"),
    (["verify"], "Laiba"),
    (["audit", "show"], "Laiba"),
])
def test_stub_says_not_implemented_with_owner(args, owner):
    result = runner.invoke(app, args)
    assert result.exit_code == 1
    assert "not implemented" in result.output
    assert owner in result.output


def test_add_file_rejects_missing_file():
    result = runner.invoke(app, ["add-file", "does-not-exist.mp4"])
    assert result.exit_code == 2        # Typer/Click usage error, before our code runs


def test_add_file_rejects_unknown_type(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    result = runner.invoke(app, ["add-file", str(f), "--type", "exe"])
    assert result.exit_code == 2


def test_file_type_choices_match_database():
    from childvault.cli import FileType
    assert tuple(t.value for t in FileType) == db.FILE_TYPES


# ---------------------------------------------------------------- unlock / status

def _make_vault():
    result = runner.invoke(app, ["init", "--passphrase", PW])
    assert result.exit_code == 0, result.output


def test_status_with_correct_passphrase():
    _make_vault()
    result = runner.invoke(app, ["status"], input=f"{PW}\n")
    assert result.exit_code == 0, result.output
    assert "Vault unlocked" in result.output
    assert "Files:        0" in result.output
    assert PW not in result.output             # prompt input is hidden


def test_status_wrong_passphrase():
    _make_vault()
    result = runner.invoke(app, ["status", "--passphrase", "not the passphrase"])
    assert result.exit_code == 1
    assert "wrong passphrase" in result.output


def test_status_without_vault_does_not_create_one(temp_vault):
    result = runner.invoke(app, ["status", "--passphrase", PW])
    assert result.exit_code == 1
    assert "no vault found" in result.output
    assert not config.get_db_path().exists()   # no empty DB left behind


def test_unlock_vault_returns_working_kek():
    from childvault.cli import unlock_vault
    _make_vault()
    conn, kek = unlock_vault(PW)
    try:
        wrapped = vc.wrap_key(kek, vc.generate_data_key(), "F-x")
        assert len(wrapped) == vc.WRAPPED_LEN
    finally:
        conn.close()


# ---------------------------------------------------------------- pseudonymize / lookup

def _pseudonymize(name):
    result = runner.invoke(app, ["pseudonymize", "--name", name, "--passphrase", PW])
    assert result.exit_code == 0, result.output
    return result.output.split("Pseudonym: ")[1].split()[0]


def test_init_creates_empty_encrypted_map():
    _make_vault()
    path = config.get_identity_map_path()
    assert path.is_file()
    conn = db.connect()
    try:
        kek = vc.unlock(PW, db.load_header(conn))
    finally:
        conn.close()
    assert len(idm.load_map(kek, path)) == 0


def test_pseudonymize_then_lookup():
    _make_vault()
    cid = _pseudonymize("Test Child One")
    assert idm.is_valid_child_id(cid)
    result = runner.invoke(app, ["lookup", cid.lower(), "--passphrase", PW])
    assert result.exit_code == 0, result.output
    assert f"{cid}  ->  Test Child One" in result.output
    assert "Files in vault for this child: 0" in result.output


def test_pseudonymize_prompts_for_name():
    _make_vault()
    result = runner.invoke(app, ["pseudonymize", "--passphrase", PW], input="Test Child Two\n")
    assert result.exit_code == 0, result.output
    assert "Pseudonym: CH-" in result.output


def test_two_children_get_different_ids():
    _make_vault()
    assert _pseudonymize("Sam") != _pseudonymize("Sam")


def test_name_never_written_in_plaintext(temp_vault):
    _make_vault()
    _pseudonymize("Unmistakable Name")
    for f in temp_vault.rglob("*"):
        if f.is_file():
            assert b"Unmistakable" not in f.read_bytes(), f


def test_pseudonymize_wrong_passphrase_changes_nothing():
    _make_vault()
    before = config.get_identity_map_path().read_bytes()
    result = runner.invoke(app, ["pseudonymize", "--name", "X", "--passphrase", "wrong passphrase"])
    assert result.exit_code == 1
    assert config.get_identity_map_path().read_bytes() == before


def test_pseudonymize_empty_name_refused():
    _make_vault()
    result = runner.invoke(app, ["pseudonymize", "--name", "   ", "--passphrase", PW])
    assert result.exit_code == 1
    assert "must not be empty" in result.output


def test_lookup_unknown_id():
    _make_vault()
    result = runner.invoke(app, ["lookup", "CH-0000", "--passphrase", PW])
    assert result.exit_code == 1
    assert "no child with id CH-0000" in result.output


def test_lookup_invalid_id_rejected_before_passphrase():
    _make_vault()
    result = runner.invoke(app, ["lookup", "Ali Khan"], input=f"{PW}\n")
    assert result.exit_code == 1
    assert "not a valid child ID" in result.output


def test_lookup_counts_child_files():
    _make_vault()
    cid = _pseudonymize("Test Child")
    conn = db.connect()
    kek = vc.unlock(PW, db.load_header(conn))
    db.add_file_record(conn, "F-1", vc.wrap_key(kek, vc.generate_data_key(), "F-1"),
                       "video", "mp4", "owner", child_id=cid)
    conn.close()
    result = runner.invoke(app, ["lookup", cid, "--passphrase", PW])
    assert "Files in vault for this child: 1" in result.output


def test_deleted_map_is_reported():
    _make_vault()
    config.get_identity_map_path().unlink()
    result = runner.invoke(app, ["lookup", "CH-0000", "--passphrase", PW])
    assert result.exit_code == 1
    assert "identity map is missing" in result.output


def test_tampered_map_is_reported():
    _make_vault()
    path = config.get_identity_map_path()
    blob = bytearray(path.read_bytes())
    blob[-1] ^= 0x01
    path.write_bytes(bytes(blob))
    result = runner.invoke(app, ["pseudonymize", "--name", "X", "--passphrase", PW])
    assert result.exit_code == 1
    assert "integrity check" in result.output


# ---------------------------------------------------------------- keygen / fingerprint

RPW = "reviewer passphrase"


def test_keygen_creates_both_files(tmp_path):
    base = tmp_path / "alice"
    result = runner.invoke(app, ["keygen", "--out", str(base)], input=f"{RPW}\n{RPW}\n")
    assert result.exit_code == 0, result.output
    priv = ks.load_private_key(tmp_path / "alice.key", RPW)
    pub = ks.load_public_key(tmp_path / "alice.pub")
    assert ks.fingerprint(priv.public_key()) == ks.fingerprint(pub)
    assert ks.fingerprint(pub) in result.output
    assert RPW not in result.output


def test_keygen_refuses_to_overwrite(tmp_path):
    base = tmp_path / "alice"
    runner.invoke(app, ["keygen", "--out", str(base), "--passphrase", RPW])
    before = (tmp_path / "alice.key").read_bytes()
    result = runner.invoke(app, ["keygen", "--out", str(base), "--passphrase", RPW])
    assert result.exit_code == 1
    assert "refusing to overwrite" in result.output
    assert (tmp_path / "alice.key").read_bytes() == before


def test_keygen_short_passphrase(tmp_path):
    result = runner.invoke(app, ["keygen", "--out", str(tmp_path / "a"), "--passphrase", "short"])
    assert result.exit_code == 1
    assert not (tmp_path / "a.key").exists()


def test_keygen_does_not_need_a_vault(tmp_path, temp_vault):
    """A reviewer usually has no vault of their own."""
    result = runner.invoke(app, ["keygen", "--out", str(tmp_path / "r"), "--passphrase", RPW])
    assert result.exit_code == 0, result.output
    assert not temp_vault.exists()


def test_fingerprint_command_matches_keygen(tmp_path):
    base = tmp_path / "bob"
    out = runner.invoke(app, ["keygen", "--out", str(base), "--passphrase", RPW]).output
    result = runner.invoke(app, ["fingerprint", str(tmp_path / "bob.pub")])
    assert result.exit_code == 0
    assert result.output.strip() in out


def test_fingerprint_rejects_bad_file(tmp_path):
    junk = tmp_path / "junk.pub"
    junk.write_text("hello")
    result = runner.invoke(app, ["fingerprint", str(junk)])
    assert result.exit_code == 1
    assert "cannot read public key" in result.output


def test_web_refuses_without_vault():
    result = runner.invoke(app, ["web"])
    assert result.exit_code == 1
    assert "no vault found" in result.output


# ---------------------------------------------------------------- add-file / open-file

def _add(path, *extra):
    return runner.invoke(app, ["add-file", str(path), *extra, "--passphrase", PW])


def _open(file_id, out, passphrase=PW):
    return runner.invoke(app, ["open-file", file_id, "--out", str(out), "--passphrase", passphrase])


def _added_id(result):
    assert result.exit_code == 0, result.output
    return result.output.split("Added ")[1].split()[0]


def test_add_and_open_roundtrip(tmp_path, temp_vault):
    _make_vault()
    src = tmp_path / "secret.csv"
    data = os.urandom(3 * vc.CHUNK_SIZE // 2)
    src.write_bytes(data)
    file_id = _added_id(_add(src, "--type", "csv"))
    assert db.FILE_TYPES and file_id.startswith("F-") and len(file_id) == 18
    assert not any("secret" in p.name for p in temp_vault.rglob("*"))

    conn = db.connect()
    try:
        row = db.get_file(conn, file_id)
    finally:
        conn.close()
    assert row["file_type"] == "csv" and row["extension"] == "csv"
    assert row["plaintext_size"] == len(data) and row["child_id"] is None

    out = tmp_path / "restored.csv"
    result = _open(file_id, out)
    assert result.exit_code == 0, result.output
    assert out.read_bytes() == data


def test_add_file_with_child(tmp_path):
    _make_vault()
    cid = _pseudonymize("Test Child")
    src = tmp_path / "a.mp4"
    src.write_bytes(b"video")
    _added_id(_add(src, "--type", "video", "--child", cid.lower()))
    result = runner.invoke(app, ["lookup", cid, "--passphrase", PW])
    assert "Files in vault for this child: 1" in result.output


def test_add_file_unknown_or_invalid_child(tmp_path, temp_vault):
    _make_vault()
    src = tmp_path / "a.bin"
    src.write_bytes(b"x")
    assert _add(src, "--child", "CH-0000").exit_code == 1
    assert _add(src, "--child", "Ali Khan").exit_code == 1
    assert list((temp_vault / "files").glob("*.enc")) == []


def test_add_file_wrong_passphrase_stores_nothing(tmp_path, temp_vault):
    _make_vault()
    src = tmp_path / "a.bin"
    src.write_bytes(b"x")
    result = runner.invoke(app, ["add-file", str(src), "--passphrase", "wrong passphrase"])
    assert result.exit_code == 1
    assert list((temp_vault / "files").glob("*.enc")) == []


def test_add_file_without_vault_fails_cleanly(tmp_path):
    src = tmp_path / "a.bin"
    src.write_bytes(b"x")
    result = _add(src)
    assert result.exit_code == 1 and "no vault found" in result.output


def test_open_wrong_passphrase(tmp_path):
    _make_vault()
    src = tmp_path / "a.bin"
    src.write_bytes(b"hello")
    file_id = _added_id(_add(src))
    out = tmp_path / "o.bin"
    assert _open(file_id, out, passphrase="wrong passphrase").exit_code == 1
    assert not out.exists()


def test_open_detects_tampered_file(tmp_path, temp_vault):
    _make_vault()
    src = tmp_path / "a.bin"
    src.write_bytes(os.urandom(5000))
    file_id = _added_id(_add(src))
    enc = temp_vault / "files" / f"{file_id}.enc"
    blob = bytearray(enc.read_bytes())
    blob[100] ^= 0x01
    enc.write_bytes(bytes(blob))
    out = tmp_path / "o.bin"
    assert _open(file_id, out).exit_code == 1
    assert not out.exists()


def test_open_detects_swapped_wrapped_key(tmp_path):
    _make_vault()
    a, b = tmp_path / "a.bin", tmp_path / "b.bin"
    a.write_bytes(b"first")
    b.write_bytes(b"second")
    id1, id2 = _added_id(_add(a)), _added_id(_add(b))
    conn = db.connect()
    try:
        k1 = db.get_file(conn, id1)["wrapped_key"]
        k2 = db.get_file(conn, id2)["wrapped_key"]
        with conn:
            conn.execute("UPDATE files SET wrapped_key = ? WHERE file_id = ?", (k2, id1))
            conn.execute("UPDATE files SET wrapped_key = ? WHERE file_id = ?", (k1, id2))
    finally:
        conn.close()
    out = tmp_path / "o.bin"
    assert _open(id1, out).exit_code == 1
    assert not out.exists()


def test_open_rejects_bad_ids_and_existing_output(tmp_path):
    _make_vault()
    out = tmp_path / "o.bin"
    assert _open("../vault", out).exit_code == 1
    assert _open("F-../../x", out).exit_code == 1
    assert _open("F-ffffffffffffffff", out).exit_code == 1      # well-formed but unknown
    src = tmp_path / "a.bin"
    src.write_bytes(b"hello")
    file_id = _added_id(_add(src))
    out.write_bytes(b"existing")
    assert _open(file_id, out).exit_code == 1
    assert out.read_bytes() == b"existing"


def test_open_reports_missing_blob(tmp_path, temp_vault):
    _make_vault()
    src = tmp_path / "a.bin"
    src.write_bytes(b"hello")
    file_id = _added_id(_add(src))
    (temp_vault / "files" / f"{file_id}.enc").unlink()
    result = _open(file_id, tmp_path / "o.bin")
    assert result.exit_code == 1 and "missing" in result.output
