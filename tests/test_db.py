import sqlite3

import pytest

from childvault import db
from childvault import vault_crypto as vc

FAST = {"n": 2 ** 10, "r": 8, "p": 1}


@pytest.fixture
def conn(tmp_path):
    """A fresh database with the schema, in a temp folder."""
    c = db.connect(tmp_path / "test.db")
    db.create_schema(c)
    yield c
    c.close()


def test_schema_version_recorded(conn):
    assert db.get_meta(conn, "schema_version") == str(db.SCHEMA_VERSION)


def test_create_schema_is_idempotent(conn):
    db.create_schema(conn)   # second call must not fail or duplicate rows
    rows = conn.execute("SELECT COUNT(*) FROM vault_meta").fetchone()[0]
    assert rows == 1


def test_not_initialized_at_start(conn):
    assert not db.is_initialized(conn)
    with pytest.raises(db.VaultNotInitializedError):
        db.load_header(conn)


def test_header_roundtrip_and_unlock(conn):
    header = vc.new_vault_header("pw", FAST)
    db.save_header(conn, header)
    assert db.is_initialized(conn)
    loaded = db.load_header(conn)
    assert loaded == header
    assert len(vc.unlock("pw", loaded)) == 32   # loaded header still works with Aaleen's code


def test_header_cannot_be_overwritten(conn):
    db.save_header(conn, vc.new_vault_header("pw", FAST))
    with pytest.raises(db.VaultAlreadyInitializedError):
        db.save_header(conn, vc.new_vault_header("other", FAST))
    # the original passphrase must still work
    vc.unlock("pw", db.load_header(conn))


def test_header_persists_after_reopen(tmp_path):
    path = tmp_path / "v.db"
    c = db.connect(path)
    db.create_schema(c)
    db.save_header(c, vc.new_vault_header("pw", FAST))
    c.close()

    c2 = db.connect(path)
    assert db.is_initialized(c2)
    c2.close()


# ---------------------------------------------------------------- files table

def _wrapped():
    kek = vc.derive_kek("pw", b"s" * 16, FAST)
    return vc.wrap_key(kek, vc.generate_data_key(), "F-test")


def test_new_file_ids_are_random_and_well_formed():
    ids = {db.new_file_id() for _ in range(100)}
    assert len(ids) == 100
    assert all(i.startswith("F-") and len(i) == 18 for i in ids)


def test_add_and_get_file(conn):
    w = _wrapped()
    db.add_file_record(conn, "F-1", w, "video", ".MP4", "owner", child_id="CH-4F7A", plaintext_size=10)
    row = db.get_file(conn, "F-1")
    assert row["wrapped_key"] == w
    assert row["child_id"] == "CH-4F7A"
    assert row["extension"] == "mp4"        # normalised
    assert row["key_version"] == 1          # default
    assert row["added_at"].endswith("+00:00")


def test_get_missing_file(conn):
    with pytest.raises(db.FileNotInVaultError):
        db.get_file(conn, "F-nope")


def test_duplicate_file_id_rejected(conn):
    db.add_file_record(conn, "F-1", _wrapped(), "csv", "csv", "owner")
    with pytest.raises(db.VaultDBError):
        db.add_file_record(conn, "F-1", _wrapped(), "csv", "csv", "owner")


def test_bad_file_type_rejected(conn):
    with pytest.raises(db.VaultDBError):
        db.add_file_record(conn, "F-1", _wrapped(), "exe", "exe", "owner")


def test_wrong_size_wrapped_key_rejected_by_database(conn):
    with pytest.raises(db.VaultDBError):
        db.add_file_record(conn, "F-1", b"too short", "csv", "csv", "owner")


def test_list_files_filter_by_child(conn):
    db.add_file_record(conn, "F-1", _wrapped(), "video", "mp4", "owner", child_id="CH-AAAA")
    db.add_file_record(conn, "F-2", _wrapped(), "csv", "csv", "owner", child_id="CH-BBBB")
    db.add_file_record(conn, "F-3", _wrapped(), "annotation", "eaf", "owner", child_id="CH-AAAA")
    assert len(db.list_files(conn)) == 3
    assert [r["file_id"] for r in db.list_files(conn, "CH-AAAA")] == ["F-1", "F-3"]


def test_files_table_has_no_name_columns(conn):
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(files)")}
    assert not cols & {"name", "child_name", "original_name", "filename"}


# ---------------------------------------------------------------- audit_log table

H1, H2, H3 = "a" * 64, "b" * 64, "c" * 64


def _append(conn, prev, entry, **kw):
    return db.append_audit_row(conn, db.utc_now(), "owner", kw.pop("action", "open"), prev, entry, **kw)


def test_audit_log_empty_at_start(conn):
    assert db.get_audit_rows(conn) == []
    assert db.get_last_audit_row(conn) is None


def test_append_and_read_in_order(conn):
    s1 = _append(conn, db.GENESIS_HASH, H1, action="init")
    s2 = _append(conn, H1, H2, file_id="F-1", details={"b": 2, "a": 1})
    assert s2 == s1 + 1
    rows = db.get_audit_rows(conn)
    assert [r["entry_hash"] for r in rows] == [H1, H2]
    assert rows[1]["details"] == '{"a": 1, "b": 2}'   # sorted keys -> stable for hashing
    assert db.get_last_audit_row(conn)["entry_hash"] == H2


def test_unknown_file_id_can_still_be_logged(conn):
    _append(conn, db.GENESIS_HASH, H1, action="open-denied", file_id="F-does-not-exist")
    assert db.get_last_audit_row(conn)["file_id"] == "F-does-not-exist"


def test_bad_hash_length_rejected(conn):
    with pytest.raises(db.VaultDBError):
        _append(conn, "short", H1)


def test_duplicate_entry_hash_rejected(conn):
    _append(conn, db.GENESIS_HASH, H1)
    with pytest.raises(db.VaultDBError):
        _append(conn, H1, H1)


def test_update_blocked_by_trigger(conn):
    _append(conn, db.GENESIS_HASH, H1)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        with conn:
            conn.execute("UPDATE audit_log SET actor = 'attacker'")


def test_delete_blocked_by_trigger(conn):
    _append(conn, db.GENESIS_HASH, H1)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        with conn:
            conn.execute("DELETE FROM audit_log")


def test_attacker_with_file_access_can_drop_trigger(conn):
    """Shows WHY the trigger is not enough: the hash chain must catch this."""
    _append(conn, db.GENESIS_HASH, H1)
    conn.execute("DROP TRIGGER audit_log_no_update")
    with conn:
        conn.execute("UPDATE audit_log SET actor = 'attacker'")
    assert db.get_last_audit_row(conn)["actor"] == "attacker"
