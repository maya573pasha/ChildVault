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
