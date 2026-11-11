"""Tests for childvault/users.py (Laiba)."""
import json
import os

import pytest

from childvault import db, users
from childvault import vault_crypto as vc
from childvault.access import Role

FAST = {"n": 2 ** 10, "r": 8, "p": 1}
OWNER_PW = "owner-passphrase-1"


@pytest.fixture
def vault(tmp_path):
    conn = db.connect(tmp_path / "t.db")
    db.create_schema(conn)
    header = vc.new_vault_header(OWNER_PW, FAST)
    db.save_header(conn, header)
    kek = vc.unlock(OWNER_PW, header)
    yield conn, kek, header
    conn.close()


def test_owner_logs_in_with_vault_passphrase(vault):
    conn, kek, header = vault
    k, actor = users.authenticate(conn, "owner", OWNER_PW, header)
    assert k == kek and actor.role is Role.OWNER and actor.name == "owner"


def test_researcher_gets_the_same_kek_but_researcher_role(vault):
    conn, kek, header = vault
    users.create_user(conn, kek, "rana", "rana-passphrase", params=FAST)
    k, actor = users.authenticate(conn, "rana", "rana-passphrase")
    assert k == kek
    assert actor.role is Role.RESEARCHER and actor.name == "rana"


def test_wrong_passphrase_unknown_user_and_empty_all_look_the_same(vault):
    conn, kek, header = vault
    users.create_user(conn, kek, "rana", "rana-passphrase", params=FAST)
    for name, pw in (("rana", "nope-nope-nope"), ("ghost", "rana-passphrase"), ("rana", ""), ("../x", "abc")):
        with pytest.raises(vc.WrongPassphraseError) as e:
            users.authenticate(conn, name, pw)
        assert str(e.value) == "wrong passphrase"


def test_researcher_passphrase_does_not_open_owner_login(vault):
    conn, kek, header = vault
    users.create_user(conn, kek, "rana", "rana-passphrase", params=FAST)
    with pytest.raises(vc.WrongPassphraseError):
        users.authenticate(conn, "owner", "rana-passphrase", header)


def test_reviewer_accounts_are_refused(vault):
    conn, kek, _ = vault
    with pytest.raises(users.UserError, match="never get vault access"):
        users.create_user(conn, kek, "rev1", "reviewer-pass", role=Role.REVIEWER, params=FAST)
    with pytest.raises(users.UserError):
        users.create_user(conn, kek, "boss", "boss-passphrase", role=Role.OWNER, params=FAST)


@pytest.mark.parametrize("bad", ["", "ab", "Rana", "1rana", "ra na", "owner", "x" * 40, "a/b", "user:evil"])
def test_bad_names_rejected(vault, bad):
    conn, kek, _ = vault
    with pytest.raises(users.UserError):
        users.create_user(conn, kek, bad, "rana-passphrase", params=FAST)


def test_short_passphrase_and_duplicate_rejected(vault):
    conn, kek, _ = vault
    with pytest.raises(users.UserError, match="at least"):
        users.create_user(conn, kek, "rana", "short", params=FAST)
    users.create_user(conn, kek, "rana", "rana-passphrase", params=FAST)
    with pytest.raises(users.UserError, match="already exists"):
        users.create_user(conn, kek, "rana", "another-passphrase", params=FAST)


def test_editing_the_role_in_the_database_breaks_the_slot(vault):
    conn, kek, _ = vault
    users.create_user(conn, kek, "rana", "rana-passphrase", params=FAST)
    rec = json.loads(db.get_meta(conn, "user:rana"))
    rec["role"] = "owner"
    with conn:
        conn.execute("UPDATE vault_meta SET value=? WHERE key='user:rana'", (json.dumps(rec),))
    with pytest.raises(vc.WrongPassphraseError):
        users.authenticate(conn, "rana", "rana-passphrase")


def test_slot_copied_to_another_username_does_not_open(vault):
    conn, kek, _ = vault
    users.create_user(conn, kek, "rana", "rana-passphrase", params=FAST)
    with conn:
        conn.execute("INSERT INTO vault_meta (key, value) SELECT 'user:eve', value FROM vault_meta "
                     "WHERE key='user:rana'")
    with pytest.raises(vc.WrongPassphraseError):
        users.authenticate(conn, "eve", "rana-passphrase")


def test_list_and_remove(vault):
    conn, kek, _ = vault
    users.create_user(conn, kek, "bilal", "bilal-passphrase", params=FAST)
    users.create_user(conn, kek, "rana", "rana-passphrase", params=FAST)
    assert users.list_users(conn) == [("bilal", "researcher"), ("rana", "researcher")]
    users.remove_user(conn, "rana")
    assert users.list_users(conn) == [("bilal", "researcher")]
    with pytest.raises(vc.WrongPassphraseError):
        users.authenticate(conn, "rana", "rana-passphrase")
    with pytest.raises(users.UserError):
        users.remove_user(conn, "rana")


def test_other_vault_meta_entries_are_not_listed_as_users(vault):
    conn, kek, _ = vault
    assert users.list_users(conn) == []      # vault_header, schema_version are not users