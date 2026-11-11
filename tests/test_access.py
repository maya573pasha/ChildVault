"""Tests for childvault/access.py (Laiba)."""
import os

import pytest

from childvault import access, audit, db
from childvault.access import Actor, PermissionDenied, Role, audited


@pytest.fixture
def conn(tmp_path):
    c = db.connect(tmp_path / "t.db")
    db.create_schema(c)
    yield c
    c.close()


@pytest.fixture
def key():
    return audit.derive_audit_key(os.urandom(32))


OWNER = Actor.owner()
RESEARCHER = Actor("rana", Role.RESEARCHER)
REVIEWER = Actor("rev1", Role.REVIEWER)


def actions(conn):
    return [e["action"] for e in audit.show(conn)]


# ---- the permission table ----------------------------------------------------

EXPECTED = {
    # action:        (owner, researcher, reviewer)
    "add_file":      (True, True, False),
    "open_file":     (True, True, False),
    "list_files":    (True, True, False),
    "pseudonymize":  (True, False, False),
    "lookup":        (True, False, False),
    "share":         (True, False, False),
    "revoke":        (True, False, False),
    "verify":        (True, True, False),
    "audit_show":    (True, False, False),
    "import_bundle": (False, False, True),
    "open_shared":   (False, False, True),
}


@pytest.mark.parametrize("action", sorted(EXPECTED))
def test_permission_matrix(action):
    for role, expected in zip((Role.OWNER, Role.RESEARCHER, Role.REVIEWER), EXPECTED[action]):
        assert access.is_allowed(role, action) is expected, (role, action)


def test_unknown_action_is_denied():
    assert not access.is_allowed(Role.OWNER, "format_disk")
    with pytest.raises(PermissionDenied):
        access.require(Role.OWNER, "format_disk")


def test_unknown_role_is_denied():
    assert not access.is_allowed("admin", "add_file")
    assert not access.is_allowed("", "add_file")


def test_role_accepts_plain_string():
    assert access.is_allowed("owner", "lookup")


def test_reviewer_cannot_touch_any_vault_data_action():
    for action in ("add_file", "open_file", "lookup", "share", "revoke", "audit_show", "pseudonymize"):
        assert not access.is_allowed(Role.REVIEWER, action)


def test_only_owner_can_reveal_names_or_share():
    for action in ("lookup", "pseudonymize", "share", "revoke"):
        allowed = {r for r in Role if access.is_allowed(r, action)}
        assert allowed == {Role.OWNER}


# ---- audited() ---------------------------------------------------------------

def test_success_is_logged_with_file_id_set_by_operation(conn, key):
    with audited(conn, key, OWNER, "add_file", details={"type": "csv"}) as ev:
        ev.file_id = "F-0123456789abcdef"
    e = audit.show(conn)[0]
    assert (e["actor"], e["action"], e["file_id"]) == ("owner", "add_file", "F-0123456789abcdef")
    assert e["details"] == {"type": "csv"}


def test_denied_is_logged_and_operation_does_not_run(conn, key):
    ran = []
    with pytest.raises(PermissionDenied):
        with audited(conn, key, RESEARCHER, "lookup", details={"child": "CH-4F7A"}):
            ran.append(True)
    assert ran == []
    e = audit.show(conn)[0]
    assert e["action"] == "denied:lookup" and e["actor"] == "rana"
    assert e["details"] == {"child": "CH-4F7A"}


def test_failure_is_logged_with_error_class_only(conn, key):
    class VaultFileError(Exception):
        pass

    with pytest.raises(VaultFileError):
        with audited(conn, key, OWNER, "open_file", file_id="F-aaaaaaaaaaaaaaaa"):
            raise VaultFileError("secret path C:/Users/x/Ali Khan.mp4")
    e = audit.show(conn)[0]
    assert e["action"] == "failed:open_file"
    assert e["details"] == {"error": "VaultFileError"}
    assert "Ali" not in str(e) and "C:/" not in str(e)       # message is never stored


def test_original_exception_is_reraised_unchanged(conn, key):
    with pytest.raises(ZeroDivisionError):
        with audited(conn, key, OWNER, "verify"):
            1 / 0


def test_successful_and_failed_and_denied_all_keep_chain_valid(conn, key):
    with audited(conn, key, OWNER, "add_file") as ev:
        ev.file_id = "F-1"
    with pytest.raises(PermissionDenied):
        with audited(conn, key, REVIEWER, "revoke", file_id="F-1"):
            pass
    with pytest.raises(ValueError):
        with audited(conn, key, OWNER, "open_file", file_id="F-1"):
            raise ValueError("x")
    assert actions(conn) == ["add_file", "denied:revoke", "failed:open_file"]
    assert audit.verify_chain(conn, key).ok


def test_operation_not_logged_as_success_if_it_raises(conn, key):
    with pytest.raises(RuntimeError):
        with audited(conn, key, OWNER, "share"):
            raise RuntimeError("boom")
    assert "share" not in actions(conn)


def test_event_details_can_be_added_by_operation(conn, key):
    with audited(conn, key, OWNER, "share") as ev:
        ev.details.update({"files": 2, "expires": "2026-12-31"})
    assert audit.show(conn)[0]["details"] == {"files": 2, "expires": "2026-12-31"}


# ---- tampered log behaviour ----------------------------------------------------

def _tamper_tail(conn, key):
    for i in range(3):
        audit.append_event(conn, key, "owner", "add_file", f"F-{i}")
    with conn:
        conn.execute("DROP TRIGGER audit_log_no_delete")
        conn.execute("DELETE FROM audit_log WHERE seq=3")


def test_strict_refuses_everything_on_a_tampered_log(conn, key):
    _tamper_tail(conn, key)
    ran = []
    with pytest.raises(audit.AuditTamperedError):
        with audited(conn, key, OWNER, "open_file"):
            ran.append(True)
    assert ran == []                                     # operation never ran


def test_non_strict_still_runs_but_does_not_write(conn, key):
    _tamper_tail(conn, key)
    before = len(audit.show(conn))
    with audited(conn, key, OWNER, "verify", strict=False):
        pass
    assert len(audit.show(conn)) == before
    assert not audit.verify_chain(conn, key).ok          # evidence not healed


def test_non_strict_still_enforces_permissions(conn, key):
    _tamper_tail(conn, key)
    with pytest.raises(PermissionDenied):
        with audited(conn, key, REVIEWER, "verify", strict=False):
            pass


@pytest.mark.parametrize("action", ["add_user", "remove_user", "list_users"])
def test_user_management_is_owner_only(action):
    assert access.is_allowed(Role.OWNER, action)
    assert not access.is_allowed(Role.RESEARCHER, action)
    assert not access.is_allowed(Role.REVIEWER, action)