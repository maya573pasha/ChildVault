"""Web UI: researcher accounts, role checks and audit entries (Laiba)."""
import os

import pytest
from fastapi.testclient import TestClient

from childvault import audit, config, db, users
from childvault import identity as idm
from childvault import vault_crypto as vc
from childvault.web import auth
from childvault.web.app import create_app

FAST = {"n": 2 ** 10, "r": 8, "p": 1}
OWNER_PW = "web owner passphrase"
RANA_PW = "rana web passphrase"
REAL_NAME = "Ayesha Khan"


@pytest.fixture
def vault(monkeypatch, tmp_path):
    monkeypatch.setenv(config.ENV_VAR, str(tmp_path / "vault"))
    config.ensure_vault_dirs()
    header = vc.new_vault_header(OWNER_PW, FAST)
    kek = vc.unlock(OWNER_PW, header)
    imap = idm.IdentityMap()
    child = imap.add(REAL_NAME)
    idm.save_map(kek, imap, config.get_identity_map_path())
    conn = db.connect()
    db.create_schema(conn)
    db.save_header(conn, header)
    users.create_user(conn, kek, "rana", RANA_PW, params=FAST)
    conn.close()
    return child


@pytest.fixture
def app(vault):
    return create_app(auth.SessionStore())


def login(app, username, pw):
    c = TestClient(app, follow_redirects=False)
    r = c.post("/login", data={"username": username, "passphrase": pw})
    assert r.status_code == 303, r.text
    return c


@pytest.fixture
def owner(app):
    return login(app, "owner", OWNER_PW)


@pytest.fixture
def rana(app):
    return login(app, "rana", RANA_PW)


def upload(c, data=b"hello", child=""):
    return c.post("/files/upload", files={"file": ("clip.mp4", data, "application/octet-stream")},
                  data={"file_type": "video", "child_id": child})


def log():
    conn = db.connect()
    try:
        return [(e["actor"], e["action"], e["file_id"], e["details"]) for e in audit.show(conn)]
    finally:
        conn.close()


def actions():
    return [(a, act) for a, act, _, _ in log()]


def only_file_id():
    conn = db.connect()
    try:
        return db.list_files(conn)[0]["file_id"]
    finally:
        conn.close()


# ---------------------------------------------------------------- login

def test_researcher_logs_in_with_own_passphrase(app):
    c = login(app, "rana", RANA_PW)
    assert "Vault unlocked" in c.get("/").text
    assert "rana" in [s.username for s in app.state.sessions._sessions.values()]
    assert [s.role for s in app.state.sessions._sessions.values()] == ["researcher"]


def test_login_is_logged_with_account_name(owner, rana):
    assert ("owner", "login") in actions() and ("rana", "login") in actions()


def test_wrong_passphrase_or_unknown_account_rejected(app):
    c = TestClient(app, follow_redirects=False)
    assert c.post("/login", data={"username": "rana", "passphrase": OWNER_PW}).status_code == 401
    assert c.post("/login", data={"username": "ghost", "passphrase": RANA_PW}).status_code == 401
    assert c.post("/login", data={"username": "owner", "passphrase": RANA_PW}).status_code == 401


def test_username_field_is_optional_and_defaults_to_owner(app):
    c = TestClient(app, follow_redirects=False)
    assert c.post("/login", data={"passphrase": OWNER_PW}).status_code == 303


def test_username_is_case_insensitive(app):
    login(app, " RANA ", RANA_PW)


def test_login_page_has_account_field(app):
    assert 'name="username"' in TestClient(app).get("/login").text


# ---------------------------------------------------------------- researcher permissions

def test_researcher_can_list_upload_and_open(rana):
    assert rana.get("/files").status_code == 200
    assert upload(rana, b"secret bytes").status_code == 200
    fid = only_file_id()
    d = rana.post(f"/files/{fid}/open")
    assert d.status_code == 200 and d.content == b"secret bytes"
    assert ("rana", "add_file") in actions() and ("rana", "open_file") in actions()


def test_upload_entry_records_file_id_and_added_by(rana):
    upload(rana)
    fid = only_file_id()
    assert any(a == "rana" and act == "add_file" and f == fid for a, act, f, _ in log())
    conn = db.connect()
    assert db.get_file(conn, fid)["added_by"] == "rana"
    conn.close()


def test_researcher_cannot_revoke(rana, owner):
    upload(owner)
    fid = only_file_id()
    assert rana.get(f"/files/{fid}/revoke").status_code == 403
    assert rana.post(f"/files/{fid}/revoke").status_code == 403
    assert ("rana", "denied:revoke") in actions()
    conn = db.connect()
    assert db.get_file(conn, fid)["key_version"] == 1          # nothing changed
    conn.close()


def test_researcher_cannot_look_up_names(rana, vault):
    assert rana.get("/lookup").status_code == 403
    r = rana.post("/lookup", data={"child_id": vault})
    assert r.status_code == 403 and REAL_NAME not in r.text
    assert ("rana", "denied:lookup") in actions()


def test_nav_hides_pages_the_role_cannot_use(rana, owner):
    r, o = rana.get("/").text, owner.get("/").text
    assert 'href="/files"' in r and 'href="/lookup"' not in r
    assert 'href="/files"' in o and 'href="/lookup"' in o


def test_reviewer_session_is_denied_everything(app):
    c = TestClient(app, follow_redirects=False)
    c.cookies.set(auth.COOKIE_NAME, app.state.sessions.create(b"k" * 32, "reviewer", "rev1"))
    assert c.get("/files").status_code == 403
    assert upload(c).status_code == 403
    assert c.post("/files/F-0011223344556677/open").status_code == 403
    assert ("rev1", "denied:add_file") in actions()


# ---------------------------------------------------------------- audit entries

def test_owner_actions_are_logged_without_names(owner, vault):
    upload(owner, child=vault)
    fid = only_file_id()
    owner.post(f"/files/{fid}/open")
    owner.post("/lookup", data={"child_id": vault})
    owner.post(f"/files/{fid}/revoke")
    acts = actions()
    for a in (("owner", "add_file"), ("owner", "open_file"), ("owner", "lookup"), ("owner", "revoke")):
        assert a in acts, a
    entries = log()
    assert any(act == "lookup" and det == {"child": vault} for _, act, _, det in entries)
    assert any(act == "add_file" and det and det.get("child") == vault for _, act, _, det in entries)
    assert REAL_NAME not in str(entries)
    conn = db.connect()
    assert audit.verify_chain(conn, audit.derive_audit_key(vc.unlock(OWNER_PW, db.load_header(conn)))).ok
    conn.close()


def test_typed_child_text_never_reaches_the_log(owner):
    r = upload(owner, child="Ayesha Khan")                    # a real name typed in the child field
    assert r.status_code == 400
    entries = log()
    assert any(act == "failed:add_file" and det == {"error": "InvalidInputError"} for _, act, _, det in entries)
    assert "Ayesha" not in str(entries)


def test_failed_open_of_tampered_file_is_logged(owner, tmp_path):
    upload(owner, os.urandom(5000))
    fid = only_file_id()
    enc = tmp_path / "vault" / "files" / f"{fid}.enc"
    blob = bytearray(enc.read_bytes())
    blob[100] ^= 1
    enc.write_bytes(bytes(blob))
    assert owner.post(f"/files/{fid}/open").status_code == 500
    entries = log()
    assert any(act == "failed:open_file" and f == fid and det == {"error": "VaultFileError"}
               for _, act, f, det in entries)


def test_malicious_file_id_in_url_is_not_written_to_the_log(owner):
    r = owner.post("/files/%3Cscript%3Ealert(1)%3E/open")
    assert r.status_code == 400
    assert "script" not in str(log())


def test_unknown_but_well_formed_id_is_logged_as_failed(owner):
    assert owner.post("/files/F-ffffffffffffffff/open").status_code == 404
    assert any(act == "failed:open_file" and f == "F-ffffffffffffffff" for _, act, f, _ in log())


# ---------------------------------------------------------------- tampered log

def _tamper_tail(app):
    c = login(app, "owner", OWNER_PW)
    for _ in range(3):
        upload(c)
    conn = db.connect()
    with conn:
        conn.execute("DROP TRIGGER audit_log_no_delete")
        conn.execute("DELETE FROM audit_log WHERE seq >= (SELECT MAX(seq) - 1 FROM audit_log)")
    conn.close()
    return c


def test_web_refuses_changes_when_the_log_was_tampered_with(app):
    c = _tamper_tail(app)
    conn = db.connect()
    n_files = len(db.list_files(conn))
    conn.close()
    r = upload(c)
    assert r.status_code == 503 and "audit log failed" in r.text
    conn = db.connect()
    assert len(db.list_files(conn)) == n_files                  # the upload did not happen... 
    conn.close()


def test_owner_can_still_log_in_on_a_tampered_log(app):
    _tamper_tail(app)
    login(app, "owner", OWNER_PW)


def test_tampered_log_is_not_healed_by_web_use(app):
    c = _tamper_tail(app)
    upload(c)
    c.post("/lookup", data={"child_id": "CH-0000"})
    conn = db.connect()
    key = audit.derive_audit_key(vc.unlock(OWNER_PW, db.load_header(conn)))
    assert not audit.verify_chain(conn, key).ok
    conn.close()