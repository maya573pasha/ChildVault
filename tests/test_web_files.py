import os

import pytest
from fastapi.testclient import TestClient

from childvault import config, db
from childvault import identity as idm
from childvault import vault_crypto as vc
from childvault.web import auth, files
from childvault.web.app import create_app

FAST = {"n": 2 ** 10, "r": 8, "p": 1}
PW = "web test passphrase"
XSS_NAME = '<script>alert("x")</script>'


@pytest.fixture
def vault(monkeypatch, tmp_path):
    monkeypatch.setenv(config.ENV_VAR, str(tmp_path / "vault"))
    config.ensure_vault_dirs()
    header = vc.new_vault_header(PW, FAST)
    kek = vc.unlock(PW, header)
    imap = idm.IdentityMap()
    child = imap.add("Test Child One")
    idm.save_map(kek, imap, config.get_identity_map_path())
    conn = db.connect()
    db.create_schema(conn)
    db.save_header(conn, header)
    conn.close()
    return child


@pytest.fixture
def app(vault):
    return create_app(auth.SessionStore())


@pytest.fixture
def client(app):
    c = TestClient(app, follow_redirects=False)
    assert c.post("/login", data={"passphrase": PW}).status_code == 303
    return c


def _upload(client, data=b"hello video", name="clip.mp4", file_type="video", child=""):
    return client.post("/files/upload",
                       files={"file": (name, data, "application/octet-stream")},
                       data={"file_type": file_type, "child_id": child})


def _only_id():
    conn = db.connect()
    try:
        rows = db.list_files(conn)
    finally:
        conn.close()
    assert len(rows) == 1
    return rows[0]["file_id"]


# ---------------------------------------------------------------- access control

def test_requires_login(app):
    anon = TestClient(app, follow_redirects=False)
    assert anon.get("/files").headers["location"] == "/login"
    assert anon.post("/files/upload", files={"file": ("a", b"x")}).headers["location"] == "/login"
    assert anon.post("/files/F-0011223344556677/open").headers["location"] == "/login"
    assert anon.get("/files/F-0011223344556677/revoke").headers["location"] == "/login"
    assert anon.post("/files/F-0011223344556677/revoke").headers["location"] == "/login"


def test_non_owner_forbidden(app):
    c = TestClient(app, follow_redirects=False)
    token = app.state.sessions.create(b"k" * 32, "reviewer")
    c.cookies.set(auth.COOKIE_NAME, token)
    assert c.get("/files").status_code == 403
    assert _upload(c).status_code == 403
    assert c.post("/files/F-0011223344556677/open").status_code == 403
    assert c.post("/files/F-0011223344556677/revoke").status_code == 403


def test_security_headers_on_files_page(client):
    r = client.get("/files")
    assert r.status_code == 200
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "script-src" not in r.headers["content-security-policy"]


# ---------------------------------------------------------------- upload / open

def test_upload_then_download_roundtrip(client, tmp_path):
    data = os.urandom(3 * vc.CHUNK_SIZE // 2)
    r = _upload(client, data=data, name="Ali Khan session.CSV", file_type="csv")
    assert r.status_code == 200 and "Added F-" in r.text
    fid = _only_id()

    # Only the extension is kept; the original name (could hold a child's name) is dropped.
    conn = db.connect()
    row = db.get_file(conn, fid)
    conn.close()
    assert row["extension"] == "csv" and row["file_type"] == "csv"
    assert row["plaintext_size"] == len(data)
    assert not any("Ali" in p.name for p in (tmp_path / "vault").rglob("*"))
    assert "Ali Khan" not in client.get("/files").text

    d = client.post(f"/files/{fid}/open")
    assert d.status_code == 200
    assert d.content == data
    assert d.headers["content-type"] == "application/octet-stream"
    assert "attachment" in d.headers["content-disposition"] and f"{fid}.csv" in d.headers["content-disposition"]
    assert not list((tmp_path / "vault" / "files").glob(".open-*"))     # temp plaintext removed


def test_upload_is_not_stored_in_plaintext(client, tmp_path):
    _upload(client, data=b"UNMISTAKABLE-PLAINTEXT" * 50)
    for f in (tmp_path / "vault").rglob("*"):
        if f.is_file():
            assert b"UNMISTAKABLE" not in f.read_bytes(), f
    assert not list((tmp_path / "vault" / "files").glob(".upload-*"))


def test_upload_with_child(client, vault):
    r = _upload(client, child=vault.lower())
    assert r.status_code == 200
    page = client.get("/files").text
    assert vault in page


def test_upload_unknown_or_invalid_child(client, tmp_path):
    assert _upload(client, child="CH-0000").status_code == 404
    assert _upload(client, child="Ali Khan").status_code == 400
    assert not list((tmp_path / "vault" / "files").glob("*.enc"))
    assert not list((tmp_path / "vault" / "files").glob(".upload-*"))


def test_upload_bad_type_rejected(client):
    assert _upload(client, file_type="exe").status_code == 400


def test_weird_extensions_are_dropped(client):
    _upload(client, name="a.<script>")
    _upload(client, name="noextension")
    conn = db.connect()
    exts = {r["extension"] for r in db.list_files(conn)}
    conn.close()
    assert exts == {""}


def test_oversize_upload_refused_before_reading(client, monkeypatch):
    monkeypatch.setattr(files, "MAX_UPLOAD_BYTES", 100)
    r = _upload(client, data=b"x" * 5000)
    assert r.status_code == 413
    conn = db.connect()
    assert db.list_files(conn) == []
    conn.close()


def test_open_tampered_file_fails_and_sends_nothing(client, tmp_path):
    _upload(client, data=os.urandom(5000))
    fid = _only_id()
    enc = tmp_path / "vault" / "files" / f"{fid}.enc"
    blob = bytearray(enc.read_bytes())
    blob[100] ^= 1
    enc.write_bytes(bytes(blob))
    r = client.post(f"/files/{fid}/open")
    assert r.status_code == 500
    assert r.headers["content-type"].startswith("text/html")
    assert not list((tmp_path / "vault" / "files").glob(".open-*"))


def test_open_unknown_bad_and_deleted(client, tmp_path):
    assert client.post("/files/F-ffffffffffffffff/open").status_code == 404
    assert client.post("/files/not-an-id/open").status_code == 400
    _upload(client)
    fid = _only_id()
    (tmp_path / "vault" / "files" / f"{fid}.enc").unlink()
    r = client.post(f"/files/{fid}/open")
    assert r.status_code == 500 and "missing" in r.text


def test_path_traversal_in_id_rejected(client):
    for bad in ["..%2F..%2Fx", "F-..%2F..%2Fx", "%2e%2e"]:
        assert client.post(f"/files/{bad}/open").status_code in (400, 404, 405)


# ---------------------------------------------------------------- revoke

def test_revoke_requires_confirmation_page_then_post(client, tmp_path):
    _upload(client, data=b"keep me" * 100)
    fid = _only_id()
    enc = tmp_path / "vault" / "files" / f"{fid}.enc"
    before = enc.read_bytes()

    page = client.get(f"/files/{fid}/revoke")           # GET changes nothing
    assert page.status_code == 200 and 'method="post"' in page.text
    assert enc.read_bytes() == before

    r = client.post(f"/files/{fid}/revoke")
    assert r.status_code == 200 and "version 2" in r.text
    assert enc.read_bytes() != before
    d = client.post(f"/files/{fid}/open")                # still readable by the owner
    assert d.content == b"keep me" * 100
    assert not list((tmp_path / "vault" / "files").glob(".revoke-*"))


def test_revoke_unknown_and_bad_ids(client):
    assert client.post("/files/F-ffffffffffffffff/revoke").status_code == 404
    assert client.post("/files/xyz/revoke").status_code == 400
    assert client.get("/files/xyz/revoke").status_code == 400


def test_revoke_tampered_file_changes_nothing(client, tmp_path):
    _upload(client, data=b"x" * 5000)
    fid = _only_id()
    enc = tmp_path / "vault" / "files" / f"{fid}.enc"
    blob = bytearray(enc.read_bytes())
    blob[100] ^= 1
    enc.write_bytes(bytes(blob))
    assert client.post(f"/files/{fid}/revoke").status_code == 500
    assert enc.read_bytes() == bytes(blob)
    conn = db.connect()
    assert db.get_file(conn, fid)["key_version"] == 1
    conn.close()


# ---------------------------------------------------------------- output safety

def test_everything_shown_is_escaped(client):
    _upload(client)
    fid = _only_id()
    conn = db.connect()
    with conn:   # a hostile value that somehow reached the DB must still render as text
        conn.execute("UPDATE files SET extension = ? WHERE file_id = ?", (XSS_NAME, fid))
    conn.close()
    page = client.get("/files").text
    assert "<script>" not in page and "&lt;script&gt;" in page


def test_error_messages_are_escaped(client):
    r = client.post("/files/upload", files={"file": ("a.bin", b"x")},
                    data={"file_type": "other", "child_id": XSS_NAME})
    assert "<script>" not in r.text
