import pytest
from fastapi.testclient import TestClient

from childvault import config, db
from childvault import identity as idm
from childvault import vault_crypto as vc
from childvault.web import auth
from childvault.web.app import create_app

FAST = {"n": 2 ** 10, "r": 8, "p": 1}
PW = "web test passphrase"
XSS_NAME = '<script>alert("x")</script>'


@pytest.fixture
def vault(monkeypatch, tmp_path):
    """A vault with three children (one with an XSS-style name) and one file for the first."""
    monkeypatch.setenv(config.ENV_VAR, str(tmp_path / "vault"))
    config.ensure_vault_dirs()
    header = vc.new_vault_header(PW, FAST)
    kek = vc.unlock(PW, header)

    imap = idm.IdentityMap()
    ids = {"normal": imap.add("Test Child One"), "xss": imap.add(XSS_NAME), "none": imap.add("No Files")}
    idm.save_map(kek, imap, config.get_identity_map_path())

    conn = db.connect()
    db.create_schema(conn)
    db.save_header(conn, header)
    db.add_file_record(conn, "F-0011223344556677", vc.wrap_key(kek, vc.generate_data_key(), "F-0011223344556677"),
                       "video", "mp4", "owner", child_id=ids["normal"])
    conn.close()
    return ids


@pytest.fixture
def app(vault):
    return create_app(auth.SessionStore())


@pytest.fixture
def client(app):
    c = TestClient(app, follow_redirects=False)
    assert c.post("/login", data={"passphrase": PW}).status_code == 303
    return c


def _lookup(client, cid):
    return client.post("/lookup", data={"child_id": cid})


def test_requires_login(app):
    anon = TestClient(app, follow_redirects=False)
    assert anon.get("/lookup").headers["location"] == "/login"
    assert anon.post("/lookup", data={"child_id": "CH-0000"}).headers["location"] == "/login"


def test_form_is_post(client):
    r = client.get("/lookup")
    assert r.status_code == 200 and 'method="post"' in r.text


def test_lookup_shows_name_and_files(client, vault):
    r = _lookup(client, vault["normal"].lower())          # lowercase accepted
    assert r.status_code == 200
    assert "Test Child One" in r.text
    assert "F-0011223344556677" in r.text and "video" in r.text


def test_child_without_files(client, vault):
    r = _lookup(client, vault["none"])
    assert "No Files" in r.text and "No files for this child yet" in r.text


def test_xss_name_is_escaped(client, vault):
    """A malicious 'name' must be shown as text, never run as a script."""
    r = _lookup(client, vault["xss"])
    assert r.status_code == 200
    assert XSS_NAME not in r.text
    assert "&lt;script&gt;" in r.text


def test_unknown_id(client):
    r = _lookup(client, "CH-FFFF")
    assert r.status_code == 404 and "No child with ID CH-FFFF" in r.text


def test_invalid_id_and_escaped_error(client):
    r = _lookup(client, "<b>Ali</b>")
    assert r.status_code == 400
    assert "<b>Ali</b>" not in r.text                      # echoed input is escaped too


def test_missing_map(client):
    config.get_identity_map_path().unlink()
    r = _lookup(client, "CH-0000")
    assert r.status_code == 500 and "missing" in r.text


def test_tampered_map(client):
    p = config.get_identity_map_path()
    blob = bytearray(p.read_bytes())
    blob[-1] ^= 0x01
    p.write_bytes(bytes(blob))
    r = _lookup(client, "CH-0000")
    assert r.status_code == 500 and "integrity check" in r.text


def test_non_owner_role_forbidden(app, vault):
    """When Laiba adds roles, a researcher must not see names."""
    token = app.state.sessions.create(b"\x00" * 32, "researcher")
    c = TestClient(app, follow_redirects=False)
    c.cookies.set(auth.COOKIE_NAME, token)
    assert c.get("/lookup").status_code == 403
    r = _lookup(c, vault["normal"])
    assert r.status_code == 403 and "Test Child One" not in r.text


def test_result_page_not_cached_and_id_not_in_url(client, vault):
    r = _lookup(client, vault["normal"])
    assert r.headers["cache-control"] == "no-store"
    assert vault["normal"] not in str(r.url)


def test_nav_links_to_lookup_when_logged_in(client):
    assert 'href="/lookup"' in client.get("/").text
