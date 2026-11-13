"""Web UI: share-bundle page and audit-log viewer (Laiba, Phase 4)."""
import json
import re
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from childvault import audit, config, db, users
from childvault import bundle as bnd
from childvault import keyshare as ks
from childvault import vault_crypto as vc
from childvault.web import auth
from childvault.web.app import create_app

FAST = {"n": 2 ** 10, "r": 8, "p": 1}
OWNER_PW = "web owner passphrase"
RANA_PW = "rana web passphrase"
XSS = '<script>alert("x")</script>'


@pytest.fixture
def vault(monkeypatch, tmp_path):
    monkeypatch.setenv(config.ENV_VAR, str(tmp_path / "vault"))
    config.ensure_vault_dirs()
    header = vc.new_vault_header(OWNER_PW, FAST)
    kek = vc.unlock(OWNER_PW, header)
    conn = db.connect()
    db.create_schema(conn)
    db.save_header(conn, header)
    users.create_user(conn, kek, "rana", RANA_PW, params=FAST)
    conn.close()


@pytest.fixture
def app(vault):
    return create_app(auth.SessionStore())


def login(app, user, pw):
    c = TestClient(app, follow_redirects=False)
    assert c.post("/login", data={"username": user, "passphrase": pw}).status_code == 303
    return c


@pytest.fixture
def owner(app):
    return login(app, "owner", OWNER_PW)


@pytest.fixture
def rana(app):
    return login(app, "rana", RANA_PW)


@pytest.fixture
def reviewer(tmp_path):
    priv, pub = ks.generate_reviewer_keypair()
    path = tmp_path / "reviewer.pub"
    ks.save_public_key(pub, path)
    return priv, pub, path.read_text()


def add_file(c, data=b"top secret clip"):
    c.post("/files/upload", files={"file": ("a.mp4", data, "application/octet-stream")},
           data={"file_type": "video", "child_id": ""})
    conn = db.connect()
    try:
        return db.list_files(conn)[-1]["file_id"]
    finally:
        conn.close()


def future(days=7):
    return (datetime.now(timezone.utc) + timedelta(days=days)).strftime("%Y-%m-%d")


def entries():
    conn = db.connect()
    try:
        return audit.show(conn)
    finally:
        conn.close()


def preview(c, ids, pem, expires):
    return c.post("/share/preview", data={"file_ids": ids, "reviewer_key": pem, "expires": expires})


def create_from_preview(c, page):
    """Re-submit exactly what the confirmation page contains (as a browser would)."""
    html = page.text
    ids = re.findall(r'name="file_ids" value="([^"]+)"', html)
    key_hex = re.search(r'name="reviewer_key_hex" value="([^"]+)"', html).group(1)
    exp = re.search(r'name="expires" value="([^"]*)"', html).group(1)
    return c.post("/share/create", data={"file_ids": ids, "reviewer_key_hex": key_hex, "expires": exp})


# ---------------------------------------------------------------- share: access

def test_share_requires_login(app):
    anon = TestClient(app, follow_redirects=False)
    for method, path in (("get", "/share"), ("post", "/share/preview"), ("post", "/share/create")):
        assert getattr(anon, method)(path).headers["location"] == "/login"


def test_researcher_cannot_share_and_attempt_is_logged(rana):
    assert rana.get("/share").status_code == 403
    assert rana.post("/share/preview", data={}).status_code == 403
    assert rana.post("/share/create", data={}).status_code == 403
    assert sum(1 for e in entries() if (e["actor"], e["action"]) == ("rana", "denied:share")) == 3


def test_share_form_lists_files_and_has_post_forms(owner):
    fid = add_file(owner)
    r = owner.get("/share")
    assert r.status_code == 200 and fid in r.text and 'method="post"' in r.text
    assert "does not exist yet" in r.text


# ---------------------------------------------------------------- share: validation

@pytest.mark.parametrize("ids, pem_ok, expires, text", [
    ([], True, "future", "at least one file"),
    (["F-0011223344556677"], False, "future", "public key"),
    (["F-0011223344556677"], True, "not-a-date", "invalid expiry"),
    (["../etc/passwd"], True, "future", "Invalid file selection"),
])
def test_preview_rejects_bad_input(owner, reviewer, ids, pem_ok, expires, text):
    pem = reviewer[2] if pem_ok else "just some text"
    r = preview(owner, ids, pem, future() if expires == "future" else expires)
    assert r.status_code == 400 and text in r.text


def test_private_key_or_wrong_key_type_is_refused(owner, tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    ed = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    r = preview(owner, ["F-0011223344556677"], ed, future())
    assert r.status_code == 400 and "not a reviewer key" in r.text


def test_expiry_in_the_past_is_refused(owner, reviewer):
    fid = add_file(owner)
    page = preview(owner, [fid], reviewer[2], "2020-01-01")
    assert page.status_code == 200                                   # parses fine...
    r = create_from_preview(owner, page)
    assert r.status_code == 400 and "future" in r.text                # ...but cannot be created
    assert not any(e["action"] == "share" for e in entries())


def test_unknown_file_is_refused_and_logged_as_failed(owner, reviewer):
    page = preview(owner, ["F-ffffffffffffffff"], reviewer[2], future())
    r = create_from_preview(owner, page)
    assert r.status_code == 404
    assert any(e["action"] == "failed:share" for e in entries())


def test_error_pages_escape_input(owner):
    r = preview(owner, [XSS], XSS, XSS)
    assert "<script>" not in r.text


def test_create_rejects_a_damaged_key_field(owner):
    r = owner.post("/share/create", data={"file_ids": ["F-0011223344556677"],
                                          "reviewer_key_hex": "zz", "expires": future()})
    assert r.status_code == 400


# ---------------------------------------------------------------- share: the whole flow

def test_preview_shows_the_reviewer_fingerprint(owner, reviewer):
    fid = add_file(owner)
    page = preview(owner, [fid], reviewer[2], future())
    assert page.status_code == 200
    assert ks.fingerprint(reviewer[1]) in page.text
    assert "fingerprint matches" in page.text
    assert not any(e["action"] == "share" for e in entries())        # nothing created yet


def test_full_flow_reviewer_can_open_the_shared_file(owner, reviewer, tmp_path):
    priv, pub, pem = reviewer
    plaintext = b"top secret clip" * 100
    fid = add_file(owner, plaintext)
    other = add_file(owner, b"NOT SHARED")

    r = create_from_preview(owner, preview(owner, [fid], pem, future()))
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/octet-stream"
    assert "attachment" in r.headers["content-disposition"]

    bundle = json.loads(r.content)
    payload = bnd.verify_bundle(bundle, reviewer_fp=ks.fingerprint(pub))
    assert list(payload["files"]) == [fid]                            # scoped: only the chosen file
    keys = ks.unwrap_files_for_reviewer(payload["files"], priv)
    out = tmp_path / "plain"
    vc.decrypt_file(config.get_files_dir() / f"{fid}.enc", out, keys[fid], fid)
    assert out.read_bytes() == plaintext                              # the reviewer really can read it
    assert other not in payload["files"]


def test_bundle_is_signed_by_the_owner_key_shown_on_the_page(owner, reviewer):
    fid = add_file(owner)
    r = create_from_preview(owner, preview(owner, [fid], reviewer[2], future()))
    payload = json.loads(r.content)["payload"]
    shown = re.search(r"signing-key fingerprint: <b>([0-9a-f:]+)</b>", owner.get("/share").text).group(1)
    assert bnd.fingerprint(bytes.fromhex(payload["owner_pub"])) == shown


def test_share_is_logged_without_the_key(owner, reviewer):
    fid = add_file(owner)
    create_from_preview(owner, preview(owner, [fid], reviewer[2], future()))
    e = [x for x in entries() if x["action"] == "share"]
    assert len(e) == 1 and e[0]["actor"] == "owner"
    assert e[0]["details"]["files"] == [fid]
    assert e[0]["details"]["reviewer_fp"] == ks.fingerprint(reviewer[1])
    assert "BEGIN PUBLIC KEY" not in str(entries())


def test_tampered_bundle_expired_bundle_and_wrong_reviewer_are_rejected(owner, reviewer):
    fid = add_file(owner)
    bundle = json.loads(create_from_preview(owner, preview(owner, [fid], reviewer[2], future())).content)
    fp = ks.fingerprint(reviewer[1])
    later = datetime.now(timezone.utc) + timedelta(days=30)
    with pytest.raises(bnd.ExpiredBundleError):
        bnd.verify_bundle(bundle, reviewer_fp=fp, now=later)
    with pytest.raises(bnd.WrongReviewerError):
        bnd.verify_bundle(bundle, reviewer_fp="0000:0000:0000:0000")
    bundle["payload"]["expires"] = "2099-01-01T00:00:00+00:00"
    with pytest.raises(bnd.BadSignatureError):
        bnd.verify_bundle(bundle, reviewer_fp=fp)


def test_cannot_share_on_a_tampered_log(app, owner, reviewer):
    fid = add_file(owner)
    conn = db.connect()
    with conn:
        conn.execute("DROP TRIGGER audit_log_no_delete")
        conn.execute("DELETE FROM audit_log WHERE seq = (SELECT MAX(seq) FROM audit_log)")
    conn.close()
    r = create_from_preview(owner, preview(owner, [fid], reviewer[2], future()))
    assert r.status_code == 503 and "audit log failed" in r.text


# ---------------------------------------------------------------- audit viewer

def test_audit_requires_login_and_owner(app, rana):
    assert TestClient(app, follow_redirects=False).get("/audit").headers["location"] == "/login"
    assert rana.get("/audit").status_code == 403
    assert ("rana", "denied:audit_show") in [(e["actor"], e["action"]) for e in entries()]


def test_audit_page_shows_entries_and_intact_banner(owner, rana):
    add_file(rana)
    r = owner.get("/audit")
    assert r.status_code == 200
    assert "Audit log intact" in r.text
    assert "add_file" in r.text and "rana" in r.text and "login" in r.text


def test_viewing_the_log_is_itself_logged(owner):
    owner.get("/audit")
    assert any(e["action"] == "audit_show" and e["details"] == {"limit": 100} for e in entries())


def test_denied_and_failed_rows_are_highlighted(owner, rana):
    rana.get("/lookup")
    assert 'style="color:#a00"' in owner.get("/audit").text


def test_limit_parameter(owner):
    for _ in range(5):
        owner.get("/audit")                 # viewing the log is logged, so this makes entries
    assert "Showing the newest 2 " in owner.get("/audit?limit=2").text
    assert "Showing the newest" in owner.get("/audit?limit=abc").text      # falls back, no error
    assert owner.get("/audit?limit=999999").status_code == 200


def test_tampering_is_shown_in_red_and_the_page_still_works(owner):
    for _ in range(3):
        add_file(owner)
    conn = db.connect()
    with conn:
        conn.execute("DROP TRIGGER audit_log_no_update")
        conn.execute("UPDATE audit_log SET actor = 'intruder' WHERE seq = 2")
    conn.close()
    r = owner.get("/audit")
    assert r.status_code == 200
    assert "TAMPERING DETECTED" in r.text and "entry 2 was modified" in r.text
    assert "intruder" in r.text                                             # the evidence is still shown


def test_audit_viewer_escapes_everything(owner):
    conn = db.connect()
    key = audit.derive_audit_key(vc.unlock(OWNER_PW, db.load_header(conn)))
    audit.append_event(conn, key, XSS, "add_file", "F-0011223344556677", {"x": XSS})
    conn.close()
    r = owner.get("/audit")
    assert XSS not in r.text and "&lt;script&gt;" in r.text


def test_nav_shows_share_and_audit_only_to_the_owner(owner, rana):
    assert 'href="/share"' in owner.get("/").text and 'href="/audit"' in owner.get("/").text
    assert 'href="/share"' not in rana.get("/").text and 'href="/audit"' not in rana.get("/").text