import pytest
from fastapi import Depends
from fastapi.testclient import TestClient

from childvault import config, db
from childvault import vault_crypto as vc
from childvault.web import auth
from childvault.web.app import create_app

FAST = {"n": 2 ** 10, "r": 8, "p": 1}
PW = "web test passphrase"


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture
def vault(monkeypatch, tmp_path):
    monkeypatch.setenv(config.ENV_VAR, str(tmp_path / "vault"))
    config.ensure_vault_dirs()
    conn = db.connect()
    db.create_schema(conn)
    db.save_header(conn, vc.new_vault_header(PW, FAST))
    conn.close()


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def app(vault, clock):
    a = create_app(auth.SessionStore(clock=clock), auth.LoginLimiter(clock=clock))

    @a.get("/test-protected")
    def protected(s: auth.Session = Depends(auth.require_login)):
        return {"role": s.role}

    return a


@pytest.fixture
def client(app):
    return TestClient(app, follow_redirects=False)


def _login(client, pw=PW):
    return client.post("/login", data={"passphrase": pw})


# ---------------------------------------------------------------- login

def test_login_page_has_password_field(client):
    r = client.get("/login")
    assert r.status_code == 200
    assert 'type="password"' in r.text and 'method="post"' in r.text


def test_correct_passphrase_logs_in(client, app):
    r = _login(client)
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert len(app.state.sessions) == 1
    assert "Vault unlocked" in client.get("/").text


def test_cookie_flags(client):
    cookie = _login(client).headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "samesite=strict" in cookie
    assert "path=/" in cookie


def test_cookie_holds_only_a_random_token(client, app):
    """The KEK and passphrase must never reach the browser."""
    r = _login(client)
    token = client.cookies.get(auth.COOKIE_NAME)
    session = app.state.sessions.get(token)
    assert len(token) >= 40
    for secret in (PW, session.kek.hex(), session.kek.decode("latin-1")):
        assert secret not in r.headers["set-cookie"]
        assert secret not in r.text


def test_wrong_passphrase(client, app):
    r = _login(client, "wrong passphrase")
    assert r.status_code == 401
    assert "Wrong passphrase" in r.text
    assert "wrong passphrase" not in r.text      # the typed value is not echoed back
    assert len(app.state.sessions) == 0
    assert "set-cookie" not in r.headers


def test_passphrase_never_in_url_or_page(client):
    r = client.get("/login")
    assert "passphrase=" not in r.text           # GET form would put it in the URL


def test_new_token_every_login(client):
    _login(client)
    first = client.cookies.get(auth.COOKIE_NAME)
    _login(client)
    second = client.cookies.get(auth.COOKIE_NAME)
    assert first != second


def test_relogin_drops_old_session(client, app):
    _login(client)
    _login(client)
    assert len(app.state.sessions) == 1


def test_login_without_vault(monkeypatch, tmp_path, clock):
    monkeypatch.setenv(config.ENV_VAR, str(tmp_path / "none"))
    c = TestClient(create_app(auth.SessionStore(clock=clock)), follow_redirects=False)
    assert _login(c).status_code == 401
    assert not (tmp_path / "none").exists()      # no empty DB created


# ---------------------------------------------------------------- protected pages

def test_protected_page_redirects_when_logged_out(client):
    r = client.get("/test-protected")
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_protected_page_works_when_logged_in(client):
    _login(client)
    assert client.get("/test-protected").json() == {"role": "owner"}


def test_forged_cookie_rejected(client):
    client.cookies.set(auth.COOKIE_NAME, "made-up-token")
    assert client.get("/test-protected").status_code == 303


# ---------------------------------------------------------------- logout / timeout

def test_logout_ends_session(client, app):
    _login(client)
    token = client.cookies.get(auth.COOKIE_NAME)
    r = client.post("/logout")
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert len(app.state.sessions) == 0
    client.cookies.set(auth.COOKIE_NAME, token)            # replaying the old cookie
    assert client.get("/test-protected").status_code == 303


def test_logout_is_post_only(client):
    assert client.get("/logout").status_code == 405


def test_idle_timeout(client, clock, app):
    _login(client)
    clock.t += auth.IDLE_TIMEOUT - 1
    assert client.get("/test-protected").status_code == 200   # activity resets the timer
    clock.t += auth.IDLE_TIMEOUT - 1
    assert client.get("/test-protected").status_code == 200
    clock.t += auth.IDLE_TIMEOUT + 1
    assert client.get("/test-protected").status_code == 303
    assert len(app.state.sessions) == 0                         # KEK forgotten


# ---------------------------------------------------------------- brute force

def test_lockout_after_repeated_failures(client, clock):
    for _ in range(auth.MAX_FAILED_LOGINS):
        assert _login(client, "nope nope").status_code == 401
    r = _login(client)                                    # even the RIGHT passphrase
    assert r.status_code == 429
    clock.t += auth.LOCKOUT_SECONDS + 1
    assert _login(client).status_code == 303              # works again after the wait


def test_success_resets_failure_count(client):
    for _ in range(auth.MAX_FAILED_LOGINS - 1):
        _login(client, "nope nope")
    assert _login(client).status_code == 303
    for _ in range(auth.MAX_FAILED_LOGINS - 1):
        _login(client, "nope nope")
    assert _login(client).status_code == 303              # not locked


# ---------------------------------------------------------------- unit: Session repr

def test_session_repr_hides_kek():
    s = auth.Session(kek=b"\x01" * 32, role="owner", last_seen=0)
    assert "kek" not in repr(s) and "\\x01" not in repr(s)


def test_create_app_keeps_the_given_empty_store():
    """Regression test: an empty store is falsy (len 0) but must still be used."""
    store = auth.SessionStore()
    assert create_app(store).state.sessions is store
