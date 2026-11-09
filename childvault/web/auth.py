"""
auth.py - log in to the web UI by unlocking the vault (Mariyam, Phase 4).

How a session works:
  1. The user POSTs the vault passphrase to /login.
  2. The server derives the KEK (scrypt) and keeps it IN SERVER MEMORY,
     inside a Session object, under a long random token.
  3. The browser only receives that token, in a cookie that is
       HttpOnly        - page scripts cannot read it
       SameSite=Strict - other websites cannot make the browser send it
  4. Every request looks the token up. Idle too long -> session deleted.
  5. /logout deletes the session, so the KEK is dropped from memory.

The passphrase and the KEK never go into a cookie, URL, page or log.
"""

import secrets
import time
from dataclasses import dataclass, field

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .. import config, db
from .. import vault_crypto as vc
from .html import esc, layout

COOKIE_NAME = "cv_session"
IDLE_TIMEOUT = 15 * 60          # seconds without activity before logout
MAX_FAILED_LOGINS = 5           # then the login form is locked for a while
LOCKOUT_SECONDS = 60

# Until Laiba's role system exists (Phase 3), whoever knows the vault
# passphrase is the owner. Her permission checks replace this.
DEFAULT_ROLE = "owner"


# --------------------------------------------------------------------------
# Server-side session store
# --------------------------------------------------------------------------

@dataclass
class Session:
    kek: bytes = field(repr=False)      # repr=False: never printed in logs / debug output
    role: str
    last_seen: float


class SessionStore:
    """Sessions live only in this process's memory: restarting the server logs everyone out."""

    def __init__(self, idle_timeout: float = IDLE_TIMEOUT, clock=time.monotonic):
        self._sessions: dict[str, Session] = {}
        self.idle_timeout = idle_timeout
        self.clock = clock               # replaceable in tests to "fast-forward" time

    def create(self, kek: bytes, role: str) -> str:
        token = secrets.token_urlsafe(32)          # 256 random bits, unguessable
        self._sessions[token] = Session(kek=kek, role=role, last_seen=self.clock())
        return token

    def get(self, token: str | None) -> Session | None:
        if not token:
            return None
        s = self._sessions.get(token)
        if s is None:
            return None
        now = self.clock()
        if now - s.last_seen > self.idle_timeout:
            del self._sessions[token]               # expired: forget the KEK
            return None
        s.last_seen = now
        return s

    def delete(self, token: str | None) -> None:
        if token:
            self._sessions.pop(token, None)

    def __len__(self) -> int:
        return len(self._sessions)


class LoginLimiter:
    """After too many wrong passphrases, refuse logins for a short time (slows guessing)."""

    def __init__(self, clock=time.monotonic):
        self.failures = 0
        self.locked_until = 0.0
        self.clock = clock

    def is_locked(self) -> bool:
        return self.clock() < self.locked_until

    def record_failure(self) -> None:
        self.failures += 1
        if self.failures >= MAX_FAILED_LOGINS:
            self.locked_until = self.clock() + LOCKOUT_SECONDS
            self.failures = 0

    def record_success(self) -> None:
        self.failures = 0


# --------------------------------------------------------------------------
# Helpers other pages use
# --------------------------------------------------------------------------

def current_session(request: Request) -> Session | None:
    return request.app.state.sessions.get(request.cookies.get(COOKIE_NAME))


def require_login(request: Request) -> Session:
    """FastAPI dependency: the page needs a logged-in user, else go to /login."""
    s = current_session(request)
    if s is None:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return s


def _derive_kek(passphrase: str) -> bytes | None:
    """Unlock the vault; None for ANY failure (no hint about what was wrong)."""
    if not config.get_db_path().is_file():
        return None
    conn = db.connect()
    try:
        return vc.unlock(passphrase, db.load_header(conn))
    except (db.VaultDBError, vc.VaultCryptoError, ValueError):
        return None
    finally:
        conn.close()


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------

router = APIRouter()

_LOGIN_FORM = """
<form method="post" action="/login">
  <label>Vault passphrase<br>
    <input type="password" name="passphrase" autocomplete="off" required autofocus>
  </label>
  <button type="submit">Unlock</button>
</form>
"""


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if current_session(request):
        return RedirectResponse("/", status_code=303)
    return layout("Log in", _LOGIN_FORM)


@router.post("/login", response_class=HTMLResponse)
def login(request: Request, passphrase: str = Form(...)):
    limiter: LoginLimiter = request.app.state.login_limiter
    if limiter.is_locked():
        body = f'<p class="error">{esc("Too many wrong attempts. Wait a minute and try again.")}</p>'
        return HTMLResponse(layout("Log in", body + _LOGIN_FORM), status_code=429)

    kek = _derive_kek(passphrase)
    if kek is None:
        limiter.record_failure()
        body = f'<p class="error">{esc("Wrong passphrase.")}</p>'
        return HTMLResponse(layout("Log in", body + _LOGIN_FORM), status_code=401)

    limiter.record_success()
    # Always a NEW token at login (prevents "session fixation").
    old = request.cookies.get(COOKIE_NAME)
    request.app.state.sessions.delete(old)
    token = request.app.state.sessions.create(kek, DEFAULT_ROLE)

    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        COOKIE_NAME, token,
        httponly=True, samesite="strict", path="/",
        # secure=True would require HTTPS; this UI only runs on http://127.0.0.1
    )
    return response


@router.post("/logout")
def logout(request: Request):
    request.app.state.sessions.delete(request.cookies.get(COOKIE_NAME))
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(COOKIE_NAME, path="/")
    return response
