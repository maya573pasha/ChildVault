"""
app.py - creates the FastAPI application.

Run it with:   python -m childvault web
It only listens on 127.0.0.1 (this computer), never on the network.
"""

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from . import auth
from .html import layout

# Sent with EVERY response.
SECURITY_HEADERS = {
    # Only load scripts/styles/images from this page itself; inline <style>
    # is allowed for our layout, but no inline or external scripts at all.
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    "X-Frame-Options": "DENY",              # no embedding in other sites (clickjacking)
    "X-Content-Type-Options": "nosniff",    # browser must trust our Content-Type
    "Referrer-Policy": "no-referrer",       # don't leak URLs (e.g. ?child=CH-...) to other sites
    "Cache-Control": "no-store",            # never keep pages with names in the browser cache
}


def create_app(sessions: auth.SessionStore | None = None,
               login_limiter: auth.LoginLimiter | None = None) -> FastAPI:
    app = FastAPI(title="ChildVault", docs_url=None, redoc_url=None, openapi_url=None)
    # "is None", not "or": an EMPTY SessionStore has len 0, so `sessions or ...`
    # would silently throw away the store we were given.
    app.state.sessions = sessions if sessions is not None else auth.SessionStore()
    app.state.login_limiter = login_limiter if login_limiter is not None else auth.LoginLimiter()

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers[name] = value
        return response

    @app.get("/", response_class=HTMLResponse)
    def home(request: Request) -> str:
        s = auth.current_session(request)
        if s is None:
            body = '<p>Encrypted, tamper-evident storage for child-behaviour data.</p><p><a href="/login">Log in</a> to continue.</p>'
            return layout("Home", body)
        return layout("Home", '<p class="ok">Vault unlocked.</p>', user_role=s.role)

    app.include_router(auth.router)
    # Teammates: register your routers here, e.g.
    #   from . import files;  app.include_router(files.router)
    return app
