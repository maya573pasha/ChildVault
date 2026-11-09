"""
app.py - creates the FastAPI application.

Run it with:   python -m childvault web
It only listens on 127.0.0.1 (this computer), never on the network.
"""

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

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


def create_app() -> FastAPI:
    app = FastAPI(title="ChildVault", docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers[name] = value
        return response

    @app.get("/", response_class=HTMLResponse)
    def home() -> str:
        return layout("Home", "<p>Encrypted, tamper-evident storage for child-behaviour data.</p>")

    # Teammates: register your routers here, e.g.
    #   from . import files;  app.include_router(files.router)
    return app
