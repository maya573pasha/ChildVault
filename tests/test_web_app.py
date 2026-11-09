from fastapi.testclient import TestClient

from childvault.web.app import SECURITY_HEADERS, create_app
from childvault.web.html import esc, layout

client = TestClient(create_app())


def test_home_page():
    r = client.get("/")
    assert r.status_code == 200
    assert "ChildVault" in r.text
    assert r.headers["content-type"].startswith("text/html")


def test_security_headers_on_every_response():
    for path in ("/", "/does-not-exist"):
        r = client.get(path)
        for name, value in SECURITY_HEADERS.items():
            assert r.headers[name] == value, (path, name)


def test_no_cache_for_pages():
    assert client.get("/").headers["cache-control"] == "no-store"


def test_auto_docs_disabled():
    """FastAPI's /docs and /openapi.json would list every endpoint - turned off."""
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


def test_esc_neutralises_html():
    evil = '<script>alert("x")</script>'
    out = esc(evil)
    assert "<script>" not in out
    assert out == "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;"
    assert esc("O'Brien") == "O&#x27;Brien"


def test_layout_escapes_title_and_role():
    page = layout("<b>t</b>", "<p>body</p>", user_role="<i>owner</i>")
    assert "<b>t</b>" not in page and "&lt;b&gt;t&lt;/b&gt;" in page
    assert "<i>owner</i>" not in page
    assert "<p>body</p>" in page          # body is trusted, already-built HTML


def test_layout_nav_depends_on_login():
    assert "Log in" in layout("t", "")
    assert "Log out" in layout("t", "", user_role="owner")
