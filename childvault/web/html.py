"""
html.py - building HTML pages safely.

Every value that comes from a user, a file or the vault (child names,
IDs, error messages) MUST go through esc() before it is put into HTML.
Otherwise a "name" like  <script>...</script>  would run as code in the
browser (cross-site scripting, XSS).
"""

from html import escape


def esc(value) -> str:
    """Escape text for HTML: < > & " ' become harmless entities."""
    return escape(str(value), quote=True)


_STYLE = """
body { font-family: system-ui, sans-serif; max-width: 46rem; margin: 2rem auto; padding: 0 1rem; color: #222; }
header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #ddd; margin-bottom: 1.5rem; }
header a { margin-left: 1rem; }
.error { background: #fde8e8; border: 1px solid #f5b5b5; padding: .6rem .8rem; border-radius: 6px; }
.ok    { background: #e7f6ea; border: 1px solid #a8dcb3; padding: .6rem .8rem; border-radius: 6px; }
form { margin: 1rem 0; }
input[type=text], input[type=password] { padding: .4rem; width: 16rem; }
button { padding: .4rem .9rem; }
table { border-collapse: collapse; } td, th { padding: .3rem .8rem; border-bottom: 1px solid #eee; text-align: left; }
"""


def layout(title: str, body: str, user_role: str | None = None) -> str:
    """
    Wrap a page body in the common layout.
    `title` is escaped here; `body` must already be safe HTML built with esc().
    """
    if user_role:
        nav = (f'<span>Signed in as <b>{esc(user_role)}</b></span>'
               '<nav><a href="/">Home</a><a href="/files">Files</a><a href="/lookup">Lookup</a>'
               '<form method="post" action="/logout" style="display:inline;margin:0 0 0 1rem">'
               '<button type="submit">Log out</button></form></nav>')
    else:
        nav = '<nav><a href="/login">Log in</a></nav>'
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        f"<title>{esc(title)} - ChildVault</title>"
        f"<style>{_STYLE}</style></head><body>"
        f"<header><h2>ChildVault</h2>{nav}</header>"
        f"<main><h1>{esc(title)}</h1>{body}</main>"
        "</body></html>"
    )
