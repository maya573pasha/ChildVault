"""
lookup.py - pseudonym lookup page (Mariyam, Phase 4).

Owner types a child ID (CH-4F7A) and sees the real name plus that
child's files. Uses the KEK from the logged-in session.

  * POST, not GET: the ID being looked up never appears in the URL,
    browser history or bookmarks.
  * Every value shown (name, IDs, errors) goes through esc().
  * Owner only. Laiba's role system will decide who counts as owner.
"""

from fastapi import APIRouter, Depends, Form
from fastapi.responses import HTMLResponse

from .. import config, db
from .. import identity as idm
from .auth import Session, require_login
from .html import esc, layout

router = APIRouter()

ALLOWED_ROLES = {"owner"}

_FORM = """
<form method="post" action="/lookup">
  <label>Child ID<br>
    <input type="text" name="child_id" placeholder="CH-4F7A" autocomplete="off" required autofocus>
  </label>
  <button type="submit">Look up</button>
</form>
"""


def _page(session: Session, body: str = "", status: int = 200) -> HTMLResponse:
    return HTMLResponse(layout("Pseudonym lookup", body + _FORM, user_role=session.role),
                        status_code=status)


def _error(session: Session, message: str, status: int) -> HTMLResponse:
    return _page(session, f'<p class="error">{esc(message)}</p>', status)


@router.get("/lookup", response_class=HTMLResponse)
def lookup_form(session: Session = Depends(require_login)):
    if session.role not in ALLOWED_ROLES:
        return _error(session, "Only the vault owner can see real names.", 403)
    return _page(session)


@router.post("/lookup", response_class=HTMLResponse)
def lookup(child_id: str = Form(...), session: Session = Depends(require_login)):
    if session.role not in ALLOWED_ROLES:
        return _error(session, "Only the vault owner can see real names.", 403)

    try:
        cid = idm.normalize_child_id(child_id)
    except idm.InvalidChildIDError as exc:
        return _error(session, str(exc), 400)

    try:
        imap = idm.load_map(session.kek, config.get_identity_map_path())
    except idm.MapMissingError:
        return _error(session, "The identity map is missing - it may have been deleted.", 500)
    except idm.MapIntegrityError:
        return _error(session, "The identity map failed its integrity check - it was modified or damaged.", 500)

    try:
        name = imap.lookup(cid)
    except idm.UnknownChildIDError:
        return _error(session, f"No child with ID {cid}.", 404)

    conn = db.connect()
    try:
        files = db.list_files(conn, cid)
    finally:
        conn.close()

    rows = "".join(
        f"<tr><td>{esc(f['file_id'])}</td><td>{esc(f['file_type'])}</td>"
        f"<td>{esc(f['extension'])}</td><td>{esc(f['added_at'])}</td></tr>"
        for f in files
    ) or '<tr><td colspan="4">No files for this child yet.</td></tr>'

    body = (
        f'<p class="ok"><b>{esc(cid)}</b> &rarr; <b>{esc(name)}</b></p>'
        "<h3>Files</h3>"
        "<table><tr><th>File ID</th><th>Type</th><th>Ext</th><th>Added (UTC)</th></tr>"
        f"{rows}</table>"
    )
    return _page(session, body)
