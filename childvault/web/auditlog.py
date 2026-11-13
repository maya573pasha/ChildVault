"""
auditlog.py - read-only audit log viewer (Laiba, Phase 4).

    GET /audit            newest entries + a "log intact / TAMPERING DETECTED" banner
    GET /audit?limit=500  how many entries (1-1000, default 100)

  * Owner only (access.PERMISSIONS "audit_show"); others get 403 + "denied:audit_show".
  * Every page load re-verifies the whole hash chain and signed head, and says so.
  * Works on a tampered log on purpose (strict=False) so the owner can see the damage.
  * Everything shown goes through esc(): actor names, file IDs and details come
    from the database and must never run as HTML.
  * GET changes no vault data. (Viewing the log is itself logged, like the CLI.)
"""

import json

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from .. import access, audit
from . import guard
from .auth import Session
from .html import esc, layout

router = APIRouter()
can_view_log = guard.permit("audit_show", "Only the vault owner can read the audit log.")

DEFAULT_LIMIT = 100
MAX_LIMIT = 1000
_BAD = ("denied:", "failed:")


def parse_limit(text: str | None) -> int:
    try:
        n = int(text) if text is not None else DEFAULT_LIMIT
    except ValueError:
        return DEFAULT_LIMIT
    return min(max(n, 1), MAX_LIMIT)


def _banner(result: audit.VerifyResult) -> str:
    if result.ok:
        return f'<p class="ok"><b>Audit log intact.</b> {esc(result.entries)} entries verified (hash chain and signed head).</p>'
    where = f" First bad entry: #{esc(result.broken_at)}." if result.broken_at is not None else ""
    return (f'<p class="error"><b>TAMPERING DETECTED.</b> {esc(result.reason)}.{where} '
            "The vault refuses to change anything until this is investigated.</p>")


def _rows(entries: list[dict]) -> str:
    if not entries:
        return '<tr><td colspan="6">The audit log is empty.</td></tr>'
    out = []
    for e in reversed(entries):                        # newest first
        bad = e["action"].startswith(_BAD)
        style = ' style="color:#a00"' if bad else ""
        details = json.dumps(e["details"], sort_keys=True) if e["details"] else ""
        out.append(
            f"<tr{style}><td>{esc(e['seq'])}</td><td>{esc(e['ts'])}</td><td>{esc(e['actor'])}</td>"
            f"<td>{esc(e['action'])}</td><td>{esc(e['file_id'] or '-')}</td><td>{esc(details)}</td></tr>"
        )
    return "".join(out)


@router.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request, session: Session = Depends(can_view_log)):
    limit = parse_limit(request.query_params.get("limit"))
    try:
        with guard.audited_session(session, "audit_show", details={"limit": limit}, strict=False) as (conn, ev):
            result = audit.verify_chain(conn, audit.derive_audit_key(session.kek))
            entries = audit.show(conn, limit=limit)
    except access.PermissionDenied:
        return HTMLResponse(layout("Audit log", '<p class="error">Not allowed.</p>', user_role=session.role), 403)

    body = (
        _banner(result)
        + f"<p>Showing the newest {esc(len(entries))} of {esc(result.entries)} entries "
        '(<a href="/audit?limit=500">show 500</a>).</p>'
        "<table><tr><th>#</th><th>Time (UTC)</th><th>Actor</th><th>Action</th><th>File</th><th>Details</th></tr>"
        + _rows(entries) + "</table>"
        "<p>Red rows are denied or failed attempts.</p>"
    )
    return HTMLResponse(layout("Audit log", body, user_role=session.role))