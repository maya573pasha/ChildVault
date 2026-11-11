"""
guard.py - role checks and audit logging for the web routes (Laiba, Phase 3).

Same permission table and the same audited() wrapper the CLI uses (access.py),
so the two front ends cannot disagree about who may do what.

  permit("revoke", "...")   FastAPI dependency: 403 + a "denied:revoke" log entry
  allowed(session, "...")   same check for routes that build their own error page
  audited_session(...)      `with` block: permission + operation + audit entry,
                            gives you (connection, event)
"""

import sqlite3
from contextlib import contextmanager

from fastapi import Depends, HTTPException

from .. import access, audit, db
from ..ops import FILE_ID_RE
from .auth import Session, require_login

AUDIT_BROKEN_MESSAGE = ("The audit log failed its integrity check, so the vault refuses to "
                        "change anything. Run `childvault verify` for details.")


def actor_of(session: Session) -> access.Actor:
    return access.Actor(session.username or session.role, session.role)


def safe_file_id(file_id: str) -> str | None:
    """Only well-formed IDs go into the log (a URL can contain anything)."""
    return file_id if FILE_ID_RE.match(file_id) else None


def _log_denied(session: Session, action: str) -> None:
    conn = db.connect()
    try:
        audit.append_event(conn, audit.derive_audit_key(session.kek),
                           actor_of(session).name, f"denied:{action}")
    except (audit.AuditError, sqlite3.Error):
        pass                      # a broken log cannot take more entries; the request is refused anyway
    finally:
        conn.close()


def allowed(session: Session, action: str) -> bool:
    """True if the session's role may do `action`; otherwise logs the denial and returns False."""
    if access.is_allowed(session.role, action):
        return True
    _log_denied(session, action)
    return False


def permit(action: str, message: str):
    """Dependency factory: the logged-in user must be allowed to `action`, else 403."""
    def dependency(session: Session = Depends(require_login)) -> Session:
        if not allowed(session, action):
            raise HTTPException(status_code=403, detail=message)
        return session
    return dependency


@contextmanager
def audited_session(session: Session, action: str, file_id: str | None = None,
                    details: dict | None = None, strict: bool = True):
    """
    with audited_session(session, "open_file", file_id=fid) as (conn, ev):
        ...

    Raises access.PermissionDenied or audit.AuditError (tampered log) BEFORE the
    operation runs. The connection is closed when the block ends.
    """
    conn = db.connect()
    try:
        with access.audited(conn, audit.derive_audit_key(session.kek), actor_of(session),
                            action, file_id, details, strict=strict) as ev:
            yield conn, ev
    finally:
        conn.close()