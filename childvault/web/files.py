"""
files.py - upload / open / revoke page ( Phase 4).

    GET  /files                 list of files + upload form
    POST /files/upload          encrypt an uploaded file into the vault
    POST /files/{id}/open       decrypt and download one file
    GET  /files/{id}/revoke     "are you sure?" page
    POST /files/{id}/revoke     re-encrypt the file under a new key

The real work is in ops.py (shared with the CLI). This module only does
HTTP: login check, role check, size limit, and showing results safely.

Security notes
  * Owner only (Laiba's role system decides later who counts as owner).
  * Everything shown goes through esc(). The uploaded file's NAME is never
    stored or shown - it can contain a child's name. Only a plain
    letters/digits extension is kept.
  * Actions are POST. The session cookie is SameSite=Strict, so other sites
    cannot make the browser send it; no state change happens on GET.
  * The upload size is checked from Content-Length BEFORE the body is read.
  * Downloads are sent as application/octet-stream + attachment, so the
    browser saves them instead of running them.
  * Decrypted temp files are deleted right after the response is sent.
"""

import shutil
import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse
from starlette.background import BackgroundTask

from .. import config, db, ops
from .auth import Session, require_login
from .html import esc, layout

router = APIRouter()

ALLOWED_ROLES = {"owner"}
MAX_UPLOAD_BYTES = 500 * 1024 * 1024        # 500 MiB per file
_STATUS = {ops.InvalidInputError: 400, ops.NotFoundError: 404, ops.VaultFileError: 500}


def owner_only(session: Session = Depends(require_login)) -> Session:
    if session.role not in ALLOWED_ROLES:
        raise HTTPException(status_code=403, detail="Only the vault owner can manage files.")
    return session


def limit_upload_size(request: Request) -> None:
    """Refuse a too-large upload from its Content-Length, before reading the body."""
    try:
        length = int(request.headers.get("content-length", "0"))
    except ValueError:
        raise HTTPException(status_code=400, detail="Bad Content-Length.") from None
    if length > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File is too large (limit 500 MiB).")


# --------------------------------------------------------------------------
# Page building
# --------------------------------------------------------------------------

def _upload_form() -> str:
    options = "".join(f'<option value="{esc(t)}">{esc(t)}</option>' for t in db.FILE_TYPES)
    return (
        "<h3>Add a file</h3>"
        '<form method="post" action="/files/upload" enctype="multipart/form-data">'
        '<p><label>File<br><input type="file" name="file" required></label></p>'
        f'<p><label>Type<br><select name="file_type">{options}</select></label></p>'
        '<p><label>Child ID (optional)<br>'
        '<input type="text" name="child_id" placeholder="CH-4F7A" autocomplete="off"></label></p>'
        '<button type="submit">Encrypt and add</button>'
        "</form>"
    )


def _file_table() -> str:
    conn = db.connect()
    try:
        files = db.list_files(conn)
    finally:
        conn.close()
    rows = "".join(
        "<tr>"
        f"<td>{esc(f['file_id'])}</td><td>{esc(f['child_id'] or '-')}</td>"
        f"<td>{esc(f['file_type'])}</td><td>{esc(f['extension'] or '-')}</td>"
        f"<td>{esc(f['plaintext_size'] if f['plaintext_size'] is not None else '-')}</td>"
        f"<td>v{esc(f['key_version'])}</td><td>{esc(f['added_at'])}</td>"
        f'<td><form method="post" action="/files/{esc(f["file_id"])}/open" style="display:inline;margin:0">'
        '<button type="submit">Open</button></form> '
        f'<a href="/files/{esc(f["file_id"])}/revoke">Revoke</a></td>'
        "</tr>"
        for f in files
    ) or '<tr><td colspan="8">No files in the vault yet.</td></tr>'
    return (
        "<h3>Files</h3><table>"
        "<tr><th>File ID</th><th>Child</th><th>Type</th><th>Ext</th><th>Bytes</th>"
        f"<th>Key</th><th>Added (UTC)</th><th></th></tr>{rows}</table>"
    )


def _page(session: Session, message: str = "", status: int = 200, ok: bool = False) -> HTMLResponse:
    box = ""
    if message:
        box = f'<p class="{"ok" if ok else "error"}">{esc(message)}</p>'
    return HTMLResponse(
        layout("Files", box + _upload_form() + _file_table(), user_role=session.role),
        status_code=status,
    )


def _error_page(session: Session, exc: ops.OpsError) -> HTMLResponse:
    return _page(session, str(exc), _STATUS.get(type(exc), 400))


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------

@router.get("/files", response_class=HTMLResponse)
def files_page(session: Session = Depends(owner_only)):
    return _page(session)


@router.post("/files/upload", response_class=HTMLResponse, dependencies=[Depends(limit_upload_size)])
def upload(
    file: UploadFile = File(...),
    file_type: str = Form("other"),
    child_id: str = Form(""),
    session: Session = Depends(owner_only),
):
    if file_type not in db.FILE_TYPES:
        return _page(session, f"Type must be one of: {', '.join(db.FILE_TYPES)}.", 400)

    # The encryptor reads from a path, so spool the upload to a short-lived temp file.
    config.get_files_dir().mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".upload-", dir=config.get_files_dir())
    tmp = Path(tmp_name)
    conn = db.connect()
    try:
        with open(fd, "wb") as dst:
            shutil.copyfileobj(file.file, dst)
        file_id = ops.add_file(
            conn, session.kek, tmp, file_type, child_id.strip() or None,
            ops.safe_extension(file.filename or ""),
        )
    except ops.OpsError as exc:
        return _error_page(session, exc)
    finally:
        conn.close()
        tmp.unlink(missing_ok=True)
    return _page(session, f"Added {file_id}.", ok=True)


@router.post("/files/{file_id}/open")
def open_file(file_id: str, session: Session = Depends(owner_only)):
    workdir = Path(tempfile.mkdtemp(prefix=".open-", dir=config.get_files_dir()))
    out = workdir / "plain"
    cleanup = BackgroundTask(shutil.rmtree, workdir, ignore_errors=True)
    conn = db.connect()
    try:
        ops.open_file(conn, session.kek, file_id, out)
        row = db.get_file(conn, file_id)
    except ops.OpsError as exc:
        shutil.rmtree(workdir, ignore_errors=True)
        return _error_page(session, exc)
    finally:
        conn.close()

    name = file_id + (f".{row['extension']}" if row["extension"] else "")
    return FileResponse(
        out, media_type="application/octet-stream", filename=name, background=cleanup,
    )


@router.get("/files/{file_id}/revoke", response_class=HTMLResponse)
def revoke_confirm(file_id: str, session: Session = Depends(owner_only)):
    try:
        ops.check_file_id(file_id)
    except ops.OpsError as exc:
        return _error_page(session, exc)
    body = (
        f"<p>Re-encrypt <b>{esc(file_id)}</b> under a new key? Share bundles that "
        "already exist for this file will stop working on the vault copy.</p>"
        "<p>A reviewer who already saved the old encrypted file can still read that copy.</p>"
        f'<form method="post" action="/files/{esc(file_id)}/revoke">'
        '<button type="submit">Yes, revoke</button> <a href="/files">Cancel</a></form>'
    )
    return HTMLResponse(layout("Revoke access", body, user_role=session.role))


@router.post("/files/{file_id}/revoke", response_class=HTMLResponse)
def revoke(file_id: str, session: Session = Depends(owner_only)):
    conn = db.connect()
    try:
        version = ops.revoke_file(conn, session.kek, file_id)
    except ops.OpsError as exc:
        return _error_page(session, exc)
    finally:
        conn.close()
    return _page(session, f"Re-encrypted {file_id} under a new key (version {version}).", ok=True)
