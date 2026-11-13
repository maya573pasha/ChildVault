"""
share.py - create a signed, time-limited share bundle for a reviewer (Laiba, Phase 4).

    GET  /share            choose files, paste the reviewer's PUBLIC key, pick an expiry
    POST /share/preview    show the key's fingerprint + a summary to CONFIRM
    POST /share/create     build the bundle and download it as a file

Two steps on purpose: the owner must compare the fingerprint with the one the
reviewer read out (phone / in person), otherwise a swapped public key
(man-in-the-middle) would go unnoticed.

  * Owner only (access.PERMISSIONS "share"). Researchers/reviewers get 403 + a
    "denied:share" log entry.
  * The real work is the same code the CLI uses (keyshare.py, bundle.py).
  * Only the PUBLIC key is pasted here - never a private key or passphrase.
  * Step 2 re-validates everything: nothing from step 1 is trusted.
  * The log entry holds file IDs, the reviewer's key fingerprint and the expiry -
    never the key itself.
"""

import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from fastapi import APIRouter, Depends, Form
from fastapi.responses import HTMLResponse, Response

from .. import access, audit, bundle as bnd, db
from .. import keyshare as ks
from ..ops import FILE_ID_RE
from . import guard
from .auth import Session
from .html import esc, layout

router = APIRouter()
can_share = guard.permit("share", "Only the vault owner can share files.")

MAX_KEY_CHARS = 4096
MAX_FILES = 100
DOWNLOAD_NAME = "childvault-share.json"


class ShareInputError(Exception):
    """Bad form input; the message is safe to show."""


# --------------------------------------------------------------------------
# Input checks
# --------------------------------------------------------------------------

def parse_reviewer_key(text: str) -> X25519PublicKey:
    text = (text or "").strip()
    if not text or len(text) > MAX_KEY_CHARS:
        raise ShareInputError("Paste the reviewer's public key (the text of their .pub file).")
    try:
        key = serialization.load_pem_public_key(text.encode("utf-8"))
    except (ValueError, TypeError):
        raise ShareInputError("That is not a valid public key.") from None
    if not isinstance(key, X25519PublicKey):
        raise ShareInputError("That is not a reviewer key. Ask the reviewer to run `childvault keygen` "
                              "and send the .pub file.")
    return key


def parse_files(file_ids: list[str]) -> list[str]:
    ids = list(dict.fromkeys(file_ids))
    if not ids:
        raise ShareInputError("Choose at least one file to share.")
    if len(ids) > MAX_FILES or not all(FILE_ID_RE.match(i) for i in ids):
        raise ShareInputError("Invalid file selection.")
    return ids


def parse_expiry(text: str):
    try:
        return bnd.parse_expiry((text or "").strip())
    except bnd.BundleError as exc:
        raise ShareInputError(str(exc)) from None


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------

def _owner_fingerprint_note() -> str:
    conn = db.connect()
    try:
        pub = db.get_meta(conn, "owner_signing_pub")
    finally:
        conn.close()
    if pub is None:
        return ("<p>Your signing key does not exist yet; it is created with your first bundle. "
                "You will then see its fingerprint here.</p>")
    return (f"<p>Your signing-key fingerprint: <b>{esc(bnd.fingerprint(bytes.fromhex(pub)))}</b><br>"
            "Tell it to the reviewer by phone or in person; they pin it when importing.</p>")


def _form(session: Session, message: str = "", status: int = 200,
          key_text: str = "", expiry: str = "", selected: tuple = ()) -> HTMLResponse:
    conn = db.connect()
    try:
        rows = db.list_files(conn)
    finally:
        conn.close()
    boxes = "".join(
        f'<p><label><input type="checkbox" name="file_ids" value="{esc(f["file_id"])}"'
        f'{" checked" if f["file_id"] in selected else ""}> '
        f'{esc(f["file_id"])} &nbsp; {esc(f["file_type"])} &nbsp; {esc(f["child_id"] or "-")}</label></p>'
        for f in rows
    ) or "<p>No files in the vault yet.</p>"
    box = f'<p class="error">{esc(message)}</p>' if message else ""
    body = (
        box + _owner_fingerprint_note() +
        '<form method="post" action="/share/preview">'
        f"<h3>1. Files to share</h3>{boxes}"
        "<h3>2. Reviewer's public key</h3>"
        f'<p><textarea name="reviewer_key" rows="6" cols="60" placeholder="-----BEGIN PUBLIC KEY-----">{esc(key_text)}</textarea></p>'
        "<h3>3. Valid until (UTC)</h3>"
        f'<p><input type="text" name="expires" value="{esc(expiry)}" placeholder="2026-12-31"></p>'
        '<button type="submit">Review</button></form>'
    )
    return HTMLResponse(layout("Share files", body, user_role=session.role), status_code=status)


@router.get("/share", response_class=HTMLResponse)
def share_form(session: Session = Depends(can_share)):
    return _form(session)


@router.post("/share/preview", response_class=HTMLResponse)
def share_preview(
    file_ids: list[str] = Form(default=[]),
    reviewer_key: str = Form(""),
    expires: str = Form(""),
    session: Session = Depends(can_share),
):
    try:
        ids = parse_files(file_ids)
        pub = parse_reviewer_key(reviewer_key)
        expiry = parse_expiry(expires)
    except ShareInputError as exc:
        return _form(session, str(exc), 400, reviewer_key, expires, tuple(file_ids))

    hidden = "".join(f'<input type="hidden" name="file_ids" value="{esc(i)}">' for i in ids)
    hidden += f'<input type="hidden" name="reviewer_key_hex" value="{esc(reviewer_key.strip().encode().hex())}">'
    hidden += f'<input type="hidden" name="expires" value="{esc(expires.strip())}">'
    body = (
        f"<p>You are about to share <b>{len(ids)}</b> file(s) with the holder of this key:</p>"
        f'<p class="ok">Reviewer key fingerprint: <b>{esc(ks.fingerprint(pub))}</b></p>'
        "<p>Ask the reviewer to read you the fingerprint of THEIR key "
        "(<code>childvault fingerprint</code>). Only continue if it is exactly the same.</p>"
        f"<p>Valid until: <b>{esc(expiry.isoformat(timespec='seconds'))}</b></p>"
        "<ul>" + "".join(f"<li>{esc(i)}</li>" for i in ids) + "</ul>"
        '<form method="post" action="/share/create">' + hidden +
        '<button type="submit">The fingerprint matches - create bundle</button> '
        '<a href="/share">Cancel</a></form>'
    )
    return HTMLResponse(layout("Confirm sharing", body, user_role=session.role))


@router.post("/share/create")
def share_create(
    file_ids: list[str] = Form(default=[]),
    reviewer_key_hex: str = Form(""),
    expires: str = Form(""),
    session: Session = Depends(can_share),
):
    try:
        ids = parse_files(file_ids)
        try:
            key_text = bytes.fromhex(reviewer_key_hex).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            raise ShareInputError("The key was damaged; start again.") from None
        pub = parse_reviewer_key(key_text)
        expiry = parse_expiry(expires)
    except ShareInputError as exc:
        return _form(session, str(exc), 400, expiry=expires, selected=tuple(file_ids))

    try:
        with guard.audited_session(session, "share") as (conn, ev):
            signing_key = bnd.get_or_create_signing_key(conn, session.kek)
            wrapped = ks.wrap_files_for_reviewer(conn, session.kek, ids, pub)
            bundle = bnd.create_bundle(signing_key, pub, wrapped, expiry)
            ev.details.update({"files": sorted(wrapped), "reviewer_fp": ks.fingerprint(pub),
                               "expires": bundle["payload"]["expires"]})
    except db.FileNotInVaultError as exc:
        return _form(session, str(exc), 404, key_text, expires, tuple(ids))
    except (ks.KeyShareError, bnd.BundleError, db.VaultDBError) as exc:
        return _form(session, str(exc), 400, key_text, expires, tuple(ids))
    except (audit.AuditError, access.PermissionDenied):
        return _form(session, guard.AUDIT_BROKEN_MESSAGE, 503, key_text, expires, tuple(ids))

    return Response(
        json.dumps(bundle, indent=2),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{DOWNLOAD_NAME}"'},
    )