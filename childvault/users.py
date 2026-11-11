"""
users.py - researcher accounts with their own passphrase (Laiba, Phase 3).

Problem: if the vault has ONE passphrase, everyone who knows it is the owner,
so "researcher" could never be a different role. Solution: key slots (the
idea LUKS uses for disk encryption). Each researcher gets a personal passphrase;
it derives a key that wraps THE SAME KEK:

    researcher passphrase --scrypt--> user key --wraps--> KEK   (stored in vault_meta)

Logging in as `rana` unwraps the KEK from rana's slot. The owner logs in with
the original vault passphrase, exactly as before. The role is bound into the
wrapped KEK as authenticated data, so editing "researcher" to "owner" in the
database makes the slot fail to open.

Honest limits (put them in the report):
  * A researcher holds the KEK while logged in. The researcher role is a
    SOFTWARE policy (access.py), not cryptographic separation. A researcher who
    modifies the program could read the identity map. The proposal already
    states this "honest client" limit.
  * Removing a researcher deletes their slot but does not change the KEK. For a
    real compromise, re-encrypt (revoke) the files and make a new vault.
  * REVIEWERS NEVER GET AN ACCOUNT. A slot hands out the KEK, which would
    destroy the one role that is enforced by cryptography. Reviewers only ever
    hold a share bundle and their own private key.
"""

import json
import os
import re
import sqlite3

from . import db
from . import vault_crypto as vc
from .access import Actor, Role

OWNER_NAME = "owner"
USER_PREFIX = "user:"
MIN_PASSPHRASE_LEN = 8
_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{2,31}$")
_DUMMY_SALT = b"\x00" * vc.SALT_LEN


class UserError(Exception):
    """Bad user name, duplicate user, unknown user, or a role that is not allowed."""


def _label(name: str, role: str) -> str:
    # Used as the "file ID" of vc.wrap_key, i.e. bound in as authenticated data.
    return f"user-slot:{name}:{role}"


def check_name(name: str) -> str:
    if not _NAME_RE.match(name) or name == OWNER_NAME:
        raise UserError("user name must be 3-32 characters: lowercase letters, digits, - or _, "
                        "starting with a letter ('owner' is reserved)")
    return name


def create_user(conn: sqlite3.Connection, kek: bytes, name: str, passphrase: str,
                role: Role = Role.RESEARCHER, params: dict | None = None) -> None:
    """Create a researcher account whose personal passphrase unlocks the vault KEK."""
    if Role(role) is not Role.RESEARCHER:
        raise UserError("only researcher accounts can be created; reviewers never get vault access")
    check_name(name)
    if len(passphrase) < MIN_PASSPHRASE_LEN:
        raise UserError(f"passphrase must be at least {MIN_PASSPHRASE_LEN} characters")

    p = dict(params or vc.DEFAULT_SCRYPT_PARAMS)
    salt = os.urandom(vc.SALT_LEN)
    slot_key = vc.derive_kek(passphrase, salt, p)
    record = {
        "role": Role.RESEARCHER.value,
        "salt": salt.hex(),
        "scrypt": p,
        "wrapped_kek": vc.wrap_key(slot_key, kek, _label(name, Role.RESEARCHER.value)).hex(),
        "created_at": db.utc_now(),
    }
    try:
        with conn:
            conn.execute("INSERT INTO vault_meta (key, value) VALUES (?, ?)",
                         (USER_PREFIX + name, json.dumps(record)))
    except sqlite3.IntegrityError:
        raise UserError(f"user '{name}' already exists") from None


def remove_user(conn: sqlite3.Connection, name: str) -> None:
    with conn:
        cur = conn.execute("DELETE FROM vault_meta WHERE key = ?", (USER_PREFIX + name,))
    if cur.rowcount != 1:
        raise UserError(f"no user named '{name}'")


def list_users(conn: sqlite3.Connection) -> list[tuple[str, str]]:
    """[(name, role)] for every researcher account, sorted by name."""
    rows = conn.execute("SELECT key, value FROM vault_meta WHERE key LIKE ?",
                        (USER_PREFIX + "%",)).fetchall()
    out = []
    for r in rows:
        try:
            out.append((r["key"][len(USER_PREFIX):], json.loads(r["value"])["role"]))
        except (ValueError, KeyError, TypeError):
            continue
    return sorted(out)


def authenticate(conn: sqlite3.Connection, username: str, passphrase: str,
                 header: dict | None = None) -> tuple[bytes, Actor]:
    """
    Log in. Returns (kek, Actor). Raises vault_crypto.WrongPassphraseError for ANY
    failure (unknown user, wrong passphrase, damaged slot) - no hint which one.
    """
    if username == OWNER_NAME:
        kek = vc.unlock(passphrase, header if header is not None else db.load_header(conn))
        return kek, Actor.owner()

    fail = vc.WrongPassphraseError("wrong passphrase")
    row = None
    if _NAME_RE.match(username):
        row = conn.execute("SELECT value FROM vault_meta WHERE key = ?",
                           (USER_PREFIX + username,)).fetchone()
    if row is None or not passphrase:
        if passphrase:                       # spend the same time as a real login
            vc.derive_kek(passphrase, _DUMMY_SALT, vc.DEFAULT_SCRYPT_PARAMS)
        raise fail
    try:
        rec = json.loads(row["value"])
        slot_key = vc.derive_kek(passphrase, bytes.fromhex(rec["salt"]), rec["scrypt"])
        kek = vc.unwrap_key(slot_key, bytes.fromhex(rec["wrapped_kek"]), _label(username, rec["role"]))
        role = Role(rec["role"])
    except (vc.KeyUnwrapError, ValueError, KeyError, TypeError):
        raise fail from None
    if role is not Role.RESEARCHER:          # defence in depth: slots only ever hold researchers
        raise fail
    return kek, Actor(username, role)