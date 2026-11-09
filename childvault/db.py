"""
db.py - SQLite storage for ChildVault.

Tables:
  vault_meta   key/value settings for the whole vault, incl. the vault header
  files        one row per encrypted file (pseudonym only, no names)
  audit_log    hash-chained, append-only record of every action

Nothing secret is stored in plaintext here: the vault header holds only the
salt, scrypt parameters and a check value, which are safe to be seen.
"""

import json
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from . import config
from .vault_crypto import WRAPPED_LEN

SCHEMA_VERSION = 1

FILE_TYPES = ("video", "csv", "annotation", "other")

SCHEMA = f"""
CREATE TABLE IF NOT EXISTS vault_meta (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);

-- One row per encrypted file. Deliberately NO original filename and NO
-- child name: both can identify a child. Only the pseudonym is stored.
CREATE TABLE IF NOT EXISTS files (
    file_id          TEXT PRIMARY KEY,
    child_id         TEXT,
    file_type        TEXT NOT NULL CHECK (file_type IN {FILE_TYPES}),
    extension        TEXT NOT NULL,
    wrapped_key      BLOB NOT NULL CHECK (length(wrapped_key) = {WRAPPED_LEN}),
    key_version      INTEGER NOT NULL DEFAULT 1,
    plaintext_size   INTEGER,
    added_by         TEXT NOT NULL,
    added_at         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_files_child ON files (child_id);

-- Hash-chained audit log. Laiba's audit module computes the hashes;
-- this table only stores them. file_id is NOT a foreign key on purpose:
-- failed attempts on unknown IDs must still be logged.
CREATE TABLE IF NOT EXISTS audit_log (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    file_id     TEXT,
    details     TEXT,
    prev_hash   TEXT NOT NULL CHECK (length(prev_hash) = 64),
    entry_hash  TEXT NOT NULL UNIQUE CHECK (length(entry_hash) = 64)
);

-- Append-only guard against bugs and casual edits through the app.
-- NOT the real protection (anyone with the file can drop these triggers);
-- the hash chain is what actually detects tampering.
CREATE TRIGGER IF NOT EXISTS audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;
"""

# prev_hash of the very first log entry (there is nothing before it).
GENESIS_HASH = "0" * 64

HEADER_KEY = "vault_header"


class VaultDBError(Exception):
    """Base class for database errors."""


class VaultNotInitializedError(VaultDBError):
    """No vault header found - run `childvault init` first."""


class VaultAlreadyInitializedError(VaultDBError):
    """A vault header already exists; refusing to overwrite it."""


class FileNotInVaultError(VaultDBError):
    """No file with that ID is stored in the vault."""


def connect(db_path: str | Path | None = None) -> sqlite3.Connection:
    """Open the vault database (default: config.get_db_path())."""
    path = Path(db_path) if db_path is not None else config.get_db_path()
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row             # rows behave like dicts: row["key"]
    conn.execute("PRAGMA foreign_keys = ON")   # SQLite has these OFF by default
    return conn


def create_schema(conn: sqlite3.Connection) -> None:
    """Create all tables if they don't exist. Safe to call more than once."""
    conn.executescript(SCHEMA)
    with conn:
        conn.execute(
            "INSERT OR IGNORE INTO vault_meta (key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )


def get_meta(conn: sqlite3.Connection, key: str) -> str | None:
    """Read one value from vault_meta, or None if it is not set."""
    row = conn.execute("SELECT value FROM vault_meta WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def save_header(conn: sqlite3.Connection, header: dict) -> None:
    """
    Store the vault header created by vault_crypto.new_vault_header().

    Refuses to overwrite an existing header: replacing it would change the
    salt, so the KEK could never be derived again and every file would be lost.
    """
    try:
        with conn:
            conn.execute(
                "INSERT INTO vault_meta (key, value) VALUES (?, ?)",
                (HEADER_KEY, json.dumps(header)),
            )
    except sqlite3.IntegrityError:
        raise VaultAlreadyInitializedError("vault is already initialized") from None


def load_header(conn: sqlite3.Connection) -> dict:
    """Return the stored vault header, for vault_crypto.unlock()."""
    value = get_meta(conn, HEADER_KEY)
    if value is None:
        raise VaultNotInitializedError("vault not initialized - run `childvault init`")
    return json.loads(value)


def is_initialized(conn: sqlite3.Connection) -> bool:
    return get_meta(conn, HEADER_KEY) is not None


# --------------------------------------------------------------------------
# Helpers shared by several modules
# --------------------------------------------------------------------------

def utc_now() -> str:
    """Current time in UTC as ISO-8601 text, e.g. 2026-11-09T14:28:03+00:00."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_file_id() -> str:
    """Random, meaningless file ID such as F-3f9a1c0b7e2d4a65 (64 random bits)."""
    return "F-" + secrets.token_hex(8)


# --------------------------------------------------------------------------
# files table
# --------------------------------------------------------------------------

def add_file_record(
    conn: sqlite3.Connection,
    file_id: str,
    wrapped_key: bytes,
    file_type: str,
    extension: str,
    added_by: str,
    child_id: str | None = None,
    plaintext_size: int | None = None,
) -> None:
    """Insert metadata for a newly encrypted file. Raises VaultDBError on bad input."""
    if file_type not in FILE_TYPES:
        raise VaultDBError(f"file_type must be one of {FILE_TYPES}")
    try:
        with conn:
            conn.execute(
                """INSERT INTO files (file_id, child_id, file_type, extension, wrapped_key,
                                      plaintext_size, added_by, added_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (file_id, child_id, file_type, extension.lower().lstrip("."),
                 wrapped_key, plaintext_size, added_by, utc_now()),
            )
    except sqlite3.IntegrityError as exc:
        raise VaultDBError(f"could not add file record: {exc}") from None


def get_file(conn: sqlite3.Connection, file_id: str) -> sqlite3.Row:
    """Return the row for one file, or raise FileNotInVaultError."""
    row = conn.execute("SELECT * FROM files WHERE file_id = ?", (file_id,)).fetchone()
    if row is None:
        raise FileNotInVaultError(f"no file with id {file_id}")
    return row


def list_files(conn: sqlite3.Connection, child_id: str | None = None) -> list[sqlite3.Row]:
    """All files, oldest first; optionally only those of one pseudonymous child."""
    if child_id is None:
        return conn.execute("SELECT * FROM files ORDER BY added_at, file_id").fetchall()
    return conn.execute(
        "SELECT * FROM files WHERE child_id = ? ORDER BY added_at, file_id", (child_id,)
    ).fetchall()


# --------------------------------------------------------------------------
# audit_log table (storage only - hashing lives in Laiba's audit module)
# --------------------------------------------------------------------------

def append_audit_row(
    conn: sqlite3.Connection,
    ts: str,
    actor: str,
    action: str,
    prev_hash: str,
    entry_hash: str,
    file_id: str | None = None,
    details: dict | None = None,
) -> int:
    """Insert one log entry and return its sequence number."""
    try:
        with conn:
            cur = conn.execute(
                """INSERT INTO audit_log (ts, actor, action, file_id, details, prev_hash, entry_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (ts, actor, action, file_id,
                 json.dumps(details, sort_keys=True) if details is not None else None,
                 prev_hash, entry_hash),
            )
    except sqlite3.IntegrityError as exc:
        raise VaultDBError(f"could not append audit entry: {exc}") from None
    return cur.lastrowid


def get_audit_rows(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Every log entry in sequence order (for `verify` and `audit show`)."""
    return conn.execute("SELECT * FROM audit_log ORDER BY seq").fetchall()


def get_last_audit_row(conn: sqlite3.Connection) -> sqlite3.Row | None:
    """The newest entry, or None if the log is empty."""
    return conn.execute("SELECT * FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
