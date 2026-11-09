"""
db.py - SQLite storage for ChildVault.

Tables (added one at a time):
  vault_meta   key/value settings for the whole vault, incl. the vault header
  files        (next step) one row per encrypted file
  audit_log    (later step) hash-chained record of every action

Nothing secret is stored in plaintext here: the vault header holds only the
salt, scrypt parameters and a check value, which are safe to be seen.
"""

import json
import sqlite3
from pathlib import Path

from . import config

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS vault_meta (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);
"""

HEADER_KEY = "vault_header"


class VaultDBError(Exception):
    """Base class for database errors."""


class VaultNotInitializedError(VaultDBError):
    """No vault header found - run `childvault init` first."""


class VaultAlreadyInitializedError(VaultDBError):
    """A vault header already exists; refusing to overwrite it."""


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
