"""
ops.py - the vault operations shared by the CLI and the web UI (Aaleen).

add_file / open_file / revoke_file hold the real logic once, so the two
front ends cannot drift apart. They raise OpsError subclasses with a safe,
human-readable message; the CLI prints it and the web UI shows it (escaped).

Plaintext only ever touches disk in short-lived temp files inside the vault's
files/ folder (or the output path the caller chose). They are deleted, not
securely wiped - the same limit decrypt_file documents.
"""

import os
import re
import sqlite3
import tempfile
from pathlib import Path

from . import config, db
from . import identity as idm
from . import vault_crypto as vc

FILE_ID_RE = re.compile(r"^F-[0-9a-f]{16}$")      # matches db.new_file_id()
_EXT_RE = re.compile(r"^[A-Za-z0-9]{1,10}$")


class OpsError(Exception):
    """Base class: the message is safe to show to the user."""


class InvalidInputError(OpsError):
    """Bad file ID, bad child ID, output already exists, ..."""


class NotFoundError(OpsError):
    """No such file (or child) in the vault."""


class VaultFileError(OpsError):
    """The vault is damaged or the file failed its integrity check."""


def safe_extension(name: str) -> str:
    """Extension from a file name, kept only if plain letters/digits (else '')."""
    ext = Path(name).suffix.lstrip(".")
    return ext.lower() if _EXT_RE.match(ext) else ""


def check_file_id(file_id: str) -> None:
    # Strict format first: the ID becomes part of a path, so no "../".
    if not FILE_ID_RE.match(file_id):
        raise InvalidInputError("invalid file ID")


def _enc_path(file_id: str) -> Path:
    return config.get_files_dir() / f"{file_id}.enc"


def check_child(kek: bytes, child_id: str) -> str:
    """Normalise a pseudonym and make sure it exists in the identity map."""
    try:
        cid = idm.normalize_child_id(child_id)
        imap = idm.load_map(kek, config.get_identity_map_path())
    except idm.InvalidChildIDError as exc:
        raise InvalidInputError(str(exc)) from None
    except idm.MapMissingError:
        raise VaultFileError("identity map is missing - it may have been deleted") from None
    except idm.MapIntegrityError:
        raise VaultFileError("identity map failed its integrity check") from None
    if cid not in imap.ids():
        raise NotFoundError(f"no child with id {cid} - run `childvault pseudonymize` first")
    return cid


def add_file(conn: sqlite3.Connection, kek: bytes, src: Path, file_type: str,
             child_id: str | None = None, extension: str = "", added_by: str = "owner") -> str:
    """Encrypt `src` into the vault and return the new file ID."""
    cid = check_child(kek, child_id) if child_id else None

    files_dir = config.get_files_dir()
    files_dir.mkdir(parents=True, exist_ok=True)
    file_id = db.new_file_id()
    while _enc_path(file_id).exists():
        file_id = db.new_file_id()
    enc_path = _enc_path(file_id)

    data_key = vc.generate_data_key()
    try:
        vc.encrypt_file(src, enc_path, data_key, file_id)
        db.add_file_record(
            conn, file_id, vc.wrap_key(kek, data_key, file_id), file_type,
            extension, added_by, child_id=cid, plaintext_size=Path(src).stat().st_size,
        )
    except (vc.VaultCryptoError, db.VaultDBError, OSError) as exc:
        enc_path.unlink(missing_ok=True)              # no orphan blob without a record
        raise VaultFileError(str(exc)) from None
    return file_id


def open_file(conn: sqlite3.Connection, kek: bytes, file_id: str, out: Path) -> None:
    """Decrypt a vault file to `out` (must not exist). Nothing is written if it fails."""
    check_file_id(file_id)
    if Path(out).exists():
        raise InvalidInputError(f"'{out}' already exists; choose a new output path")
    try:
        row = db.get_file(conn, file_id)
    except db.FileNotInVaultError:
        raise NotFoundError(f"file '{file_id}' not found in the vault") from None
    enc_path = _enc_path(file_id)
    if not enc_path.is_file():
        raise VaultFileError(f"encrypted data for '{file_id}' is missing from the vault folder")
    try:
        data_key = vc.unwrap_key(kek, bytes(row["wrapped_key"]), file_id)
        vc.decrypt_file(enc_path, out, data_key, file_id)
    except (vc.VaultCryptoError, OSError) as exc:
        raise VaultFileError(str(exc)) from None


def revoke_file(conn: sqlite3.Connection, kek: bytes, file_id: str) -> int:
    """Re-encrypt a file under a new key; returns the new key version."""
    check_file_id(file_id)
    try:
        row = db.get_file(conn, file_id)
    except db.FileNotInVaultError:
        raise NotFoundError(f"file '{file_id}' not found in the vault") from None
    enc_path = _enc_path(file_id)
    if not enc_path.is_file():
        raise VaultFileError(f"encrypted data for '{file_id}' is missing from the vault folder")

    fd, plain_name = tempfile.mkstemp(prefix=".revoke-", dir=config.get_files_dir())
    os.close(fd)
    tmp_plain = Path(plain_name)
    tmp_new = enc_path.with_name(enc_path.name + ".new")
    try:
        old_key = vc.unwrap_key(kek, bytes(row["wrapped_key"]), file_id)
        vc.decrypt_file(enc_path, tmp_plain, old_key, file_id)    # verifies integrity first
        new_key = vc.generate_data_key()
        vc.encrypt_file(tmp_plain, tmp_new, new_key, file_id)
        # DB update and file swap succeed together, or the DB change is rolled back.
        with conn:
            version = db.rotate_file_key(conn, file_id, vc.wrap_key(kek, new_key, file_id))
            os.replace(tmp_new, enc_path)
    except (vc.VaultCryptoError, OSError) as exc:
        raise VaultFileError(str(exc)) from None
    finally:
        tmp_plain.unlink(missing_ok=True)
        tmp_new.unlink(missing_ok=True)
    return version
