"""
identity.py - pseudonymization (Mariyam, Phase 2).

Real child names are replaced by random IDs such as CH-4F7A. The ID-name
map is kept in a separate encrypted file, identity_map.enc.

Design decisions:
  * IDs are RANDOM, never derived from the name (e.g. a hash of the name).
    A hash could be reversed by hashing a list of likely names and
    comparing - a dictionary attack that re-identifies children.
  * 4 hex characters = 65,536 possible IDs. By the birthday problem two
    random IDs collide with ~50% probability after only ~300 children, so
    we never rely on luck: every new ID is checked against the existing
    ones and redrawn if taken.
  * The map file is encrypted with AES-256-GCM under a FRESH random key
    and a FRESH random nonce on every save. That key is wrapped under the
    KEK (Aaleen's wrap_key) and stored at the front of the file.

Map file layout (identity_map.enc):
    MAGIC (6) || wrapped map key (60) || nonce (12) || ciphertext + tag
    AAD = MAGIC || wrapped map key   (so the header cannot be swapped)
"""

import json
import math
import os
import re
import secrets
from collections.abc import Collection
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import vault_crypto as vc
from .db import utc_now

PREFIX = "CH-"
ID_HEX_CHARS = 4
ID_SPACE = 16 ** ID_HEX_CHARS          # 65,536 possible IDs
MAX_ATTEMPTS = 1000                    # give up instead of looping forever

_ID_RE = re.compile(rf"^{PREFIX}[0-9A-F]{{{ID_HEX_CHARS}}}$")


class IdentityError(Exception):
    """Base class for pseudonymization errors."""


class InvalidChildIDError(IdentityError):
    """Text is not a well-formed child ID like CH-4F7A."""


class IDSpaceExhaustedError(IdentityError):
    """Could not find a free ID (the vault is close to 65,536 children)."""


class UnknownChildIDError(IdentityError):
    """The pseudonym is valid but not in the map."""


class MapMissingError(IdentityError):
    """identity_map.enc does not exist (deleted, or vault created without it)."""


class MapIntegrityError(IdentityError):
    """The map file was modified, truncated, or belongs to another vault."""


def random_child_id() -> str:
    """One random ID from the OS's secure random generator, e.g. CH-4F7A."""
    n = secrets.randbelow(ID_SPACE)
    return f"{PREFIX}{n:0{ID_HEX_CHARS}X}"


def new_child_id(existing: Collection[str]) -> str:
    """A random ID that is not already in `existing` (redrawn on collision)."""
    for _ in range(MAX_ATTEMPTS):
        candidate = random_child_id()
        if candidate not in existing:
            return candidate
    raise IDSpaceExhaustedError(f"no free child ID after {MAX_ATTEMPTS} attempts")


def normalize_child_id(text: str) -> str:
    """Accept ' ch-4f7a ' style input; return 'CH-4F7A' or raise InvalidChildIDError."""
    cleaned = text.strip().upper()
    if not _ID_RE.match(cleaned):
        raise InvalidChildIDError(f"not a valid child ID: {text!r} (expected e.g. CH-4F7A)")
    return cleaned


def is_valid_child_id(text: str) -> bool:
    return bool(_ID_RE.match(text))


def collision_probability(n: int, space: int = ID_SPACE) -> float:
    """
    Birthday-problem estimate: chance that at least two of n random IDs
    are equal, if we did NOT check for duplicates. Used in the report.
        p ~= 1 - exp(-n(n-1) / 2N)
    """
    if n < 2:
        return 0.0
    return 1 - math.exp(-n * (n - 1) / (2 * space))


# --------------------------------------------------------------------------
# The ID -> name map (in memory)
# --------------------------------------------------------------------------

class IdentityMap:
    """Pseudonym -> real name, held in memory only while the vault is unlocked."""

    def __init__(self, entries: dict | None = None):
        # {"CH-4F7A": {"name": "Ali Khan", "created_at": "2026-11-09T..."}}
        self.entries: dict[str, dict] = dict(entries or {})

    def add(self, name: str) -> str:
        """Give a new child a fresh pseudonym and return it."""
        name = name.strip()
        if not name:
            raise IdentityError("name must not be empty")
        child_id = new_child_id(self.entries.keys())
        self.entries[child_id] = {"name": name, "created_at": utc_now()}
        return child_id

    def lookup(self, child_id: str) -> str:
        """Real name for a pseudonym (input is normalised first)."""
        cid = normalize_child_id(child_id)
        try:
            return self.entries[cid]["name"]
        except KeyError:
            raise UnknownChildIDError(f"no child with id {cid}") from None

    def ids(self) -> list[str]:
        return sorted(self.entries)

    def __len__(self) -> int:
        return len(self.entries)


# --------------------------------------------------------------------------
# Encrypting the map to disk
# --------------------------------------------------------------------------

MAP_MAGIC = b"CVMAP1"                  # file type + format version
MAP_KEY_ID = "identity-map"            # binds the wrapped key to THIS purpose
_NONCE_LEN = vc.NONCE_LEN
_HEADER_LEN = len(MAP_MAGIC) + vc.WRAPPED_LEN


def encrypt_map(kek: bytes, imap: IdentityMap) -> bytes:
    """Serialise and encrypt the map. Fresh key and nonce every call."""
    plaintext = json.dumps(
        {"version": 1, "entries": imap.entries}, sort_keys=True
    ).encode("utf-8")

    map_key = vc.generate_data_key()
    wrapped = vc.wrap_key(kek, map_key, MAP_KEY_ID)
    header = MAP_MAGIC + wrapped
    nonce = os.urandom(_NONCE_LEN)
    ciphertext = AESGCM(map_key).encrypt(nonce, plaintext, header)
    return header + nonce + ciphertext


def decrypt_map(kek: bytes, blob: bytes) -> IdentityMap:
    """Inverse of encrypt_map. Raises MapIntegrityError on any tampering."""
    if len(blob) < _HEADER_LEN + _NONCE_LEN + vc.TAG_LEN or not blob.startswith(MAP_MAGIC):
        raise MapIntegrityError("identity map is damaged or not a ChildVault map")

    header = blob[:_HEADER_LEN]
    wrapped = header[len(MAP_MAGIC):]
    nonce = blob[_HEADER_LEN:_HEADER_LEN + _NONCE_LEN]
    ciphertext = blob[_HEADER_LEN + _NONCE_LEN:]

    try:
        map_key = vc.unwrap_key(kek, wrapped, MAP_KEY_ID)
        plaintext = AESGCM(map_key).decrypt(nonce, ciphertext, header)
    except (vc.KeyUnwrapError, InvalidTag):
        raise MapIntegrityError("identity map failed authentication (tampered or wrong vault)") from None

    data = json.loads(plaintext)
    return IdentityMap(data["entries"])


def save_map(kek: bytes, imap: IdentityMap, path: str | Path) -> None:
    """
    Write the encrypted map ATOMICALLY: write a temp file, then rename it
    over the old one. A crash mid-write leaves the old map intact instead
    of a half-written file (losing the map = losing every child's identity).
    """
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(encrypt_map(kek, imap))
    os.replace(tmp, path)


def load_map(kek: bytes, path: str | Path) -> IdentityMap:
    """Read and decrypt the map. A missing file is an error, not an empty map."""
    path = Path(path)
    if not path.is_file():
        raise MapMissingError(f"identity map not found at {path}")
    return decrypt_map(kek, path.read_bytes())
