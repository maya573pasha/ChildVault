"""
bundle.py - signed, time-limited share bundles (Aaleen, Phase 3).

keyshare.py locks each chosen file's data key to the reviewer. This module
adds what that cannot give: proof of WHO made the bundle and until WHEN it
is valid.

    bundle file (JSON)
    {
      "payload":   { version, owner_pub, reviewer_fp, created, expires,
                     files: {file_id: {key_version, wrapped}} },
      "signature": "<hex Ed25519 over the canonical payload>"
    }

The owner has one long-term Ed25519 signing key. Its 32-byte seed is stored
in the vault database wrapped under the KEK (same AES-GCM wrapping as file
keys), so it is only usable once the vault is unlocked. The public key is
embedded in every bundle; the reviewer pins its fingerprint (checked over
the phone, like the reviewer's own key) so a forged bundle signed by some
other key is rejected.

A reviewer must call verify_bundle() BEFORE keyshare.unwrap_files_for_reviewer().
"""

import hashlib
import json
import sqlite3
from datetime import date, datetime, time, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import keyshare as ks
from . import vault_crypto as vc

BUNDLE_VERSION = 1
_SIGN_CONTEXT = b"childvault:share-bundle:v1\n"       # domain separation
_META_WRAPPED = "owner_signing_key"
_META_PUBLIC = "owner_signing_pub"
_KEY_PURPOSE = "owner-signing-key"                    # binds the wrapped seed to this purpose
_ALLOWED_PAYLOAD_KEYS = {"version", "owner_pub", "reviewer_fp", "created", "expires", "files"}


class BundleError(Exception):
    """Base class for bundle problems."""


class BadSignatureError(BundleError):
    """The signature does not match the payload (tampered or forged)."""


class ExpiredBundleError(BundleError):
    """The bundle's expiry time has passed."""


class UntrustedOwnerError(BundleError):
    """The bundle is signed by a key other than the one the reviewer pinned."""


class WrongReviewerError(BundleError):
    """The bundle was made for a different reviewer key."""


class MalformedBundleError(BundleError):
    """The bundle is not valid JSON or is missing / has unexpected fields."""


# --------------------------------------------------------------------------
# Owner signing key
# --------------------------------------------------------------------------

def _raw_pub(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def fingerprint(pub: Ed25519PublicKey | bytes) -> str:
    """Short human-checkable ID, same format as keyshare.fingerprint."""
    raw = pub if isinstance(pub, bytes) else _raw_pub(pub)
    h = hashlib.sha256(raw).hexdigest()[:16]
    return ":".join(h[i:i + 4] for i in range(0, 16, 4))


def _set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    with conn:
        conn.execute("INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?, ?)", (key, value))


def get_or_create_signing_key(conn: sqlite3.Connection, kek: bytes) -> Ed25519PrivateKey:
    """
    Load the owner's Ed25519 signing key, creating it on first use.
    Raises BundleError if the stored key was tampered with or the KEK is wrong.
    """
    row = conn.execute("SELECT value FROM vault_meta WHERE key = ?", (_META_WRAPPED,)).fetchone()
    if row is None:
        priv = Ed25519PrivateKey.generate()
        seed = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                  serialization.NoEncryption())
        _set_meta(conn, _META_WRAPPED, vc.wrap_key(kek, seed, _KEY_PURPOSE).hex())
        _set_meta(conn, _META_PUBLIC, _raw_pub(priv.public_key()).hex())
        return priv

    try:
        seed = vc.unwrap_key(kek, bytes.fromhex(row["value"]), _KEY_PURPOSE)
    except (vc.KeyUnwrapError, ValueError):
        raise BundleError("owner signing key failed authentication (damaged or tampered)") from None
    priv = Ed25519PrivateKey.from_private_bytes(seed)

    # The plaintext copy of the public key must match; otherwise someone edited it.
    pub_row = conn.execute("SELECT value FROM vault_meta WHERE key = ?", (_META_PUBLIC,)).fetchone()
    if pub_row is None or pub_row["value"] != _raw_pub(priv.public_key()).hex():
        raise BundleError("owner public key does not match the signing key (tampered)")
    return priv


# --------------------------------------------------------------------------
# Expiry
# --------------------------------------------------------------------------

def parse_expiry(text: str) -> datetime:
    """
    '2026-12-31' means the END of that day (23:59:59 UTC). A full ISO time
    such as '2026-12-31T09:00:00+00:00' is used as given (naive = UTC).
    """
    try:
        if len(text) == 10:
            d = date.fromisoformat(text)
            return datetime.combine(d, time(23, 59, 59), tzinfo=timezone.utc)
        dt = datetime.fromisoformat(text)
    except ValueError:
        raise BundleError(f"invalid expiry '{text}' - use e.g. 2026-12-31") from None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# --------------------------------------------------------------------------
# Create / verify
# --------------------------------------------------------------------------

def _canonical(payload: dict) -> bytes:
    return _SIGN_CONTEXT + json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def create_bundle(
    signing_key: Ed25519PrivateKey,
    reviewer_pub,
    wrapped_files: dict[str, dict],
    expires: datetime,
    now: datetime | None = None,
) -> dict:
    """Build and sign a bundle. `wrapped_files` comes from keyshare.wrap_files_for_reviewer."""
    now = now or datetime.now(timezone.utc)
    if expires <= now:
        raise BundleError("expiry must be in the future")
    if not wrapped_files:
        raise BundleError("a bundle must contain at least one file")
    payload = {
        "version": BUNDLE_VERSION,
        "owner_pub": _raw_pub(signing_key.public_key()).hex(),
        "reviewer_fp": ks.fingerprint(reviewer_pub),
        "created": now.isoformat(timespec="seconds"),
        "expires": expires.isoformat(timespec="seconds"),
        "files": wrapped_files,
    }
    return {"payload": payload, "signature": signing_key.sign(_canonical(payload)).hex()}


def save_bundle(bundle: dict, path: str | Path) -> None:
    Path(path).write_text(json.dumps(bundle, indent=2), encoding="utf-8")


def load_bundle(path: str | Path) -> dict:
    try:
        bundle = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise MalformedBundleError(f"cannot read bundle {path}: {exc}") from None
    if not isinstance(bundle, dict) or set(bundle) != {"payload", "signature"}:
        raise MalformedBundleError("bundle must contain exactly 'payload' and 'signature'")
    return bundle


def verify_bundle(
    bundle: dict,
    *,
    trusted_owner_fp: str | None = None,
    reviewer_fp: str | None = None,
    now: datetime | None = None,
) -> dict:
    """
    Check a bundle and return its payload. Order matters: structure, then
    signature, then the pinned owner, then reviewer and expiry. Nothing in
    the payload is trusted until the signature has been verified.

    trusted_owner_fp - fingerprint the reviewer got from the owner out-of-band
    reviewer_fp      - fingerprint of the reviewer's own key (bundle must match)
    """
    now = now or datetime.now(timezone.utc)
    try:
        payload, sig_hex = bundle["payload"], bundle["signature"]
        owner_pub_raw = bytes.fromhex(payload["owner_pub"])
        signature = bytes.fromhex(sig_hex)
        owner_pub = Ed25519PublicKey.from_public_bytes(owner_pub_raw)
    except (KeyError, TypeError, ValueError):
        raise MalformedBundleError("bundle is malformed") from None
    if not isinstance(payload, dict) or set(payload) != _ALLOWED_PAYLOAD_KEYS:
        raise MalformedBundleError("bundle payload has missing or unexpected fields")

    try:
        owner_pub.verify(signature, _canonical(payload))
    except InvalidSignature:
        raise BadSignatureError("bundle signature is invalid - it was modified or forged") from None

    if payload["version"] != BUNDLE_VERSION:
        raise MalformedBundleError(f"unsupported bundle version {payload['version']}")
    if trusted_owner_fp is not None and fingerprint(owner_pub_raw) != trusted_owner_fp.strip().lower():
        raise UntrustedOwnerError(
            f"bundle is signed by {fingerprint(owner_pub_raw)}, not the owner you trust")
    if reviewer_fp is not None and payload["reviewer_fp"] != reviewer_fp:
        raise WrongReviewerError("this bundle was made for a different reviewer key")

    try:
        expires = datetime.fromisoformat(payload["expires"])
    except (TypeError, ValueError):
        raise MalformedBundleError("bundle expiry is malformed") from None
    if expires.tzinfo is None or now >= expires:
        raise ExpiredBundleError(f"bundle expired on {payload['expires']}")
    return payload
