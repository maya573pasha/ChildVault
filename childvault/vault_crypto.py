"""
vault_crypto.py - ChildVault, Phase 1 (key management + interface stubs)

Scope of this phase
  - passphrase -> scrypt -> 256-bit key-encryption key (KEK)
  - vault header (salt, scrypt params, passphrase check value)
  - per-file random 256-bit data key
  - wrap / unwrap of data keys under the KEK (bound to the file ID)
  - encrypt_file / decrypt_file STUBS so Mariyam and Laiba can code against
    a fixed interface; the real chunked AES-256-GCM goes in here in Phase 2.

Everything uses the `cryptography` library only.
"""

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

KEY_LEN = 32      # 256-bit keys everywhere
NONCE_LEN = 12    # standard AES-GCM nonce size
SALT_LEN = 16
TAG_LEN = 16
WRAPPED_LEN = NONCE_LEN + KEY_LEN + TAG_LEN   # nonce || ciphertext || tag

# Tunable. Stored in the vault header so a vault always opens with the
# parameters it was created with, even if this default changes later.
DEFAULT_SCRYPT_PARAMS = {"n": 2 ** 15, "r": 8, "p": 1}

_CHECK_PLAINTEXT = b"childvault-kek-check-v1"
_CHECK_AAD = b"childvault:vault-check"
_WRAP_AAD_PREFIX = b"childvault:wrap:"


class VaultCryptoError(Exception):
    """Base class for all errors raised by this module."""


class WrongPassphraseError(VaultCryptoError):
    """The passphrase does not match the vault header."""


class KeyUnwrapError(VaultCryptoError):
    """A wrapped key failed authentication (wrong KEK, wrong file ID, or tampered)."""


# --------------------------------------------------------------------------
# KEK derivation and vault header
# --------------------------------------------------------------------------

def derive_kek(passphrase: str, salt: bytes, params: dict | None = None) -> bytes:
    """passphrase -> scrypt -> 256-bit KEK."""
    if not passphrase:
        raise ValueError("passphrase must not be empty")
    if len(salt) < SALT_LEN:
        raise ValueError(f"salt must be at least {SALT_LEN} bytes")
    p = params or DEFAULT_SCRYPT_PARAMS
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=p["n"], r=p["r"], p=p["p"])
    return kdf.derive(passphrase.encode("utf-8"))


def new_vault_header(passphrase: str, params: dict | None = None) -> dict:
    """
    Create the header stored in the vault at `init` time (JSON-serialisable).

    Contains the salt, the scrypt parameters and a check value (a known
    plaintext encrypted under the KEK) so a wrong passphrase is reported
    clearly instead of failing later on some random file.
    """
    p = dict(params or DEFAULT_SCRYPT_PARAMS)
    salt = os.urandom(SALT_LEN)
    kek = derive_kek(passphrase, salt, p)
    nonce = os.urandom(NONCE_LEN)
    check = AESGCM(kek).encrypt(nonce, _CHECK_PLAINTEXT, _CHECK_AAD)
    return {
        "version": 1,
        "kdf": "scrypt",
        "scrypt": p,
        "salt": salt.hex(),
        "check": (nonce + check).hex(),
    }


def unlock(passphrase: str, header: dict) -> bytes:
    """Derive the KEK from the passphrase and verify it against the header."""
    try:
        salt = bytes.fromhex(header["salt"])
        blob = bytes.fromhex(header["check"])
        params = header["scrypt"]
    except (KeyError, ValueError) as exc:
        raise VaultCryptoError("malformed vault header") from exc

    kek = derive_kek(passphrase, salt, params)
    try:
        plain = AESGCM(kek).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], _CHECK_AAD)
    except InvalidTag:
        raise WrongPassphraseError("wrong passphrase (or vault header was modified)") from None
    if plain != _CHECK_PLAINTEXT:
        raise WrongPassphraseError("wrong passphrase (or vault header was modified)")
    return kek


# --------------------------------------------------------------------------
# Per-file data keys and key wrapping
# --------------------------------------------------------------------------

def generate_data_key() -> bytes:
    """Fresh random 256-bit data key (one per file)."""
    return AESGCM.generate_key(bit_length=256)


def wrap_key(kek: bytes, data_key: bytes, file_id: str) -> bytes:
    """
    Wrap a data key under the KEK with AES-256-GCM.

    The file ID is bound in as associated data, so a wrapped key copied next
    to a different file will not unwrap. Output: nonce(12) || ct(32) || tag(16).
    """
    _check_len("kek", kek, KEY_LEN)
    _check_len("data_key", data_key, KEY_LEN)
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(kek).encrypt(nonce, data_key, _wrap_aad(file_id))
    return nonce + ct


def unwrap_key(kek: bytes, wrapped: bytes, file_id: str) -> bytes:
    """Inverse of wrap_key. Raises KeyUnwrapError on any authentication failure."""
    _check_len("kek", kek, KEY_LEN)
    if len(wrapped) != WRAPPED_LEN:
        raise KeyUnwrapError("wrapped key has the wrong length")
    try:
        return AESGCM(kek).decrypt(wrapped[:NONCE_LEN], wrapped[NONCE_LEN:], _wrap_aad(file_id))
    except InvalidTag:
        raise KeyUnwrapError("wrapped key failed authentication") from None


def _wrap_aad(file_id: str) -> bytes:
    return _WRAP_AAD_PREFIX + file_id.encode("utf-8")


def _check_len(name: str, value: bytes, expected: int) -> None:
    if len(value) != expected:
        raise ValueError(f"{name} must be {expected} bytes, got {len(value)}")


# --------------------------------------------------------------------------
# File encryption interface (STUBS - implemented in Phase 2)
# --------------------------------------------------------------------------

def encrypt_file(src_path: str, dst_path: str, data_key: bytes, file_id: str) -> None:
    """
    Encrypt src_path into dst_path with 1 MB AES-256-GCM chunks, streaming.

    Contract for other modules:
      - raises nothing on success, returns None
      - the chunk number is bound into each chunk's authenticated data
      - dst_path is only complete if this function returns normally
    """
    raise NotImplementedError("Phase 2")


def decrypt_file(src_path: str, dst_path: str, data_key: bytes, file_id: str) -> None:
    """
    Decrypt src_path into dst_path, streaming.

    Contract for other modules:
      - raises IntegrityError (to be added in Phase 2) if any chunk was
        flipped, swapped, removed or the file was truncated
      - never leaves partially trusted plaintext at dst_path on failure
    """
    raise NotImplementedError("Phase 2")