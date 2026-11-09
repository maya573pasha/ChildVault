"""
vault_crypto.py - ChildVault encryption engine


Phase 1 - key management
  - passphrase -> scrypt -> 256-bit key-encryption key (KEK)
  - vault header (salt, scrypt params, passphrase check value)
  - per-file random 256-bit data key
  - wrap / unwrap of data keys under the KEK (bound to the file ID)

Phase 2 - file encryption
  - streaming AES-256-GCM in 1 MB chunks
  - every chunk's authenticated data binds: file header, file ID,
    chunk number, and a "final chunk" flag
  - any bit-flip, chunk swap/duplication, truncation, extension, wrong key
    or wrong file ID raises IntegrityError and leaves no output file

Encrypted file layout
  header  : magic "CVLT" (4) | format version (1) | chunk size (4, big-endian)
  chunks  : repeated  nonce (12) | ciphertext (<= chunk size) | tag (16)
  All chunks hold exactly `chunk size` plaintext bytes except the last one.
  An empty file is stored as a single, empty, final chunk.

Chunk AAD = header | len(file_id) (2) | file_id | chunk number (8) | final flag (1)

Everything uses the `cryptography` library only.
"""

import os
import struct

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

# File format (Phase 2)
MAGIC = b"CVLT"
FORMAT_VERSION = 1
CHUNK_SIZE = 1024 * 1024               # 1 MB
MAX_CHUNK_SIZE = 64 * 1024 * 1024      # sanity cap when reading a header
_HEADER = struct.Struct(">4sBI")       # magic, version, chunk size
HEADER_LEN = _HEADER.size              # 9 bytes


class VaultCryptoError(Exception):
    """Base class for all errors raised by this module."""


class WrongPassphraseError(VaultCryptoError):
    """The passphrase does not match the vault header."""


class KeyUnwrapError(VaultCryptoError):
    """A wrapped key failed authentication (wrong KEK, wrong file ID, or tampered)."""


class IntegrityError(VaultCryptoError):
    """An encrypted file failed verification (modified, truncated, reordered, wrong key or ID)."""


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
# Chunked file encryption (Phase 2)
# --------------------------------------------------------------------------

def encrypt_file(src_path, dst_path, data_key: bytes, file_id: str,
                 chunk_size: int = CHUNK_SIZE) -> None:
    """
    Encrypt src_path into dst_path with AES-256-GCM chunks, streaming.

    The output is written to "<dst_path>.part" and moved into place only after
    the last chunk is written, so dst_path is either complete or absent.
    `chunk_size` exists so tests can use small chunks; production uses 1 MB.
    """
    src_path, dst_path = os.fspath(src_path), os.fspath(dst_path)
    _check_len("data_key", data_key, KEY_LEN)
    _check_file_id(file_id)
    if not 1 <= chunk_size <= MAX_CHUNK_SIZE:
        raise ValueError(f"chunk_size must be between 1 and {MAX_CHUNK_SIZE}")

    header = _HEADER.pack(MAGIC, FORMAT_VERSION, chunk_size)
    aead = AESGCM(data_key)
    tmp_path = dst_path + ".part"
    try:
        with open(src_path, "rb") as src, open(tmp_path, "wb") as dst:
            dst.write(header)
            current = src.read(chunk_size)
            index = 0
            while True:
                # Read one chunk ahead: the chunk is "final" iff nothing follows it.
                # An empty file therefore becomes one empty final chunk.
                nxt = src.read(chunk_size)
                final = not nxt
                nonce = os.urandom(NONCE_LEN)
                aad = _chunk_aad(header, file_id, index, final)
                dst.write(nonce + aead.encrypt(nonce, current, aad))
                if final:
                    break
                current = nxt
                index += 1
            dst.flush()
            os.fsync(dst.fileno())
        os.replace(tmp_path, dst_path)
    except BaseException:
        _remove_quietly(tmp_path)
        raise


def decrypt_file(src_path, dst_path, data_key: bytes, file_id: str) -> None:
    """
    Decrypt src_path into dst_path, streaming.

    Raises IntegrityError if any chunk was flipped, swapped, duplicated,
    removed or appended, if the header was edited, or if the key / file ID
    is wrong. Plaintext is written to "<dst_path>.part" and only moved to
    dst_path after the final chunk verifies; on failure the .part file is
    deleted (it is removed, not securely wiped) and an existing dst_path is
    left untouched.
    """
    src_path, dst_path = os.fspath(src_path), os.fspath(dst_path)
    _check_len("data_key", data_key, KEY_LEN)
    _check_file_id(file_id)

    aead = AESGCM(data_key)
    tmp_path = dst_path + ".part"
    try:
        with open(src_path, "rb") as src:
            header = src.read(HEADER_LEN)
            if len(header) != HEADER_LEN:
                raise IntegrityError("file is too short to be a ChildVault file")
            magic, version, chunk_size = _HEADER.unpack(header)
            if magic != MAGIC or version != FORMAT_VERSION:
                raise IntegrityError("not a ChildVault file, or unsupported version")
            if not 1 <= chunk_size <= MAX_CHUNK_SIZE:
                raise IntegrityError("invalid chunk size in header")

            record_len = NONCE_LEN + chunk_size + TAG_LEN
            with open(tmp_path, "wb") as dst:
                current = src.read(record_len)
                if not current:
                    raise IntegrityError("file has no chunks (truncated)")
                index = 0
                while True:
                    nxt = src.read(record_len)
                    final = not nxt
                    if len(current) < NONCE_LEN + TAG_LEN:
                        raise IntegrityError(f"chunk {index} is truncated")
                    aad = _chunk_aad(header, file_id, index, final)
                    try:
                        plain = aead.decrypt(current[:NONCE_LEN], current[NONCE_LEN:], aad)
                    except InvalidTag:
                        raise IntegrityError(
                            f"chunk {index} failed authentication "
                            "(modified, reordered, truncated, wrong key or wrong file ID)"
                        ) from None
                    dst.write(plain)
                    if final:
                        break
                    current = nxt
                    index += 1
                dst.flush()
                os.fsync(dst.fileno())
        os.replace(tmp_path, dst_path)
    except BaseException:
        _remove_quietly(tmp_path)
        raise


def _chunk_aad(header: bytes, file_id: str, index: int, final: bool) -> bytes:
    fid = file_id.encode("utf-8")
    return header + struct.pack(">H", len(fid)) + fid + struct.pack(">QB", index, 1 if final else 0)


def _check_file_id(file_id: str) -> None:
    if not file_id or len(file_id.encode("utf-8")) > 0xFFFF:
        raise ValueError("file_id must be 1 to 65535 bytes")


def _remove_quietly(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass