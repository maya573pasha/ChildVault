"""
keyshare.py - wrap file data keys to a reviewer's X25519 public key
(Mariyam, Phase 3).

The owner wants a reviewer to open a few chosen files. Each file has its
own random data key (Aaleen). We lock that data key so that ONLY the
reviewer's private key can unlock it:

    owner                                          reviewer
    -----                                          --------
    ephemeral key pair (e_priv, e_pub)             long-term key pair (r_priv, r_pub)
    shared = X25519(e_priv, r_pub)        ==       shared = X25519(r_priv, e_pub)
    wrap_key = HKDF(shared, context)               wrap_key = HKDF(shared, context)
    AES-GCM(wrap_key).encrypt(data_key)   ---->    AES-GCM(wrap_key).decrypt(...)

Wrapped blob:  e_pub (32) || nonce (12) || encrypted data key (32) + tag (16) = 92 bytes

What this does NOT give: proof of WHO made the blob. Anyone can encrypt to
a public key. The share bundle is therefore signed with Ed25519 (Aaleen);
the reviewer must check that signature before trusting any wrapped key.
"""

import hashlib
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import vault_crypto as vc

PUB_LEN = 32
SHARE_WRAPPED_LEN = PUB_LEN + vc.NONCE_LEN + vc.KEY_LEN + vc.TAG_LEN   # 92
_HKDF_INFO = b"childvault:share-wrap:v1"
_AAD_PREFIX = b"childvault:share:"


class KeyShareError(Exception):
    """Base class for reviewer key-wrapping errors."""


class ShareUnwrapError(KeyShareError):
    """Wrapped key could not be opened: wrong reviewer, wrong file, or tampered."""


class KeyFileError(KeyShareError):
    """A key file is missing, the wrong type, or its passphrase is wrong."""


# --------------------------------------------------------------------------
# Wrapping a data key to a reviewer
# --------------------------------------------------------------------------

def _raw(pub: X25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _derive_wrap_key(shared: bytes, e_pub: bytes, r_pub: bytes) -> bytes:
    """
    Turn the raw X25519 shared secret into an AES key with HKDF-SHA256.
    Both public keys go into `info`, so the key belongs to exactly this
    ephemeral key + this reviewer.
    """
    return HKDF(
        algorithm=hashes.SHA256(), length=vc.KEY_LEN, salt=None,
        info=_HKDF_INFO + e_pub + r_pub,
    ).derive(shared)


def wrap_for_reviewer(data_key: bytes, reviewer_pub: X25519PublicKey, file_id: str) -> bytes:
    """Lock one file's data key so only the reviewer's private key can open it."""
    if len(data_key) != vc.KEY_LEN:
        raise ValueError(f"data_key must be {vc.KEY_LEN} bytes")

    e_priv = X25519PrivateKey.generate()          # fresh for every wrap, then discarded
    e_pub = _raw(e_priv.public_key())
    r_pub = _raw(reviewer_pub)
    try:
        shared = e_priv.exchange(reviewer_pub)
    except ValueError:
        raise KeyShareError("invalid reviewer public key") from None

    wrap_key = _derive_wrap_key(shared, e_pub, r_pub)
    nonce = os.urandom(vc.NONCE_LEN)
    ct = AESGCM(wrap_key).encrypt(nonce, data_key, _AAD_PREFIX + file_id.encode("utf-8"))
    return e_pub + nonce + ct


def unwrap_for_reviewer(blob: bytes, reviewer_priv: X25519PrivateKey, file_id: str) -> bytes:
    """Reviewer side: recover the data key. Raises ShareUnwrapError on any failure."""
    if len(blob) != SHARE_WRAPPED_LEN:
        raise ShareUnwrapError("wrapped key has the wrong length")

    e_pub = blob[:PUB_LEN]
    nonce = blob[PUB_LEN:PUB_LEN + vc.NONCE_LEN]
    ct = blob[PUB_LEN + vc.NONCE_LEN:]
    r_pub = _raw(reviewer_priv.public_key())

    try:
        shared = reviewer_priv.exchange(X25519PublicKey.from_public_bytes(e_pub))
        wrap_key = _derive_wrap_key(shared, e_pub, r_pub)
        return AESGCM(wrap_key).decrypt(nonce, ct, _AAD_PREFIX + file_id.encode("utf-8"))
    except (ValueError, InvalidTag):
        raise ShareUnwrapError("could not unwrap key (wrong reviewer key, wrong file, or tampered)") from None


# --------------------------------------------------------------------------
# Reviewer key pair and key files
# --------------------------------------------------------------------------

def generate_reviewer_keypair() -> tuple[X25519PrivateKey, X25519PublicKey]:
    priv = X25519PrivateKey.generate()
    return priv, priv.public_key()


def fingerprint(pub: X25519PublicKey) -> str:
    """
    Short human-checkable ID of a public key, e.g. 'a1b2:c3d4:e5f6:0718'.
    The owner and reviewer compare it over the phone / in person so a
    swapped public key (man-in-the-middle) is noticed.
    """
    h = hashlib.sha256(_raw(pub)).hexdigest()[:16]
    return ":".join(h[i:i + 4] for i in range(0, 16, 4))


def save_public_key(pub: X25519PublicKey, path: str | Path) -> None:
    Path(path).write_bytes(pub.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))


def load_public_key(path: str | Path) -> X25519PublicKey:
    try:
        key = serialization.load_pem_public_key(Path(path).read_bytes())
    except (OSError, ValueError) as exc:
        raise KeyFileError(f"cannot read public key {path}: {exc}") from None
    if not isinstance(key, X25519PublicKey):
        raise KeyFileError(f"{path} is not an X25519 public key")
    return key


def save_private_key(priv: X25519PrivateKey, path: str | Path, passphrase: str) -> None:
    """Private key is stored ENCRYPTED with the reviewer's own passphrase."""
    if not passphrase:
        raise ValueError("passphrase must not be empty")
    Path(path).write_bytes(priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase.encode("utf-8"))))


def load_private_key(path: str | Path, passphrase: str) -> X25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(
            Path(path).read_bytes(), password=passphrase.encode("utf-8"))
    except (OSError, ValueError, TypeError):
        raise KeyFileError(f"cannot open private key {path} (wrong passphrase or not a key file)") from None
    if not isinstance(key, X25519PrivateKey):
        raise KeyFileError(f"{path} is not an X25519 private key")
    return key
