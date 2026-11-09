import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from childvault import keyshare as ks
from childvault import vault_crypto as vc


@pytest.fixture
def reviewer():
    return ks.generate_reviewer_keypair()


# ---------------------------------------------------------------- wrap / unwrap

def test_roundtrip(reviewer):
    priv, pub = reviewer
    dk = vc.generate_data_key()
    blob = ks.wrap_for_reviewer(dk, pub, "F-1")
    assert len(blob) == ks.SHARE_WRAPPED_LEN == 92
    assert ks.unwrap_for_reviewer(blob, priv, "F-1") == dk


def test_data_key_not_visible_in_blob(reviewer):
    dk = vc.generate_data_key()
    assert dk not in ks.wrap_for_reviewer(dk, reviewer[1], "F-1")


def test_fresh_ephemeral_key_every_wrap(reviewer):
    dk = vc.generate_data_key()
    a = ks.wrap_for_reviewer(dk, reviewer[1], "F-1")
    b = ks.wrap_for_reviewer(dk, reviewer[1], "F-1")
    assert a[:32] != b[:32]          # different ephemeral public keys
    assert a != b


def test_wrong_reviewer_key_rejected(reviewer):
    """Attack from the proposal: a different reviewer tries to use the bundle."""
    other_priv, _ = ks.generate_reviewer_keypair()
    blob = ks.wrap_for_reviewer(vc.generate_data_key(), reviewer[1], "F-1")
    with pytest.raises(ks.ShareUnwrapError):
        ks.unwrap_for_reviewer(blob, other_priv, "F-1")


def test_key_bound_to_file_id(reviewer):
    """A wrapped key for F-1 must not be relabelled as the key for F-2."""
    blob = ks.wrap_for_reviewer(vc.generate_data_key(), reviewer[1], "F-1")
    with pytest.raises(ks.ShareUnwrapError):
        ks.unwrap_for_reviewer(blob, reviewer[0], "F-2")


@pytest.mark.parametrize("pos", [0, 31, 32, 43, 44, 70, 91])
def test_any_flipped_bit_rejected(reviewer, pos):
    blob = bytearray(ks.wrap_for_reviewer(vc.generate_data_key(), reviewer[1], "F-1"))
    blob[pos] ^= 0x01
    with pytest.raises(ks.ShareUnwrapError):
        ks.unwrap_for_reviewer(bytes(blob), reviewer[0], "F-1")


@pytest.mark.parametrize("length", [0, 91, 93])
def test_wrong_length_rejected(reviewer, length):
    with pytest.raises(ks.ShareUnwrapError):
        ks.unwrap_for_reviewer(b"\x00" * length, reviewer[0], "F-1")


def test_all_zero_ephemeral_key_rejected(reviewer):
    """A low-order (all-zero) public key would make the shared secret predictable."""
    blob = bytearray(ks.wrap_for_reviewer(vc.generate_data_key(), reviewer[1], "F-1"))
    blob[:32] = bytes(32)
    with pytest.raises(ks.ShareUnwrapError):
        ks.unwrap_for_reviewer(bytes(blob), reviewer[0], "F-1")


def test_bad_data_key_size(reviewer):
    with pytest.raises(ValueError):
        ks.wrap_for_reviewer(b"short", reviewer[1], "F-1")


# ---------------------------------------------------------------- fingerprints

def test_fingerprint_format_and_stability(reviewer):
    fp = ks.fingerprint(reviewer[1])
    assert len(fp) == 19 and fp.count(":") == 3
    assert ks.fingerprint(reviewer[1]) == fp
    assert ks.fingerprint(ks.generate_reviewer_keypair()[1]) != fp


# ---------------------------------------------------------------- key files

def test_public_key_file_roundtrip(tmp_path, reviewer):
    path = tmp_path / "r.pub"
    ks.save_public_key(reviewer[1], path)
    assert path.read_bytes().startswith(b"-----BEGIN PUBLIC KEY-----")
    assert ks.fingerprint(ks.load_public_key(path)) == ks.fingerprint(reviewer[1])


def test_private_key_file_is_encrypted(tmp_path, reviewer):
    path = tmp_path / "r.key"
    ks.save_private_key(reviewer[0], path, "reviewer pass")
    assert b"ENCRYPTED PRIVATE KEY" in path.read_bytes()
    loaded = ks.load_private_key(path, "reviewer pass")
    blob = ks.wrap_for_reviewer(b"k" * 32, reviewer[1], "F-1")
    assert ks.unwrap_for_reviewer(blob, loaded, "F-1") == b"k" * 32


def test_private_key_wrong_passphrase(tmp_path, reviewer):
    path = tmp_path / "r.key"
    ks.save_private_key(reviewer[0], path, "reviewer pass")
    with pytest.raises(ks.KeyFileError):
        ks.load_private_key(path, "wrong")


def test_private_key_empty_passphrase_refused(tmp_path, reviewer):
    with pytest.raises(ValueError):
        ks.save_private_key(reviewer[0], tmp_path / "r.key", "")


def test_load_public_key_rejects_other_key_types(tmp_path):
    """An Ed25519 (signing) key must not be accepted as an X25519 (encryption) key."""
    ed_pub = Ed25519PrivateKey.generate().public_key()
    path = tmp_path / "ed.pub"
    path.write_bytes(ed_pub.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    with pytest.raises(ks.KeyFileError):
        ks.load_public_key(path)


def test_load_public_key_missing_or_garbage(tmp_path):
    with pytest.raises(ks.KeyFileError):
        ks.load_public_key(tmp_path / "missing.pub")
    junk = tmp_path / "junk.pub"
    junk.write_text("not a key")
    with pytest.raises(ks.KeyFileError):
        ks.load_public_key(junk)
