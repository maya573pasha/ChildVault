import pytest

from childvault import vault_crypto as vc

# Cheap scrypt params so the test suite runs fast. Production uses the defaults.
FAST = {"n": 2 ** 10, "r": 8, "p": 1}


def test_derive_kek_is_deterministic_and_32_bytes():
    salt = b"s" * vc.SALT_LEN
    a = vc.derive_kek("pass", salt, FAST)
    b = vc.derive_kek("pass", salt, FAST)
    assert a == b and len(a) == 32


def test_different_salt_or_passphrase_changes_kek():
    s1, s2 = b"a" * 16, b"b" * 16
    base = vc.derive_kek("pass", s1, FAST)
    assert vc.derive_kek("pass", s2, FAST) != base
    assert vc.derive_kek("other", s1, FAST) != base


def test_empty_passphrase_and_short_salt_rejected():
    with pytest.raises(ValueError):
        vc.derive_kek("", b"s" * 16, FAST)
    with pytest.raises(ValueError):
        vc.derive_kek("pass", b"short", FAST)


def test_header_unlock_roundtrip():
    header = vc.new_vault_header("correct horse", FAST)
    kek = vc.unlock("correct horse", header)
    assert len(kek) == 32


def test_wrong_passphrase_detected():
    header = vc.new_vault_header("correct horse", FAST)
    with pytest.raises(vc.WrongPassphraseError):
        vc.unlock("wrong horse", header)


def test_modified_header_detected():
    header = vc.new_vault_header("pw", FAST)
    header["check"] = header["check"][:-2] + ("00" if header["check"][-2:] != "00" else "01")
    with pytest.raises(vc.WrongPassphraseError):
        vc.unlock("pw", header)


def test_malformed_header():
    with pytest.raises(vc.VaultCryptoError):
        vc.unlock("pw", {"salt": "zz"})


def test_each_header_has_fresh_salt():
    h1 = vc.new_vault_header("pw", FAST)
    h2 = vc.new_vault_header("pw", FAST)
    assert h1["salt"] != h2["salt"]


def test_data_keys_are_32_bytes_and_unique():
    keys = {vc.generate_data_key() for _ in range(50)}
    assert len(keys) == 50
    assert all(len(k) == 32 for k in keys)


def test_wrap_unwrap_roundtrip():
    kek = vc.derive_kek("pw", b"s" * 16, FAST)
    dk = vc.generate_data_key()
    wrapped = vc.wrap_key(kek, dk, "file-1")
    assert len(wrapped) == vc.WRAPPED_LEN
    assert vc.unwrap_key(kek, wrapped, "file-1") == dk


def test_wrapping_same_key_twice_gives_different_blobs():
    kek = vc.derive_kek("pw", b"s" * 16, FAST)
    dk = vc.generate_data_key()
    assert vc.wrap_key(kek, dk, "f") != vc.wrap_key(kek, dk, "f")


def test_unwrap_with_wrong_kek_fails():
    kek1 = vc.derive_kek("pw1", b"s" * 16, FAST)
    kek2 = vc.derive_kek("pw2", b"s" * 16, FAST)
    wrapped = vc.wrap_key(kek1, vc.generate_data_key(), "f")
    with pytest.raises(vc.KeyUnwrapError):
        vc.unwrap_key(kek2, wrapped, "f")


def test_unwrap_bound_to_file_id():
    kek = vc.derive_kek("pw", b"s" * 16, FAST)
    wrapped = vc.wrap_key(kek, vc.generate_data_key(), "file-1")
    with pytest.raises(vc.KeyUnwrapError):
        vc.unwrap_key(kek, wrapped, "file-2")


@pytest.mark.parametrize("pos", [0, 11, 12, 30, vc.WRAPPED_LEN - 1])
def test_tampered_wrapped_key_fails(pos):
    kek = vc.derive_kek("pw", b"s" * 16, FAST)
    wrapped = bytearray(vc.wrap_key(kek, vc.generate_data_key(), "f"))
    wrapped[pos] ^= 0x01
    with pytest.raises(vc.KeyUnwrapError):
        vc.unwrap_key(kek, bytes(wrapped), "f")


def test_truncated_wrapped_key_fails():
    kek = vc.derive_kek("pw", b"s" * 16, FAST)
    wrapped = vc.wrap_key(kek, vc.generate_data_key(), "f")
    with pytest.raises(vc.KeyUnwrapError):
        vc.unwrap_key(kek, wrapped[:-1], "f")


def test_wrap_rejects_bad_key_sizes():
    with pytest.raises(ValueError):
        vc.wrap_key(b"x" * 16, vc.generate_data_key(), "f")
    kek = vc.derive_kek("pw", b"s" * 16, FAST)
    with pytest.raises(ValueError):
        vc.wrap_key(kek, b"x" * 16, "f")


def test_file_stubs_not_implemented_yet():
    with pytest.raises(NotImplementedError):
        vc.encrypt_file("a", "b", b"k" * 32, "f")
    with pytest.raises(NotImplementedError):
        vc.decrypt_file("a", "b", b"k" * 32, "f")