import os

import pytest

from childvault import vault_crypto as vc
# Cheap scrypt params so the test suite runs fast. Production uses the defaults.
FAST = {"n": 2 ** 10, "r": 8, "p": 1}


# ==========================================================================
# Phase 1: key management
# ==========================================================================

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


# ==========================================================================
# Phase 2: chunked file encryption
# ==========================================================================

FID = "F-000000000001"
CS = 64                                   # small chunk size so tests stay fast
REC = vc.NONCE_LEN + CS + vc.TAG_LEN      # size of one full encrypted record
HL = vc.HEADER_LEN
OVERHEAD = vc.NONCE_LEN + vc.TAG_LEN      # per-chunk overhead


def make(tmp_path, data, chunk_size=CS, file_id=FID):
    """Encrypt `data`; return (data_key, path_to_encrypted_file)."""
    src = tmp_path / "plain.bin"
    src.write_bytes(data)
    enc = tmp_path / "x.enc"
    key = vc.generate_data_key()
    vc.encrypt_file(src, enc, key, file_id, chunk_size)
    return key, enc


def dec(tmp_path, enc, key, file_id=FID):
    out = tmp_path / "out.bin"
    vc.decrypt_file(enc, out, key, file_id)
    return out


def split(blob):
    """Split an encrypted file into (header, [records])."""
    body = blob[HL:]
    return blob[:HL], [body[i:i + REC] for i in range(0, len(body), REC)]


def join(header, records):
    return header + b"".join(records)


def assert_rejected(tmp_path, enc, key, file_id=FID):
    """Decryption must raise IntegrityError and leave no output behind."""
    out = tmp_path / "out.bin"
    with pytest.raises(vc.IntegrityError):
        vc.decrypt_file(enc, out, key, file_id)
    assert not out.exists()
    assert not (tmp_path / "out.bin.part").exists()


@pytest.mark.parametrize("size", [0, 1, CS - 1, CS, CS + 1, 3 * CS, 3 * CS + 5])
def test_roundtrip_sizes(tmp_path, size):
    data = os.urandom(size)
    key, enc = make(tmp_path, data)
    assert dec(tmp_path, enc, key).read_bytes() == data
    n_chunks = max(1, -(-size // CS))
    assert enc.stat().st_size == HL + n_chunks * OVERHEAD + size


def test_roundtrip_with_default_1mb_chunks(tmp_path):
    for size in (vc.CHUNK_SIZE, vc.CHUNK_SIZE + 1):
        data = os.urandom(size)
        src = tmp_path / "plain.bin"
        src.write_bytes(data)
        enc = tmp_path / "big.enc"
        out = tmp_path / "big.out"
        key = vc.generate_data_key()
        vc.encrypt_file(src, enc, key, FID)
        vc.decrypt_file(enc, out, key, FID)
        assert out.read_bytes() == data
        n_chunks = 1 if size == vc.CHUNK_SIZE else 2
        assert enc.stat().st_size == HL + n_chunks * OVERHEAD + size
        enc.unlink()
        out.unlink()


def test_ciphertext_is_not_plaintext_and_is_randomised(tmp_path):
    data = b"A" * (2 * CS)
    key, enc1 = make(tmp_path, data)
    assert data not in enc1.read_bytes()
    enc2 = tmp_path / "y.enc"
    vc.encrypt_file(tmp_path / "plain.bin", enc2, key, FID, CS)
    assert enc1.read_bytes() != enc2.read_bytes()


def test_encrypt_leaves_no_part_file_and_cleans_up_on_error(tmp_path):
    key = vc.generate_data_key()
    with pytest.raises(FileNotFoundError):
        vc.encrypt_file(tmp_path / "missing.bin", tmp_path / "x.enc", key, FID, CS)
    assert not (tmp_path / "x.enc").exists()
    assert not (tmp_path / "x.enc.part").exists()


def test_encrypt_rejects_bad_arguments(tmp_path):
    src = tmp_path / "p.bin"
    src.write_bytes(b"hi")
    with pytest.raises(ValueError):
        vc.encrypt_file(src, tmp_path / "x", b"short", FID)
    with pytest.raises(ValueError):
        vc.encrypt_file(src, tmp_path / "x", vc.generate_data_key(), "")
    with pytest.raises(ValueError):
        vc.encrypt_file(src, tmp_path / "x", vc.generate_data_key(), FID, chunk_size=0)


# ---- attack: bit-flip ----------------------------------------------------

def _flip_offsets(file_len):
    return [
        0, 4, 5, 8,                    # header: magic, version, chunk size
        HL,                            # first nonce
        HL + vc.NONCE_LEN,             # first ciphertext byte
        HL + REC - 1,                  # first tag (last byte)
        HL + REC + 20,                 # inside the second chunk
        file_len - 1,                  # last byte of the final chunk
    ]


def test_bit_flip_anywhere_is_detected(tmp_path):
    key, enc = make(tmp_path, os.urandom(3 * CS + 5))
    original = enc.read_bytes()
    for offset in _flip_offsets(len(original)):
        tampered = bytearray(original)
        tampered[offset] ^= 0x01
        enc.write_bytes(bytes(tampered))
        assert_rejected(tmp_path, enc, key)


# ---- attack: chunk swap / duplicate / splice -------------------------------

def test_chunk_swap_is_detected(tmp_path):
    key, enc = make(tmp_path, os.urandom(3 * CS + 5))
    header, recs = split(enc.read_bytes())
    recs[0], recs[1] = recs[1], recs[0]
    enc.write_bytes(join(header, recs))
    assert_rejected(tmp_path, enc, key)


def test_chunk_duplicate_over_another_is_detected(tmp_path):
    key, enc = make(tmp_path, os.urandom(3 * CS + 5))
    header, recs = split(enc.read_bytes())
    recs[1] = recs[0]
    enc.write_bytes(join(header, recs))
    assert_rejected(tmp_path, enc, key)


def test_chunk_from_another_file_is_detected(tmp_path):
    key, enc = make(tmp_path, os.urandom(3 * CS + 5))
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    _, other_enc = make(other_dir, os.urandom(3 * CS + 5))
    header, recs = split(enc.read_bytes())
    _, other_recs = split(other_enc.read_bytes())
    recs[1] = other_recs[1]
    enc.write_bytes(join(header, recs))
    assert_rejected(tmp_path, enc, key)


# ---- attack: truncation (needs the final-chunk flag) ------------------------

def test_dropping_last_chunk_is_detected(tmp_path):
    key, enc = make(tmp_path, os.urandom(3 * CS + 5))
    header, recs = split(enc.read_bytes())
    enc.write_bytes(join(header, recs[:-1]))
    assert_rejected(tmp_path, enc, key)


def test_dropping_last_chunk_of_exact_multiple_is_detected(tmp_path):
    key, enc = make(tmp_path, os.urandom(3 * CS))
    header, recs = split(enc.read_bytes())
    assert len(recs) == 3 and len(recs[-1]) == REC
    enc.write_bytes(join(header, recs[:-1]))
    assert_rejected(tmp_path, enc, key)


def test_dropping_several_chunks_is_detected(tmp_path):
    key, enc = make(tmp_path, os.urandom(5 * CS + 1))
    header, recs = split(enc.read_bytes())
    for keep in (1, 2, 3, 4):
        enc.write_bytes(join(header, recs[:keep]))
        assert_rejected(tmp_path, enc, key)


def test_cutting_mid_chunk_is_detected(tmp_path):
    key, enc = make(tmp_path, os.urandom(3 * CS + 5))
    blob = enc.read_bytes()
    for cut in (1, 10, 20, 40):
        enc.write_bytes(blob[:-cut])
        assert_rejected(tmp_path, enc, key)


def test_header_only_empty_or_partial_header_is_detected(tmp_path):
    key, enc = make(tmp_path, os.urandom(3 * CS))
    blob = enc.read_bytes()
    for piece in (blob[:HL], blob[:HL - 1], b""):
        enc.write_bytes(piece)
        assert_rejected(tmp_path, enc, key)


def test_empty_file_cannot_be_emptied_further(tmp_path):
    key, enc = make(tmp_path, b"")
    blob = enc.read_bytes()
    enc.write_bytes(blob[:HL])           # strip the single empty final chunk
    assert_rejected(tmp_path, enc, key)


# ---- attack: extension --------------------------------------------------

def test_appending_a_chunk_is_detected(tmp_path):
    key, enc = make(tmp_path, os.urandom(3 * CS + 5))
    header, recs = split(enc.read_bytes())
    enc.write_bytes(join(header, recs + [recs[0]]))
    assert_rejected(tmp_path, enc, key)


def test_appending_garbage_is_detected(tmp_path):
    key, enc = make(tmp_path, os.urandom(3 * CS + 5))
    enc.write_bytes(enc.read_bytes() + os.urandom(10))
    assert_rejected(tmp_path, enc, key)


def test_appending_a_copy_of_the_final_chunk_is_detected(tmp_path):
    key, enc = make(tmp_path, os.urandom(3 * CS))
    header, recs = split(enc.read_bytes())
    enc.write_bytes(join(header, recs + [recs[-1]]))
    assert_rejected(tmp_path, enc, key)


# ---- wrong key / wrong file ID / not a vault file -----------------------------

def test_wrong_data_key_is_detected(tmp_path):
    _, enc = make(tmp_path, os.urandom(2 * CS))
    assert_rejected(tmp_path, enc, vc.generate_data_key())


def test_wrong_file_id_is_detected(tmp_path):
    key, enc = make(tmp_path, os.urandom(2 * CS))
    assert_rejected(tmp_path, enc, key, file_id="F-000000000002")


def test_random_file_is_rejected(tmp_path):
    enc = tmp_path / "x.enc"
    enc.write_bytes(os.urandom(500))
    assert_rejected(tmp_path, enc, vc.generate_data_key())


def test_huge_chunk_size_in_header_is_rejected(tmp_path):
    key, enc = make(tmp_path, os.urandom(2 * CS))
    blob = bytearray(enc.read_bytes())
    blob[5:9] = (vc.MAX_CHUNK_SIZE + 1).to_bytes(4, "big")
    enc.write_bytes(bytes(blob))
    assert_rejected(tmp_path, enc, key)


# ---- failure behaviour ------------------------------------------------------

def test_failed_decrypt_does_not_touch_an_existing_output(tmp_path):
    key, enc = make(tmp_path, os.urandom(3 * CS))
    blob = bytearray(enc.read_bytes())
    blob[-1] ^= 0x01
    enc.write_bytes(bytes(blob))
    out = tmp_path / "out.bin"
    out.write_bytes(b"precious")
    with pytest.raises(vc.IntegrityError):
        vc.decrypt_file(enc, out, key, FID)
    assert out.read_bytes() == b"precious"
    assert not (tmp_path / "out.bin.part").exists()


def test_tamper_in_last_chunk_leaves_no_plaintext_even_though_earlier_chunks_were_ok(tmp_path):
    key, enc = make(tmp_path, os.urandom(4 * CS))
    blob = bytearray(enc.read_bytes())
    blob[-1] ^= 0x01
    enc.write_bytes(bytes(blob))
    assert_rejected(tmp_path, enc, key)
