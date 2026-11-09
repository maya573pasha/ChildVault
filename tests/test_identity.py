import pytest

from childvault import identity as idm
from childvault import vault_crypto as vc


def test_random_id_format():
    for _ in range(500):
        cid = idm.random_child_id()
        assert idm.is_valid_child_id(cid), cid
        assert len(cid) == 7                    # "CH-" + 4 hex


def test_random_ids_are_spread_out():
    ids = {idm.random_child_id() for _ in range(200)}
    assert len(ids) > 190                       # a few repeats are expected, not many


def test_new_id_avoids_existing(monkeypatch):
    """Force the generator to return a taken ID first, then a free one."""
    draws = iter(["CH-AAAA", "CH-AAAA", "CH-BBBB"])
    monkeypatch.setattr(idm, "random_child_id", lambda: next(draws))
    assert idm.new_child_id({"CH-AAAA"}) == "CH-BBBB"


def test_new_id_gives_up_when_space_is_full(monkeypatch):
    monkeypatch.setattr(idm, "random_child_id", lambda: "CH-AAAA")
    with pytest.raises(idm.IDSpaceExhaustedError):
        idm.new_child_id({"CH-AAAA"})


def test_many_new_ids_are_all_unique():
    taken = set()
    for _ in range(2000):                       # far past the ~300 "birthday" point
        taken.add(idm.new_child_id(taken))
    assert len(taken) == 2000


@pytest.mark.parametrize("raw, expected", [
    ("CH-4F7A", "CH-4F7A"),
    ("ch-4f7a", "CH-4F7A"),
    ("  CH-00ff ", "CH-00FF"),
])
def test_normalize_accepts(raw, expected):
    assert idm.normalize_child_id(raw) == expected


@pytest.mark.parametrize("raw", ["", "CH-4F7", "CH-4F7AB", "CH-4G7A", "XX-4F7A", "CH4F7A", "Ali Khan"])
def test_normalize_rejects(raw):
    with pytest.raises(idm.InvalidChildIDError):
        idm.normalize_child_id(raw)


def test_collision_probability_matches_birthday_problem():
    assert idm.collision_probability(1) == 0.0
    assert idm.collision_probability(100) == pytest.approx(0.0727, abs=0.001)
    assert idm.collision_probability(301) == pytest.approx(0.50, abs=0.01)
    assert idm.collision_probability(1000) > 0.99


# ---------------------------------------------------------------- IdentityMap (memory)

FAST = {"n": 2 ** 10, "r": 8, "p": 1}


@pytest.fixture
def kek():
    return vc.derive_kek("pw", b"s" * 16, FAST)


def test_add_and_lookup():
    m = idm.IdentityMap()
    cid = m.add("  Test Child One ")
    assert idm.is_valid_child_id(cid)
    assert m.lookup(cid) == "Test Child One"           # name trimmed
    assert m.lookup(cid.lower()) == "Test Child One"   # lookup normalises
    assert len(m) == 1


def test_same_name_twice_gets_two_ids():
    """Two different children can share a name; each gets its own ID."""
    m = idm.IdentityMap()
    assert m.add("Sam") != m.add("Sam")


def test_empty_name_rejected():
    with pytest.raises(idm.IdentityError):
        idm.IdentityMap().add("   ")


def test_lookup_unknown_id():
    with pytest.raises(idm.UnknownChildIDError):
        idm.IdentityMap().lookup("CH-0000")


# ---------------------------------------------------------------- encrypted map

def _filled_map():
    m = idm.IdentityMap()
    for name in ("Test Child One", "Test Child Two", "Test Child Three"):
        m.add(name)
    return m


def test_encrypt_decrypt_roundtrip(kek):
    m = _filled_map()
    back = idm.decrypt_map(kek, idm.encrypt_map(kek, m))
    assert back.entries == m.entries


def test_names_not_visible_in_ciphertext(kek):
    blob = idm.encrypt_map(kek, _filled_map())
    assert b"Test Child" not in blob
    assert b"CH-" not in blob          # even the pseudonyms are hidden


def test_fresh_key_and_nonce_every_save(kek):
    m = _filled_map()
    a, b = idm.encrypt_map(kek, m), idm.encrypt_map(kek, m)
    assert a != b
    hdr = idm._HEADER_LEN
    assert a[6:hdr] != b[6:hdr]                                  # different wrapped key
    assert a[hdr:hdr + 12] != b[hdr:hdr + 12]                    # different nonce


def test_wrong_kek_rejected(kek):
    other = vc.derive_kek("other", b"s" * 16, FAST)
    with pytest.raises(idm.MapIntegrityError):
        idm.decrypt_map(other, idm.encrypt_map(kek, _filled_map()))


@pytest.mark.parametrize("where", ["magic", "wrapped_key", "nonce", "ciphertext", "tag"])
def test_any_flipped_bit_detected(kek, where):
    blob = bytearray(idm.encrypt_map(kek, _filled_map()))
    pos = {"magic": 0, "wrapped_key": 10, "nonce": idm._HEADER_LEN + 1,
           "ciphertext": idm._HEADER_LEN + 12 + 5, "tag": len(blob) - 1}[where]
    blob[pos] ^= 0x01
    with pytest.raises(idm.MapIntegrityError):
        idm.decrypt_map(kek, bytes(blob))


@pytest.mark.parametrize("cut", [1, 16, 40, 200])
def test_truncated_map_detected(kek, cut):
    blob = idm.encrypt_map(kek, _filled_map())
    with pytest.raises(idm.MapIntegrityError):
        idm.decrypt_map(kek, blob[:-cut])


def test_file_key_cannot_be_used_as_map_key(kek):
    """A wrapped key for a vault FILE must not unlock the map (purpose binding)."""
    blob = bytearray(idm.encrypt_map(kek, _filled_map()))
    file_wrapped = vc.wrap_key(kek, vc.generate_data_key(), "F-0123456789abcdef")
    blob[6:idm._HEADER_LEN] = file_wrapped
    with pytest.raises(idm.MapIntegrityError):
        idm.decrypt_map(kek, bytes(blob))


# ---------------------------------------------------------------- files on disk

def test_save_and_load(tmp_path, kek):
    path = tmp_path / "identity_map.enc"
    m = _filled_map()
    idm.save_map(kek, m, path)
    assert idm.load_map(kek, path).entries == m.entries
    assert not (tmp_path / "identity_map.enc.tmp").exists()     # temp file renamed away


def test_save_overwrites_previous(tmp_path, kek):
    path = tmp_path / "identity_map.enc"
    m = idm.IdentityMap()
    idm.save_map(kek, m, path)
    cid = m.add("Test Child")
    idm.save_map(kek, m, path)
    assert idm.load_map(kek, path).lookup(cid) == "Test Child"


def test_missing_map_is_an_error_not_empty(tmp_path, kek):
    with pytest.raises(idm.MapMissingError):
        idm.load_map(kek, tmp_path / "nope.enc")
