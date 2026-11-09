import pytest

from childvault import identity as idm


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
