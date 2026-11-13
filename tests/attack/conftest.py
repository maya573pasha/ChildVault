"""
conftest for tests/attack/: the `attack` marker, the optional results table, and
the scenario fixtures. The scenario itself lives in attack_support.py.

  @pytest.mark.attack("what the attacker does", "what must happen")
  ATTACK_REPORT=attack_results.md  ->  Markdown table of every attack + PASS/FAIL
"""
import os
from pathlib import Path

import pytest

from attack_support import build_world
from childvault import config

_RESULTS: list[tuple[str, str, str]] = []


def pytest_configure(config):
    config.addinivalue_line("markers", "attack(name, expected): one attack and what must happen")


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    marker = item.get_closest_marker("attack")
    if marker is None or report.when != "call":
        return
    name = marker.args[0] if marker.args else item.name
    callspec = getattr(item, "callspec", None)
    if callspec is not None:
        name += f"  [{callspec.id}]"
    expected = marker.args[1] if len(marker.args) > 1 else ""
    _RESULTS.append((name, expected, "PASS" if report.passed else "FAIL"))


def pytest_sessionfinish(session):
    target = os.environ.get("ATTACK_REPORT")
    if not target or not _RESULTS:
        return
    lines = ["| # | Attack | Expected | Result |", "|---|---|---|---|"]
    for i, (name, expected, result) in enumerate(_RESULTS, 1):
        lines.append(f"| {i} | {name} | {expected} | {result} |")
    passed = sum(1 for r in _RESULTS if r[2] == "PASS")
    lines.append("")
    lines.append(f"{passed} of {len(_RESULTS)} attacks behaved exactly as expected.")
    Path(target).write_text("\n".join(lines) + "\n", encoding="utf-8")


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    mp = pytest.MonkeyPatch()
    base = tmp_path_factory.mktemp("attack_world")
    mp.setenv(config.ENV_VAR, str(base / "vault"))
    yield build_world(base)
    mp.undo()


@pytest.fixture
def fresh_world(tmp_path, monkeypatch):
    """A separate scenario for attacks that change the vault (e.g. revoke)."""
    monkeypatch.setenv(config.ENV_VAR, str(tmp_path / "vault"))
    return build_world(tmp_path)