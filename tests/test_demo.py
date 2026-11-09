"""Runs the whole demo, so it can't silently break before presentation day."""

import importlib.util
from pathlib import Path

DEMO_PATH = Path(__file__).resolve().parent.parent / "demo" / "demo.py"


def _load_demo():
    spec = importlib.util.spec_from_file_location("childvault_demo", DEMO_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_demo_end_to_end(capsys, tmp_path, monkeypatch):
    """One run (the demo is slow) checking three things."""
    demo = _load_demo()
    monkeypatch.setattr(demo.tempfile, "tempdir", str(tmp_path))

    assert demo.main([]) == 0
    out = capsys.readouterr().out

    # 1. every check in the demo passed
    assert "0 failed" in out and "[FAIL]" not in out
    # 2. no secrets are printed on screen (it may be projected or recorded)
    assert demo.PASSPHRASE not in out
    assert demo.REVIEWER_PASSPHRASE not in out
    assert "--name ****" in out
    # 3. the throw-away vault is deleted afterwards
    assert list(tmp_path.iterdir()) == []
