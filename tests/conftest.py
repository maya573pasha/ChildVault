
"""Shared pytest fixtures for ChildVault. Everything uses synthetic data only."""
import shutil, sys
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from generate_synthetic import generate  # noqa: E402

PASSPHRASE = "correct horse battery staple (test only)"


@pytest.fixture(scope="session")
def synthetic_dir(tmp_path_factory):
    """Generated once per test run. Treat as READ-ONLY; use sample_files if you need to modify."""
    d = tmp_path_factory.mktemp("synthetic")
    generate(d, seed=42)
    return d


@pytest.fixture
def work_dir(tmp_path):
    """Fresh empty directory per test (use for vault root / outputs)."""
    return tmp_path


@pytest.fixture
def sample_files(synthetic_dir, tmp_path):
    """Per-test COPIES of the synthetic files, safe to tamper with (bit-flip etc.). name -> Path."""
    dst = tmp_path / "samples"
    shutil.copytree(synthetic_dir, dst)
    return {p.name: p for p in dst.iterdir()}


@pytest.fixture
def passphrase():
    return PASSPHRASE