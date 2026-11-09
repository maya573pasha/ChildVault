import pytest
from typer.testing import CliRunner

from childvault import __version__, config, db
from childvault import vault_crypto as vc
from childvault.cli import app

runner = CliRunner()
PW = "correct horse battery"


@pytest.fixture(autouse=True)
def temp_vault(monkeypatch, tmp_path):
    """Every CLI test gets its own empty vault folder."""
    monkeypatch.setenv(config.ENV_VAR, str(tmp_path / "vault"))
    return tmp_path / "vault"


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_no_args_shows_help():
    result = runner.invoke(app, [])
    assert "init" in result.output


def test_init_creates_vault(temp_vault):
    result = runner.invoke(app, ["init"], input=f"{PW}\n{PW}\n")
    assert result.exit_code == 0, result.output
    assert (temp_vault / "files").is_dir()
    conn = db.connect()
    try:
        assert len(vc.unlock(PW, db.load_header(conn))) == 32
    finally:
        conn.close()


def test_passphrase_not_echoed():
    result = runner.invoke(app, ["init"], input=f"{PW}\n{PW}\n")
    assert PW not in result.output


def test_init_twice_refused():
    runner.invoke(app, ["init", "--passphrase", PW])
    result = runner.invoke(app, ["init", "--passphrase", "another passphrase"])
    assert result.exit_code == 1
    assert "already exists" in result.output
    conn = db.connect()
    try:
        vc.unlock(PW, db.load_header(conn))   # original passphrase still works
    finally:
        conn.close()


def test_short_passphrase_refused(temp_vault):
    result = runner.invoke(app, ["init", "--passphrase", "short"])
    assert result.exit_code == 1
    assert not temp_vault.exists()            # nothing created


def test_mismatched_confirmation_refused():
    result = runner.invoke(app, ["init"], input=f"{PW}\nsomething else\n{PW}\n{PW}\n")
    assert "do not match" in result.output.lower()
