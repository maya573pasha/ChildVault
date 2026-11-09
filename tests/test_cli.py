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


# ---------------------------------------------------------------- stub commands

ALL_COMMANDS = ["init", "add-file", "open-file", "revoke", "pseudonymize",
                "lookup", "share", "import-bundle", "verify", "audit"]


def test_help_lists_every_command():
    output = runner.invoke(app, ["--help"]).output
    for name in ALL_COMMANDS:
        assert name in output


@pytest.mark.parametrize("args, owner", [
    (["open-file", "F-1", "--out", "x.mp4"], "Aaleen"),
    (["revoke", "F-1"], "Aaleen"),
    (["pseudonymize", "Test Child"], "Mariyam"),
    (["lookup", "CH-4F7A"], "Mariyam"),
    (["share", "F-1", "F-2", "--reviewer-key", "r.pub", "--expires", "2026-12-31", "--out", "b.json"], "Mariyam"),
    (["import-bundle", "b.json"], "Mariyam"),
    (["verify"], "Laiba"),
    (["audit", "show"], "Laiba"),
])
def test_stub_says_not_implemented_with_owner(args, owner):
    result = runner.invoke(app, args)
    assert result.exit_code == 1
    assert "not implemented" in result.output
    assert owner in result.output


def test_add_file_stub(tmp_path):
    f = tmp_path / "clip.mp4"
    f.write_bytes(b"x")
    result = runner.invoke(app, ["add-file", str(f), "--type", "video", "--child", "CH-4F7A"])
    assert result.exit_code == 1 and "Aaleen" in result.output


def test_add_file_rejects_missing_file():
    result = runner.invoke(app, ["add-file", "does-not-exist.mp4"])
    assert result.exit_code == 2        # Typer/Click usage error, before our code runs


def test_add_file_rejects_unknown_type(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"x")
    result = runner.invoke(app, ["add-file", str(f), "--type", "exe"])
    assert result.exit_code == 2


def test_file_type_choices_match_database():
    from childvault.cli import FileType
    assert tuple(t.value for t in FileType) == db.FILE_TYPES
