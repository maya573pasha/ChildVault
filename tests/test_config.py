from pathlib import Path

from childvault import config


def test_default_vault_dir(monkeypatch):
    monkeypatch.delenv(config.ENV_VAR, raising=False)
    assert config.get_vault_dir() == Path("vault_data")


def test_env_var_overrides_vault_dir(monkeypatch, tmp_path):
    monkeypatch.setenv(config.ENV_VAR, str(tmp_path))
    assert config.get_vault_dir() == tmp_path
    assert config.get_db_path() == tmp_path / "childvault.db"
    assert config.get_files_dir() == tmp_path / "files"


def test_ensure_vault_dirs_creates_folders(monkeypatch, tmp_path):
    vault = tmp_path / "myvault"
    monkeypatch.setenv(config.ENV_VAR, str(vault))
    assert config.ensure_vault_dirs() == vault
    assert (vault / "files").is_dir()
    # calling it again must not fail
    config.ensure_vault_dirs()
