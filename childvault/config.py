"""
config.py - where the vault lives on disk.

Every other module asks this file for paths instead of hard-coding them,
so the location can be changed in one place (and tests can point the
vault at a temporary folder).

Layout of a vault folder:
    vault_data/
        childvault.db      SQLite: vault header, file metadata, audit log
        files/             encrypted file blobs (<file_id>.enc)
"""

import os
from pathlib import Path

# Environment variable that overrides the vault location.
ENV_VAR = "CHILDVAULT_HOME"

# Used when the environment variable is not set. Relative to the folder
# the command is run from. Already listed in .gitignore.
DEFAULT_VAULT_DIR = "vault_data"

DB_FILENAME = "childvault.db"
FILES_DIRNAME = "files"


def get_vault_dir() -> Path:
    """Folder holding the whole vault. $CHILDVAULT_HOME wins over the default."""
    return Path(os.environ.get(ENV_VAR, DEFAULT_VAULT_DIR))


def get_db_path() -> Path:
    """Path of the SQLite database inside the vault folder."""
    return get_vault_dir() / DB_FILENAME


def get_files_dir() -> Path:
    """Folder where encrypted file blobs are stored."""
    return get_vault_dir() / FILES_DIRNAME


def ensure_vault_dirs() -> Path:
    """Create the vault folder and files/ subfolder if missing. Returns the vault folder."""
    get_files_dir().mkdir(parents=True, exist_ok=True)
    return get_vault_dir()
