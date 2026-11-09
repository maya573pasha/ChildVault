"""
cli.py - ChildVault command line (Phase 2: init, add-file, open-file)

Standalone version: the vault is a plain folder, no database yet.

    <vault>/
        vault.json          header from vault_crypto.new_vault_header
        files/F-xxxxxxxxxxxx.enc   encrypted file
        files/F-xxxxxxxxxxxx.key   its data key, wrapped under the KEK

Original file names are deliberately NOT stored (they can contain a child's name).

Usage:
    python cli.py init
    python cli.py add-file path/to/recording.mp4
    python cli.py open-file F-1a2b3c4d5e6f out.mp4
"""

import json
import re
import secrets
from pathlib import Path

import typer

from . import vault_crypto as vc

app = typer.Typer(help="ChildVault: encrypted, tamper-evident storage for child-behaviour data.",
                  no_args_is_help=True)

DEFAULT_VAULT = Path("vault_data")
HEADER_NAME = "vault.json"
FILES_DIR = "files"
FILE_ID_RE = re.compile(r"^F-[0-9a-f]{12}$")

VaultOpt = typer.Option(DEFAULT_VAULT, "--vault", "-v", help="Vault folder.")


def _fail(message: str) -> None:
    typer.echo(f"Error: {message}", err=True)
    raise typer.Exit(code=1)


def _unlock(vault: Path) -> bytes:
    header_path = vault / HEADER_NAME
    if not header_path.is_file():
        _fail(f"no vault found at '{vault}'. Run 'init' first.")
    try:
        header = json.loads(header_path.read_text())
    except (OSError, ValueError):
        _fail("vault header is unreadable or corrupted.")
    passphrase = typer.prompt("Passphrase", hide_input=True)
    try:
        return vc.unlock(passphrase, header)
    except vc.VaultCryptoError as exc:
        _fail(str(exc))
    except ValueError as exc:
        _fail(str(exc))


@app.command()
def init(vault: Path = VaultOpt) -> None:
    """Create a new vault and set its passphrase."""
    header_path = vault / HEADER_NAME
    if header_path.exists():
        _fail(f"a vault already exists at '{vault}'.")
    passphrase = typer.prompt("New passphrase", hide_input=True, confirmation_prompt=True)
    try:
        header = vc.new_vault_header(passphrase)
    except ValueError as exc:
        _fail(str(exc))
    (vault / FILES_DIR).mkdir(parents=True, exist_ok=True)
    header_path.write_text(json.dumps(header, indent=2))
    typer.echo(f"Vault created at '{vault}'.")


@app.command("add-file")
def add_file(
    path: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True,
                                help="File to encrypt into the vault."),
    vault: Path = VaultOpt,
) -> None:
    """Encrypt a file into the vault and print its file ID."""
    kek = _unlock(vault)
    files_dir = vault / FILES_DIR
    files_dir.mkdir(parents=True, exist_ok=True)

    file_id = _new_file_id(files_dir)
    data_key = vc.generate_data_key()
    enc_path = files_dir / f"{file_id}.enc"
    key_path = files_dir / f"{file_id}.key"
    try:
        vc.encrypt_file(path, enc_path, data_key, file_id)
        key_path.write_bytes(vc.wrap_key(kek, data_key, file_id))
    except (vc.VaultCryptoError, OSError) as exc:
        enc_path.unlink(missing_ok=True)
        key_path.unlink(missing_ok=True)
        _fail(str(exc))
    typer.echo(f"Added {file_id}")


@app.command("open-file")
def open_file(
    file_id: str = typer.Argument(..., help="File ID printed by add-file, e.g. F-1a2b3c4d5e6f."),
    out: Path = typer.Argument(..., help="Where to write the decrypted file."),
    vault: Path = VaultOpt,
) -> None:
    """Decrypt a file from the vault to a path you choose."""
    if not FILE_ID_RE.match(file_id):
        _fail("invalid file ID.")
    files_dir = vault / FILES_DIR
    enc_path = files_dir / f"{file_id}.enc"
    key_path = files_dir / f"{file_id}.key"
    if not enc_path.is_file() or not key_path.is_file():
        _fail(f"file '{file_id}' not found in the vault.")
    if out.exists():
        _fail(f"'{out}' already exists; choose a new output path.")

    kek = _unlock(vault)
    try:
        data_key = vc.unwrap_key(kek, key_path.read_bytes(), file_id)
        vc.decrypt_file(enc_path, out, data_key, file_id)
    except vc.VaultCryptoError as exc:
        _fail(str(exc))
    except OSError as exc:
        _fail(str(exc))
    typer.echo(f"Decrypted {file_id} to '{out}'")


def _new_file_id(files_dir: Path) -> str:
    while True:
        file_id = "F-" + secrets.token_hex(6)
        if not (files_dir / f"{file_id}.enc").exists():
            return file_id


if __name__ == "__main__":
    app()