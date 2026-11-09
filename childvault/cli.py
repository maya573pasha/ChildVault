"""
cli.py - ChildVault command-line interface (Typer).

Run with:   python -m childvault --help

Each command is a small function. Teammates add their commands here
(add-file, open-file, verify, share, ...) following the same pattern.
"""

import sqlite3
from enum import Enum
from pathlib import Path

import typer

from . import __version__, config, db
from . import vault_crypto as vc

MIN_PASSPHRASE_LEN = 8

app = typer.Typer(
    help="ChildVault: encrypted, tamper-evident storage for child-behaviour data.",
    no_args_is_help=True,
    add_completion=False,
)


def fail(message: str) -> None:
    """Print an error in red and stop with exit code 1."""
    typer.secho(f"Error: {message}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code=1)


def not_implemented(owner: str, phase: int) -> None:
    """Placeholder body for a command a teammate will fill in."""
    fail(f"not implemented yet (owner: {owner}, Phase {phase})")


def passphrase_option():
    """
    The --passphrase option for every command that needs the KEK.
    Asked interactively (hidden) if not given. A new object is made per
    command because Typer options should not be shared between commands.
    """
    return typer.Option(
        ..., prompt="Vault passphrase", hide_input=True,
        help="Vault passphrase (asked interactively if omitted).",
    )


def unlock_vault(passphrase: str) -> tuple[sqlite3.Connection, bytes]:
    """
    Open the existing vault and derive the KEK from the passphrase.

    Returns (conn, kek). The caller must close conn. Exits with a clear
    error if there is no vault or the passphrase is wrong.
    """
    # Check first: sqlite3.connect() would silently CREATE an empty database.
    if not config.get_db_path().is_file():
        fail(f"no vault found in {config.get_vault_dir()} - run `childvault init` first")

    conn = db.connect()
    try:
        header = db.load_header(conn)
        kek = vc.unlock(passphrase, header)
    except db.VaultNotInitializedError:
        conn.close()
        fail("vault is not initialized - run `childvault init` first")
    except vc.WrongPassphraseError:
        conn.close()
        fail("wrong passphrase")
    except vc.VaultCryptoError as exc:
        conn.close()
        fail(f"vault header is damaged: {exc}")
    return conn, kek


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"childvault {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True,
        help="Show the version and exit.",
    ),
) -> None:
    """Options that apply to every command."""


@app.command()
def init(
    passphrase: str = typer.Option(
        ..., prompt="Choose a vault passphrase", hide_input=True,
        confirmation_prompt=True, help="Master passphrase (asked interactively if omitted).",
    ),
) -> None:
    """Create a new, empty vault protected by a passphrase."""
    if len(passphrase) < MIN_PASSPHRASE_LEN:
        fail(f"passphrase must be at least {MIN_PASSPHRASE_LEN} characters")

    vault_dir = config.ensure_vault_dirs()
    conn = db.connect()
    try:
        db.create_schema(conn)
        if db.is_initialized(conn):
            fail(f"a vault already exists in {vault_dir}")
        header = vc.new_vault_header(passphrase)
        db.save_header(conn, header)
    finally:
        conn.close()

    typer.secho(f"Vault created in {vault_dir.resolve()}", fg=typer.colors.GREEN)
    typer.echo("Keep your passphrase safe: it cannot be recovered.")


@app.command()
def status(passphrase: str = passphrase_option()) -> None:
    """Check the passphrase and show a summary of the vault."""
    conn, _kek = unlock_vault(passphrase)
    try:
        n_files = len(db.list_files(conn))
        n_log = len(db.get_audit_rows(conn))
    finally:
        conn.close()

    typer.secho("Vault unlocked.", fg=typer.colors.GREEN)
    typer.echo(f"Location:     {config.get_vault_dir().resolve()}")
    typer.echo(f"Files:        {n_files}")
    typer.echo(f"Log entries:  {n_log}")


# ==========================================================================
# STUB COMMANDS - the interface is fixed here; owners replace the body.
# Keep the names and arguments unless the team agrees to change them.
# ==========================================================================

class FileType(str, Enum):
    """Allowed --type values. Must match db.FILE_TYPES (a test checks this)."""
    video = "video"
    csv = "csv"
    annotation = "annotation"
    other = "other"


# ---------------------------------------------------------------- Aaleen

@app.command("add-file")
def add_file(
    path: Path = typer.Argument(..., exists=True, dir_okay=False, help="File to encrypt into the vault."),
    file_type: FileType = typer.Option(FileType.other, "--type", help="Kind of file."),
    child_id: str = typer.Option(None, "--child", help="Pseudonym the file belongs to, e.g. CH-4F7A."),
) -> None:
    """Encrypt a file into the vault (AES-256-GCM, own random key)."""
    not_implemented("Aaleen", 2)


@app.command("open-file")
def open_file(
    file_id: str = typer.Argument(..., help="Vault file ID, e.g. F-3f9a1c0b7e2d4a65."),
    out: Path = typer.Option(..., "--out", help="Where to write the decrypted file."),
) -> None:
    """Decrypt a file from the vault (fails if it was tampered with)."""
    not_implemented("Aaleen", 2)


@app.command()
def revoke(
    file_id: str = typer.Argument(..., help="File to re-encrypt under a new key."),
) -> None:
    """Revoke shared access by re-encrypting a file under a new key."""
    not_implemented("Aaleen", 3)


# ---------------------------------------------------------------- Mariyam

@app.command()
def pseudonymize(
    name: str = typer.Argument(..., help="Real name of the child."),
) -> None:
    """Give a child a random pseudonym (e.g. CH-4F7A)."""
    not_implemented("Mariyam", 2)


@app.command()
def lookup(
    child_id: str = typer.Argument(..., help="Pseudonym to resolve, e.g. CH-4F7A."),
) -> None:
    """Show the real name behind a pseudonym (owner only)."""
    not_implemented("Mariyam", 2)


@app.command()
def share(
    file_ids: list[str] = typer.Argument(..., help="One or more file IDs to share."),
    reviewer_key: Path = typer.Option(..., "--reviewer-key", help="Reviewer's X25519 public key file."),
    expires: str = typer.Option(..., "--expires", help="Expiry date, e.g. 2026-12-31."),
    out: Path = typer.Option(..., "--out", help="Where to write the share bundle."),
) -> None:
    """Create a signed, time-limited share bundle for a reviewer."""
    not_implemented("Mariyam", 3)


@app.command("import-bundle")
def import_bundle(
    bundle: Path = typer.Argument(..., help="Share bundle file received from the owner."),
) -> None:
    """Import a share bundle as a reviewer (checks signature and expiry)."""
    not_implemented("Mariyam", 3)


# ---------------------------------------------------------------- Laiba

@app.command()
def verify() -> None:
    """Walk the audit hash chain and report any tampering."""
    not_implemented("Laiba", 2)


audit_app = typer.Typer(help="Audit log commands.", no_args_is_help=True)
app.add_typer(audit_app, name="audit")


@audit_app.command("show")
def audit_show(
    limit: int = typer.Option(20, "--limit", min=1, help="How many recent entries to show."),
) -> None:
    """Print the most recent audit log entries."""
    not_implemented("Laiba", 2)
