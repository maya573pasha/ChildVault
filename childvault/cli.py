"""
cli.py - ChildVault command-line interface (Typer).

Run with:   python -m childvault --help

Each command is a small function. Teammates add their commands here
(add-file, open-file, verify, share, ...) following the same pattern.
"""

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
