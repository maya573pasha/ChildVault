"""
cli.py - ChildVault command-line interface (Typer).

Run with:   python -m childvault --help

Each command is a small function. Teammates add their commands here
(add-file, open-file, verify, share, ...) following the same pattern.
"""

import re
import sqlite3
from enum import Enum
from pathlib import Path

import typer

from . import __version__, config, db
from . import identity as idm
from . import keyshare as ks
from . import vault_crypto as vc

MIN_PASSPHRASE_LEN = 8
FILE_ID_RE = re.compile(r"^F-[0-9a-f]{16}$")      # matches db.new_file_id()

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


def load_identity_map(kek: bytes) -> idm.IdentityMap:
    """Load and decrypt identity_map.enc, turning its errors into clear CLI messages."""
    try:
        return idm.load_map(kek, config.get_identity_map_path())
    except idm.MapMissingError:
        fail("identity map is missing - it may have been deleted (restore it from a backup)")
    except idm.MapIntegrityError:
        fail("identity map failed its integrity check - it was modified or damaged")


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
        # Create the (empty) encrypted ID-name map BEFORE saving the header:
        # a vault never exists without its map, so a missing map later
        # always means deletion or damage.
        kek = vc.unlock(passphrase, header)
        idm.save_map(kek, idm.IdentityMap(), config.get_identity_map_path())
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
    passphrase: str = passphrase_option(),
) -> None:
    """Encrypt a file into the vault (AES-256-GCM, own random key)."""
    cid = None
    if child_id is not None:
        try:
            cid = idm.normalize_child_id(child_id)    # reject bad input before unlocking
        except idm.InvalidChildIDError as exc:
            fail(str(exc))

    conn, kek = unlock_vault(passphrase)
    try:
        if cid is not None:
            imap = load_identity_map(kek)
            if cid not in imap.ids():
                fail(f"no child with id {cid} - run `childvault pseudonymize` first")

        files_dir = config.get_files_dir()
        files_dir.mkdir(parents=True, exist_ok=True)
        file_id = db.new_file_id()
        while (files_dir / f"{file_id}.enc").exists():
            file_id = db.new_file_id()
        enc_path = files_dir / f"{file_id}.enc"

        data_key = vc.generate_data_key()
        try:
            vc.encrypt_file(path, enc_path, data_key, file_id)
            db.add_file_record(
                conn, file_id, vc.wrap_key(kek, data_key, file_id), file_type.value,
                path.suffix, "owner", child_id=cid, plaintext_size=path.stat().st_size,
            )
        except (vc.VaultCryptoError, db.VaultDBError, OSError) as exc:
            enc_path.unlink(missing_ok=True)          # no orphan blob without a record
            fail(str(exc))
    finally:
        conn.close()

    typer.secho(f"Added {file_id}", fg=typer.colors.GREEN)


@app.command("open-file")
def open_file(
    file_id: str = typer.Argument(..., help="Vault file ID, e.g. F-3f9a1c0b7e2d4a65."),
    out: Path = typer.Option(..., "--out", help="Where to write the decrypted file."),
    passphrase: str = passphrase_option(),
) -> None:
    """Decrypt a file from the vault (fails if it was tampered with)."""
    # Strict format check first: the ID becomes part of a path, so no "../".
    if not FILE_ID_RE.match(file_id):
        fail("invalid file ID")
    if out.exists():
        fail(f"'{out}' already exists; choose a new output path")

    conn, kek = unlock_vault(passphrase)
    try:
        try:
            row = db.get_file(conn, file_id)
        except db.FileNotInVaultError:
            fail(f"file '{file_id}' not found in the vault")
        enc_path = config.get_files_dir() / f"{file_id}.enc"
        if not enc_path.is_file():
            fail(f"encrypted data for '{file_id}' is missing from the vault folder")
        try:
            data_key = vc.unwrap_key(kek, bytes(row["wrapped_key"]), file_id)
            vc.decrypt_file(enc_path, out, data_key, file_id)
        except vc.VaultCryptoError as exc:
            fail(str(exc))
        except OSError as exc:
            fail(str(exc))
    finally:
        conn.close()

    typer.secho(f"Decrypted {file_id} to '{out}'", fg=typer.colors.GREEN)


@app.command()
def revoke(
    file_id: str = typer.Argument(..., help="File to re-encrypt under a new key."),
) -> None:
    """Revoke shared access by re-encrypting a file under a new key."""
    not_implemented("Aaleen", 3)


# ---------------------------------------------------------------- Mariyam

@app.command()
def pseudonymize(
    name: str = typer.Option(
        ..., "--name", prompt="Child's real name",
        help="Real name (asked interactively if omitted, so it stays out of shell history).",
    ),
    passphrase: str = passphrase_option(),
) -> None:
    """Give a child a random pseudonym (e.g. CH-4F7A)."""
    conn, kek = unlock_vault(passphrase)
    conn.close()                                  # the map lives outside the DB

    imap = load_identity_map(kek)
    try:
        child_id = imap.add(name)
    except idm.IdentityError as exc:
        fail(str(exc))
    idm.save_map(kek, imap, config.get_identity_map_path())

    typer.secho(f"Pseudonym: {child_id}", fg=typer.colors.GREEN)
    typer.echo("Use this ID everywhere instead of the child's name.")


@app.command()
def lookup(
    child_id: str = typer.Argument(..., help="Pseudonym to resolve, e.g. CH-4F7A."),
    passphrase: str = passphrase_option(),
) -> None:
    """Show the real name behind a pseudonym (owner only)."""
    try:
        cid = idm.normalize_child_id(child_id)    # reject bad input before unlocking
    except idm.InvalidChildIDError as exc:
        fail(str(exc))

    conn, kek = unlock_vault(passphrase)
    try:
        n_files = len(db.list_files(conn, cid))
    finally:
        conn.close()

    imap = load_identity_map(kek)
    try:
        name = imap.lookup(cid)
    except idm.UnknownChildIDError as exc:
        fail(str(exc))

    typer.echo(f"{cid}  ->  {name}")
    typer.echo(f"Files in vault for this child: {n_files}")


@app.command()
def web(
    port: int = typer.Option(8000, "--port", min=1024, max=65535, help="Port on 127.0.0.1."),
) -> None:
    """Start the local web UI at http://127.0.0.1:<port> (this computer only)."""
    if not config.get_db_path().is_file():
        fail(f"no vault found in {config.get_vault_dir()} - run `childvault init` first")

    import uvicorn                                  # imported here: only this command needs it
    from .web.app import create_app

    typer.echo(f"ChildVault web UI on http://127.0.0.1:{port}  (Ctrl+C to stop)")
    uvicorn.run(create_app(), host="127.0.0.1", port=port, log_level="warning",
                server_header=False)       # don't advertise the server software


@app.command()
def keygen(
    out: Path = typer.Option(
        Path("reviewer"), "--out",
        help="Base name: writes <out>.key (private, encrypted) and <out>.pub (public).",
    ),
    passphrase: str = typer.Option(
        ..., prompt="Choose a passphrase for your private key", hide_input=True,
        confirmation_prompt=True, help="Protects the private key file.",
    ),
) -> None:
    """(Reviewer) Create an X25519 key pair for receiving share bundles."""
    if len(passphrase) < MIN_PASSPHRASE_LEN:
        fail(f"passphrase must be at least {MIN_PASSPHRASE_LEN} characters")

    key_path = out.with_name(out.name + ".key")
    pub_path = out.with_name(out.name + ".pub")
    for p in (key_path, pub_path):
        if p.exists():
            fail(f"{p} already exists - refusing to overwrite a key")

    priv, pub = ks.generate_reviewer_keypair()
    ks.save_private_key(priv, key_path, passphrase)
    ks.save_public_key(pub, pub_path)

    typer.secho(f"Private key: {key_path}  (keep secret)", fg=typer.colors.GREEN)
    typer.secho(f"Public key:  {pub_path}  (send this to the vault owner)", fg=typer.colors.GREEN)
    typer.echo(f"Fingerprint: {ks.fingerprint(pub)}")
    typer.echo("Read this fingerprint to the owner by phone or in person.")


@app.command()
def fingerprint(
    pub_key: Path = typer.Argument(..., help="An X25519 public key file (.pub)."),
) -> None:
    """Show the fingerprint of a public key, to confirm it really is the reviewer's."""
    try:
        pub = ks.load_public_key(pub_key)
    except ks.KeyFileError as exc:
        fail(str(exc))
    typer.echo(ks.fingerprint(pub))


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
