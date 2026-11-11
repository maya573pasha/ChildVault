"""
cli.py - ChildVault command-line interface (Typer).

Run with:   python -m childvault --help

Each command is a small function. Teammates add their commands here
(add-file, open-file, verify, share, ...) following the same pattern.
"""

import os
import re
import sqlite3
import tempfile
from enum import Enum
from pathlib import Path

import typer

from . import __version__, access, audit, config, db, users
from . import bundle as bnd
from . import ops
from . import identity as idm
from . import keyshare as ks
from . import vault_crypto as vc

MIN_PASSPHRASE_LEN = 8
FILE_ID_RE = ops.FILE_ID_RE

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


# Who is running the current command. Reset by main() at the start of EVERY run.
_session = {"user": users.OWNER_NAME, "actor": None}


def _current_username() -> str:
    return _session["user"]


def _remember_actor(actor: access.Actor) -> None:
    _session["actor"] = actor


def get_actor() -> access.Actor:
    """Who is running this command (set by unlock_vault; owner if not set)."""
    return _session["actor"] or access.Actor.owner()


def audited_op(conn, kek: bytes, action: str, file_id: str | None = None,
               details: dict | None = None, strict: bool = True):
    """`with audited_op(...) as ev:` = permission check + operation + audit entry (see access.py)."""
    return access.audited(conn, audit.derive_audit_key(kek), get_actor(), action,
                          file_id, details, strict=strict)


def _load_map(kek: bytes) -> idm.IdentityMap:
    """Like load_identity_map, but raises (so it can run inside `audited_op`) instead of exiting."""
    try:
        return idm.load_map(kek, config.get_identity_map_path())
    except idm.MapMissingError:
        raise ops.VaultFileError("identity map is missing - it may have been deleted (restore it from a backup)") from None
    except idm.MapIntegrityError:
        raise ops.VaultFileError("identity map failed its integrity check - it was modified or damaged") from None


# Errors every wired command turns into a clean message.
_OP_ERRORS = (access.PermissionDenied, audit.AuditError, users.UserError)


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
        kek, actor = users.authenticate(conn, _current_username(), passphrase, header)
        _remember_actor(actor)
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
    user: str = typer.Option(
        users.OWNER_NAME, "--user", envvar="CHILDVAULT_USER",
        help="Account to log in as (default: owner). Researchers: `childvault --user rana <command>`.",
    ),
) -> None:
    """Options that apply to every command."""
    _session["user"], _session["actor"] = user, None


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
    conn, kek = unlock_vault(passphrase)
    try:
        with audited_op(conn, kek, "status", strict=False):
            n_files = len(db.list_files(conn))
            n_log = len(db.get_audit_rows(conn))
    except _OP_ERRORS as exc:
        fail(str(exc))
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
        info = {"type": file_type.value, **({"child": cid} if cid else {})}
        with audited_op(conn, kek, "add_file", details=info) as ev:
            file_id = ops.add_file(conn, kek, path, file_type.value, cid,
                                   ops.safe_extension(path.name), added_by=get_actor().name)
            ev.file_id = file_id
    except (*_OP_ERRORS, ops.OpsError) as exc:
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
    try:                                              # cheap checks before the slow unlock
        ops.check_file_id(file_id)
        if out.exists():
            raise ops.InvalidInputError(f"'{out}' already exists; choose a new output path")
    except ops.OpsError as exc:
        fail(str(exc))

    conn, kek = unlock_vault(passphrase)
    try:
        with audited_op(conn, kek, "open_file", file_id=file_id):
            ops.open_file(conn, kek, file_id, out)
    except (*_OP_ERRORS, ops.OpsError) as exc:
        fail(str(exc))
    finally:
        conn.close()

    typer.secho(f"Decrypted {file_id} to '{out}'", fg=typer.colors.GREEN)


@app.command()
def revoke(
    file_id: str = typer.Argument(..., help="File to re-encrypt under a new key."),
    passphrase: str = passphrase_option(),
) -> None:
    """Revoke shared access by re-encrypting a file under a new key."""
    try:
        ops.check_file_id(file_id)
    except ops.OpsError as exc:
        fail(str(exc))

    conn, kek = unlock_vault(passphrase)
    try:
        with audited_op(conn, kek, "revoke", file_id=file_id) as ev:
            version = ops.revoke_file(conn, kek, file_id)
            ev.details["key_version"] = version
    except (*_OP_ERRORS, ops.OpsError) as exc:
        fail(str(exc))
    finally:
        conn.close()

    typer.secho(f"Re-encrypted {file_id} under a new key (key version {version}).", fg=typer.colors.GREEN)
    typer.echo("Existing share bundles for this file no longer open the vault copy.")
    typer.echo("A reviewer who already saved a copy of the old .enc file can still read that copy.")


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
    try:
        with audited_op(conn, kek, "pseudonymize") as ev:
            imap = _load_map(kek)
            child_id = imap.add(name)
            idm.save_map(kek, imap, config.get_identity_map_path())
            ev.details["child"] = child_id        # the pseudonym, NEVER the real name
    except (*_OP_ERRORS, ops.OpsError, idm.IdentityError) as exc:
        fail(str(exc))
    finally:
        conn.close()

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
        with audited_op(conn, kek, "lookup", details={"child": cid}):
            n_files = len(db.list_files(conn, cid))
            name = _load_map(kek).lookup(cid)
    except (*_OP_ERRORS, ops.OpsError, idm.IdentityError) as exc:
        fail(str(exc))
    finally:
        conn.close()

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
    passphrase: str = passphrase_option(),
) -> None:
    """Create a signed, time-limited share bundle for a reviewer."""
    for fid in file_ids:
        if not FILE_ID_RE.match(fid):
            fail(f"invalid file ID: {fid}")
    if out.exists():
        fail(f"'{out}' already exists; choose a new output path")
    try:
        reviewer_pub = ks.load_public_key(reviewer_key)
        expiry = bnd.parse_expiry(expires)
    except (ks.KeyShareError, bnd.BundleError) as exc:
        fail(str(exc))

    conn, kek = unlock_vault(passphrase)
    try:
        with audited_op(conn, kek, "share") as ev:
            signing_key = bnd.get_or_create_signing_key(conn, kek)
            wrapped = ks.wrap_files_for_reviewer(conn, kek, file_ids, reviewer_pub)
            bundle = bnd.create_bundle(signing_key, reviewer_pub, wrapped, expiry)
            bnd.save_bundle(bundle, out)
            ev.details.update({"files": sorted(wrapped), "reviewer_fp": ks.fingerprint(reviewer_pub),
                               "expires": bundle["payload"]["expires"]})
    except (*_OP_ERRORS, db.VaultDBError, ks.KeyShareError, bnd.BundleError, OSError) as exc:
        fail(str(exc))
    finally:
        conn.close()
    payload = bundle["payload"]
    typer.secho(f"Share bundle written to {out}", fg=typer.colors.GREEN)
    typer.echo(f"Files:        {len(wrapped)}")
    typer.echo(f"Expires:      {payload['expires']}")
    typer.echo(f"Reviewer key: {payload['reviewer_fp']}")
    typer.echo(f"Your signing-key fingerprint: {bnd.fingerprint(bytes.fromhex(payload['owner_pub']))}")
    typer.echo("Tell the reviewer this fingerprint by phone or in person; they pin it on import.")


def _verified_payload(bundle_path: Path, key_path: Path, key_passphrase: str, owner_fp: str | None):
    """Shared by import-bundle and open-shared: load key, load + verify bundle."""
    try:
        priv = ks.load_private_key(key_path, key_passphrase)
        payload = bnd.verify_bundle(
            bnd.load_bundle(bundle_path),
            trusted_owner_fp=owner_fp,
            reviewer_fp=ks.fingerprint(priv.public_key()),
        )
    except (ks.KeyShareError, bnd.BundleError) as exc:
        fail(str(exc))
    return priv, payload


def key_option():
    return typer.Option(..., "--key", help="Your private key file (<name>.key).")


def key_passphrase_option():
    return typer.Option(..., prompt="Private key passphrase", hide_input=True,
                        help="Passphrase of your private key.")


def owner_fp_option():
    return typer.Option(None, "--owner-fingerprint",
                        help="Owner's signing-key fingerprint, got by phone / in person.")


@app.command("import-bundle")
def import_bundle(
    bundle: Path = typer.Argument(..., help="Share bundle file received from the owner."),
    key: Path = key_option(),
    key_passphrase: str = key_passphrase_option(),
    owner_fingerprint: str = owner_fp_option(),
) -> None:
    """Import a share bundle as a reviewer (checks signature and expiry)."""
    priv, payload = _verified_payload(bundle, key, key_passphrase, owner_fingerprint)
    try:
        ks.unwrap_files_for_reviewer(payload["files"], priv)     # proves every key opens
    except ks.KeyShareError as exc:
        fail(str(exc))

    typer.secho("Bundle is valid.", fg=typer.colors.GREEN)
    typer.echo(f"Signed by:  {bnd.fingerprint(bytes.fromhex(payload['owner_pub']))}")
    typer.echo(f"Expires:    {payload['expires']}")
    typer.echo(f"Files ({len(payload['files'])}):")
    for fid in payload["files"]:
        typer.echo(f"  {fid}")
    if owner_fingerprint is None:
        typer.secho("Warning: no --owner-fingerprint given, so the signer was NOT checked "
                    "against a key you trust.", fg=typer.colors.YELLOW)
    typer.echo("Open a file with `childvault open-shared`.")


@app.command("open-shared")
def open_shared(
    bundle: Path = typer.Argument(..., help="Share bundle file."),
    file_id: str = typer.Argument(..., help="File ID from the bundle."),
    encrypted: Path = typer.Argument(..., exists=True, dir_okay=False, help="The .enc file the owner sent."),
    out: Path = typer.Option(..., "--out", help="Where to write the decrypted file."),
    key: Path = key_option(),
    key_passphrase: str = key_passphrase_option(),
    owner_fingerprint: str = owner_fp_option(),
) -> None:
    """(Reviewer) Decrypt one shared file using a verified bundle."""
    if not FILE_ID_RE.match(file_id):
        fail("invalid file ID")
    if out.exists():
        fail(f"'{out}' already exists; choose a new output path")
    priv, payload = _verified_payload(bundle, key, key_passphrase, owner_fingerprint)
    if file_id not in payload["files"]:
        fail(f"{file_id} is not in this bundle")
    try:
        keys = ks.unwrap_files_for_reviewer({file_id: payload["files"][file_id]}, priv)
        vc.decrypt_file(encrypted, out, keys[file_id], file_id)
    except (ks.KeyShareError, vc.VaultCryptoError, OSError) as exc:
        fail(str(exc))
    typer.secho(f"Decrypted {file_id} to '{out}'", fg=typer.colors.GREEN)


# ---------------------------------------------------------------- Laiba

@app.command()
def verify(passphrase: str = passphrase_option()) -> None:
    """Walk the audit hash chain and report any tampering."""
    conn, kek = unlock_vault(passphrase)
    try:
        with audited_op(conn, kek, "verify", strict=False) as ev:
            result = audit.verify_chain(conn, audit.derive_audit_key(kek))
            ev.details = {"ok": result.ok, "entries": result.entries}
    except _OP_ERRORS as exc:
        fail(str(exc))
    finally:
        conn.close()

    if result.ok:
        typer.secho(f"Audit log OK: {result.entries} entries verified.", fg=typer.colors.GREEN)
        return
    typer.secho("AUDIT LOG TAMPERING DETECTED", fg=typer.colors.RED, bold=True, err=True)
    where = f" (first bad entry: #{result.broken_at})" if result.broken_at is not None else ""
    fail(f"{result.reason}{where}")


audit_app = typer.Typer(help="Audit log commands.", no_args_is_help=True)
app.add_typer(audit_app, name="audit")


@audit_app.command("show")
def audit_show(
    limit: int = typer.Option(20, "--limit", min=1, help="How many recent entries to show."),
    passphrase: str = passphrase_option(),
) -> None:
    """Print the most recent audit log entries (and warn if the log was tampered with)."""
    conn, kek = unlock_vault(passphrase)
    try:
        with audited_op(conn, kek, "audit_show", details={"limit": limit}, strict=False):
            result = audit.verify_chain(conn, audit.derive_audit_key(kek))
            entries = audit.show(conn, limit=limit)
    except _OP_ERRORS as exc:
        fail(str(exc))
    finally:
        conn.close()

    if not result.ok:
        typer.secho(f"WARNING: audit log failed verification - {result.reason}",
                    fg=typer.colors.RED, bold=True, err=True)
    typer.echo(audit.format_table(entries))
    typer.echo(f"({len(entries)} of {result.entries} entries shown)")


# ---------------------------------------------------------------- accounts

@app.command("add-user")
def add_user(
    name: str = typer.Argument(..., help="Name for the new researcher account, e.g. rana."),
    user_passphrase: str = typer.Option(
        ..., "--user-passphrase", prompt="Passphrase for the new researcher", hide_input=True,
        confirmation_prompt=True, help="The researcher's own passphrase.",
    ),
    passphrase: str = passphrase_option(),
) -> None:
    """(Owner) Create a researcher account with its own passphrase."""
    conn, kek = unlock_vault(passphrase)
    try:
        with audited_op(conn, kek, "add_user", details={"user": name}):
            users.create_user(conn, kek, name, user_passphrase)
    except _OP_ERRORS as exc:
        fail(str(exc))
    finally:
        conn.close()
    typer.secho(f"Researcher '{name}' created.", fg=typer.colors.GREEN)
    typer.echo(f"They log in with:  childvault --user {name} <command>")


@app.command("remove-user")
def remove_user(
    name: str = typer.Argument(..., help="Researcher account to remove."),
    passphrase: str = passphrase_option(),
) -> None:
    """(Owner) Delete a researcher account."""
    conn, kek = unlock_vault(passphrase)
    try:
        with audited_op(conn, kek, "remove_user", details={"user": name}):
            users.remove_user(conn, name)
    except _OP_ERRORS as exc:
        fail(str(exc))
    finally:
        conn.close()
    typer.secho(f"Researcher '{name}' removed.", fg=typer.colors.GREEN)


@app.command("users")
def list_users_cmd(passphrase: str = passphrase_option()) -> None:
    """(Owner) List researcher accounts."""
    conn, kek = unlock_vault(passphrase)
    try:
        with audited_op(conn, kek, "list_users"):
            accounts = users.list_users(conn)
    except _OP_ERRORS as exc:
        fail(str(exc))
    finally:
        conn.close()
    typer.echo("owner (owner)")
    for name, role in accounts:
        typer.echo(f"{name} ({role})")