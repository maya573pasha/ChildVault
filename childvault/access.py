"""
access.py - roles, permission checks and audited actions (Laiba, Phase 3).

One table (PERMISSIONS) says which role may do which action. Every operation
runs inside `audited(...)`, which does three things in one place:

    1. checks the table      -> not allowed: logs "denied:<action>" and raises
    2. runs the operation
    3. logs the outcome      -> success: "<action>"   failure: "failed:<action>"

So nobody can forget to log, and a denied or failed attempt (for example an
open-file on a tampered file) leaves a trace just like a successful one.

IMPORTANT - what each role really means (state this in the report):
  * reviewer  - enforced by CRYPTOGRAPHY. A reviewer holds only an X25519 key
                and a signed bundle; without the vault passphrase they cannot
                derive the KEK, so no software check is needed to stop them.
  * owner / researcher - enforced by SOFTWARE POLICY (this module). Both know
                the vault passphrase, so a malicious researcher who modifies
                the program could bypass these checks. This is the "honest
                client" limitation already stated in the proposal.

Privacy rule for log entries: only IDs go in `details` (file IDs, pseudonyms,
fingerprints). NEVER a real name, a passphrase, a path, or an error message.
The audit log is stored unencrypted in the database.
"""

from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum

from . import audit


class Role(str, Enum):
    OWNER = "owner"
    RESEARCHER = "researcher"
    REVIEWER = "reviewer"


class PermissionDenied(Exception):
    """The actor's role is not allowed to perform this action."""


@dataclass(frozen=True)
class Actor:
    name: str          # who, as written in the log (a username, not a real name)
    role: Role

    @classmethod
    def owner(cls, name: str = "owner") -> "Actor":
        return cls(name, Role.OWNER)


_O, _R, _V = Role.OWNER, Role.RESEARCHER, Role.REVIEWER

# action -> roles allowed. Anything NOT listed is denied (fail closed).
PERMISSIONS: dict[str, frozenset[Role]] = {
    "login":         frozenset({_O, _R, _V}),
    "status":        frozenset({_O, _R}),
    "add_file":      frozenset({_O, _R}),
    "open_file":     frozenset({_O, _R}),
    "list_files":    frozenset({_O, _R}),      # the web file list (metadata only)
    "pseudonymize":  frozenset({_O}),          # needs the real name -> owner only
    "lookup":        frozenset({_O}),          # reveals a real name  -> owner only
    "share":         frozenset({_O}),
    "revoke":        frozenset({_O}),
    "verify":        frozenset({_O, _R}),      # read-only integrity check
    "audit_show":    frozenset({_O}),          # the log shows who accessed what
    "add_user":      frozenset({_O}),
    "remove_user":   frozenset({_O}),
    "list_users":    frozenset({_O}),
    "import_bundle": frozenset({_V}),          # reviewer side (runs offline, see note)
    "open_shared":   frozenset({_V}),
}


def is_allowed(role: Role | str, action: str) -> bool:
    try:
        role = Role(role)
    except ValueError:
        return False
    return role in PERMISSIONS.get(action, frozenset())


def require(role: Role | str, action: str) -> None:
    """Raise PermissionDenied unless `role` may do `action`."""
    if not is_allowed(role, action):
        raise PermissionDenied(f"role '{getattr(role, 'value', role)}' may not {action.replace('_', ' ')}")


@dataclass
class Event:
    """Filled in by the operation so the log entry can name what was created."""
    file_id: str | None = None
    details: dict = field(default_factory=dict)


@contextmanager
def audited(conn, audit_key: bytes, actor: Actor, action: str,
            file_id: str | None = None, details: dict | None = None, strict: bool = True):
    """
    Wrap one vault operation:

        with audited(conn, key, actor, "add_file") as ev:
            ev.file_id = ops.add_file(...)

    strict=True (default): if the audit log already fails its integrity check,
    raise AuditTamperedError BEFORE doing anything - the vault will not keep
    working on a log that has been tampered with.
    strict=False is for read-only `verify` / `audit show` / `status`: they must
    still work on a damaged log so the owner can investigate; the entry is then
    simply not written (nothing can be appended to a broken log).

    Do NOT call the CLI's fail() inside the `with` block: typer.Exit would be
    logged as a failure. Let the exception leave the block, then handle it.
    """
    problem = audit.head_problem(conn, audit_key)
    if problem and strict:
        raise audit.AuditTamperedError(f"audit log failed its integrity check: {problem}")
    log = problem is None

    ev = Event(file_id=file_id, details=dict(details or {}))
    try:
        require(actor.role, action)
    except PermissionDenied:
        if log:
            audit.append_event(conn, audit_key, actor.name, f"denied:{action}",
                               ev.file_id, ev.details or None)
        raise
    try:
        yield ev
    except Exception as exc:
        # Only the exception CLASS is stored - messages can contain paths or names.
        if log:
            audit.append_event(conn, audit_key, actor.name, f"failed:{action}", ev.file_id,
                               {**ev.details, "error": type(exc).__name__})
        raise
    if log:
        audit.append_event(conn, audit_key, actor.name, action, ev.file_id, ev.details or None)