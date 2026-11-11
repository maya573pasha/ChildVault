"""
audit.py - tamper-evident audit log (Laiba, Phase 2).

Every action in the vault becomes one row in the audit_log table. Each row
contains the SHA-256 hash of the PREVIOUS row, so the rows form a chain:

    entry 1 --hash--> entry 2 --hash--> entry 3 --hash--> ...

  * Editing any row changes its hash, so the next row's prev_hash no longer
    matches (the chain breaks at that point).
  * Deleting a row in the middle, or reordering rows, breaks the chain too.
  * A chain alone CANNOT notice that the last few rows were deleted, or that
    someone rebuilt the whole chain after editing it - anyone can compute
    SHA-256. So after every append we also store a "head" record: the newest
    sequence number + hash, authenticated with HMAC-SHA256 under a key that
    comes from the vault passphrase. Without the passphrase an attacker
    cannot produce a valid head for a doctored log.

Storage (SQL) is Mariyam's db.py; this module only does the hashing, the
signed head, `verify` and `show`.

Known limits (state these honestly in the report):
  * The row and the head are written in ONE transaction, so a crash can never
    leave them out of step.
  * append_event REFUSES to append if the log already fails its head check.
    Otherwise the next normal action would re-sign the head over a truncated
    log and silently erase the evidence of the deletion.
  * Rollback: an attacker who saved an OLD copy of the database can restore it
    and everything is self-consistent again. Only a copy of the head hash kept
    somewhere else (printed, e-mailed) can reveal that.
  * Two processes appending at the exact same moment could fork the chain.
    ChildVault is a single-user, single-machine tool, so this is out of scope.
  * Someone who knows the passphrase can forge a log. That is outside the
    threat model in the proposal.
  * db.py also installs SQL triggers that refuse UPDATE/DELETE on audit_log.
    Those only stop mistakes and casual edits through the app: anyone with the
    database file can drop them. The hash chain + signed head are the real defence.
"""

import hashlib
import hmac
import json
import sqlite3
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import db

GENESIS_HASH = db.GENESIS_HASH          # prev_hash of the very first entry (defined in db.py)
HEAD_META_KEY = "audit_head"            # vault_meta key holding the signed head
_HKDF_INFO = b"childvault:audit-head:v1"
AUDIT_KEY_LEN = 32


class AuditError(Exception):
    """Base class for audit-log errors."""


class AuditTamperedError(AuditError):
    """The log fails its integrity check, so nothing more may be appended to it."""


# --------------------------------------------------------------------------
# Keys and hashing
# --------------------------------------------------------------------------

def derive_audit_key(kek: bytes) -> bytes:
    """
    A separate HMAC key derived from the KEK (HKDF-SHA256), so the KEK itself
    is never used for two different jobs.
    """
    if len(kek) != AUDIT_KEY_LEN:
        raise ValueError(f"kek must be {AUDIT_KEY_LEN} bytes")
    return HKDF(algorithm=hashes.SHA256(), length=AUDIT_KEY_LEN,
                salt=None, info=_HKDF_INFO).derive(kek)


def compute_entry_hash(ts: str, actor: str, action: str, file_id: str | None,
                       details_json: str | None, prev_hash: str) -> str:
    """
    SHA-256 over every field of the entry (and the previous hash).

    The fields are encoded as a JSON list, not joined with a separator, so no
    field value can "slide" into the next one (ambiguity attack).
    `details_json` must be the exact text stored in the database.
    """
    payload = json.dumps([ts, actor, action, file_id, details_json, prev_hash],
                         separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _head_mac(audit_key: bytes, seq: int, entry_hash: str) -> str:
    return hmac.new(audit_key, f"{seq}:{entry_hash}".encode("utf-8"), hashlib.sha256).hexdigest()


def _write_head(conn: sqlite3.Connection, audit_key: bytes, seq: int, entry_hash: str) -> None:
    """Upsert the signed head. Does NOT commit: runs inside append_event's transaction."""
    head = json.dumps({"seq": seq, "hash": entry_hash,
                       "mac": _head_mac(audit_key, seq, entry_hash)}, sort_keys=True)
    conn.execute(
        "INSERT INTO vault_meta (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (HEAD_META_KEY, head),
    )


def _head_problem(conn: sqlite3.Connection, audit_key: bytes, last) -> tuple[str, int | None] | None:
    """
    Compare the signed head with the newest log row (`last`, or None if empty).
    Returns (reason, broken_at) if something is wrong, else None. O(1).
    """
    raw = db.get_meta(conn, HEAD_META_KEY)
    if raw is None:
        if last is not None:
            return "signed head is missing - the log cannot be authenticated", None
        return None                                   # brand-new log
    try:
        head = json.loads(raw)
        h_seq, h_hash, h_mac = int(head["seq"]), str(head["hash"]), str(head["mac"])
    except (ValueError, KeyError, TypeError):
        return "signed head is malformed", None
    if not hmac.compare_digest(_head_mac(audit_key, h_seq, h_hash), h_mac):
        return "signed head has an invalid signature (tampered, or wrong passphrase)", None
    if last is None:
        return f"log is empty but the signed head says it had {h_seq} entries (log was wiped)", None
    if last["seq"] != h_seq or last["entry_hash"] != h_hash:
        if last["seq"] < h_seq:
            return (f"entries after #{last['seq']} were deleted "
                    f"(signed head records up to #{h_seq})"), last["seq"] + 1
        return "the log does not match its signed head (rewritten or extended outside the vault)", None
    return None


def head_problem(conn: sqlite3.Connection, audit_key: bytes) -> str | None:
    """Reason the log cannot be appended to, or None if it is healthy."""
    problem = _head_problem(conn, audit_key, db.get_last_audit_row(conn))
    return problem[0] if problem else None


# --------------------------------------------------------------------------
# Writing
# --------------------------------------------------------------------------

def append_event(conn: sqlite3.Connection, audit_key: bytes, actor: str, action: str,
                 file_id: str | None = None, details: dict | None = None) -> int:
    """
    Add one entry to the log and re-sign the head. Returns the entry's seq.

    The row and the head are written in ONE transaction. Raises
    AuditTamperedError (writing nothing) if the log already fails its head check.
    Every module calls this - nobody writes to audit_log directly.
    """
    if not actor or not action:
        raise AuditError("actor and action must not be empty")
    last = db.get_last_audit_row(conn)
    problem = _head_problem(conn, audit_key, last)
    if problem:
        raise AuditTamperedError(f"audit log failed its integrity check: {problem[0]}")

    prev_hash = last["entry_hash"] if last is not None else GENESIS_HASH
    ts = db.utc_now()
    # Same serialisation as db.append_audit_row, so the hash matches what is stored.
    details_json = json.dumps(details, sort_keys=True) if details is not None else None
    entry_hash = compute_entry_hash(ts, actor, action, file_id, details_json, prev_hash)
    try:
        with conn:                                    # one transaction: row + head
            seq = conn.execute(
                """INSERT INTO audit_log (ts, actor, action, file_id, details, prev_hash, entry_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (ts, actor, action, file_id, details_json, prev_hash, entry_hash),
            ).lastrowid
            _write_head(conn, audit_key, seq, entry_hash)
    except sqlite3.IntegrityError as exc:
        raise AuditError(f"could not append audit entry: {exc}") from None
    return seq


# --------------------------------------------------------------------------
# Verifying
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    entries: int                       # how many entries were checked
    broken_at: int | None = None       # seq of the first bad entry, if known
    reason: str = "audit log is intact"


def _fail(entries: int, reason: str, broken_at: int | None = None) -> VerifyResult:
    return VerifyResult(False, entries, broken_at, reason)


def verify_chain(conn: sqlite3.Connection, audit_key: bytes) -> VerifyResult:
    """
    Walk the whole log and check (1) every hash and link, then (2) the signed head.

    Never raises for tampering - it returns a VerifyResult explaining what broke.
    """
    rows = db.get_audit_rows(conn)

    # ---- 1. the chain itself -------------------------------------------
    prev_hash = GENESIS_HASH
    prev_seq = 0
    for row in rows:
        seq = row["seq"]
        if seq <= prev_seq:
            return _fail(len(rows), f"entry {seq} is out of order", seq)
        if row["prev_hash"] != prev_hash:
            return _fail(len(rows),
                         f"chain broken at entry {seq}: an entry before it was deleted, "
                         "reordered or edited", seq)
        expected = compute_entry_hash(row["ts"], row["actor"], row["action"],
                                      row["file_id"], row["details"], row["prev_hash"])
        if not hmac.compare_digest(expected, row["entry_hash"]):
            return _fail(len(rows), f"entry {seq} was modified (its hash does not match)", seq)
        prev_hash, prev_seq = row["entry_hash"], seq

    # ---- 2. the signed head --------------------------------------------
    problem = _head_problem(conn, audit_key, rows[-1] if rows else None)
    if problem:
        return _fail(len(rows), problem[0], problem[1])
    if not rows:
        return VerifyResult(True, 0, None, "audit log is empty")
    return VerifyResult(True, len(rows))


# --------------------------------------------------------------------------
# Reading (`audit show`)
# --------------------------------------------------------------------------

def show(conn: sqlite3.Connection, limit: int | None = None) -> list[dict]:
    """
    Entries in order, as plain dicts with `details` decoded. With `limit`,
    only the newest N (still returned oldest-first). This does NOT verify -
    run `verify` for that.
    """
    rows = db.get_audit_rows(conn)
    if limit is not None:
        rows = rows[-limit:] if limit > 0 else []
    out = []
    for r in rows:
        out.append({
            "seq": r["seq"], "ts": r["ts"], "actor": r["actor"], "action": r["action"],
            "file_id": r["file_id"],
            "details": json.loads(r["details"]) if r["details"] is not None else None,
        })
    return out


def format_table(entries: list[dict]) -> str:
    """Plain-text table for the CLI."""
    if not entries:
        return "(audit log is empty)"
    lines = [f"{'#':>4}  {'time (UTC)':<25} {'actor':<12} {'action':<14} {'file':<20} details"]
    for e in entries:
        det = json.dumps(e["details"], sort_keys=True) if e["details"] else ""
        lines.append(f"{e['seq']:>4}  {e['ts']:<25} {e['actor']:<12} {e['action']:<14} "
                     f"{(e['file_id'] or '-'):<20} {det}")
    return "\n".join(lines)