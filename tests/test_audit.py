"""Unit tests for childvault/audit.py (Laiba)."""
import json
import os
import sqlite3

import pytest

from childvault import audit, db
from childvault import vault_crypto as vc


@pytest.fixture
def conn(tmp_path):
    c = db.connect(tmp_path / "test.db")
    db.create_schema(c)
    yield c
    c.close()


@pytest.fixture
def key():
    return audit.derive_audit_key(os.urandom(32))


def fill(conn, key, n=5):
    for i in range(n):
        audit.append_event(conn, key, "owner", "add_file", f"F-{i:016x}", {"n": i})


def drop_triggers(conn):
    """An attacker with the .db file can remove db.py's append-only triggers."""
    with conn:
        conn.execute("DROP TRIGGER IF EXISTS audit_log_no_update")
        conn.execute("DROP TRIGGER IF EXISTS audit_log_no_delete")


# ---- normal behaviour -------------------------------------------------------

def test_empty_log_is_valid(conn, key):
    r = audit.verify_chain(conn, key)
    assert r.ok and r.entries == 0


def test_valid_log_verifies(conn, key):
    fill(conn, key, 5)
    r = audit.verify_chain(conn, key)
    assert r.ok and r.entries == 5


def test_first_entry_links_to_genesis(conn, key):
    fill(conn, key, 1)
    assert db.get_audit_rows(conn)[0]["prev_hash"] == db.GENESIS_HASH


def test_each_entry_links_to_previous(conn, key):
    fill(conn, key, 4)
    rows = db.get_audit_rows(conn)
    for a, b in zip(rows, rows[1:]):
        assert b["prev_hash"] == a["entry_hash"]


def test_entry_without_details_or_file(conn, key):
    audit.append_event(conn, key, "owner", "login")
    assert audit.verify_chain(conn, key).ok


def test_show_returns_decoded_details_in_order(conn, key):
    fill(conn, key, 3)
    entries = audit.show(conn)
    assert [e["seq"] for e in entries] == sorted(e["seq"] for e in entries)
    assert entries[1]["details"] == {"n": 1}
    assert len(audit.show(conn, limit=2)) == 2
    assert audit.show(conn, limit=2)[-1]["details"] == {"n": 2}


def test_format_table(conn, key):
    assert "empty" in audit.format_table([])
    fill(conn, key, 2)
    assert "add_file" in audit.format_table(audit.show(conn))


def test_empty_actor_rejected(conn, key):
    with pytest.raises(audit.AuditError):
        audit.append_event(conn, key, "", "add_file")


def test_audit_key_is_not_the_kek():
    kek = os.urandom(32)
    k = audit.derive_audit_key(kek)
    assert k != kek and len(k) == 32 and audit.derive_audit_key(kek) == k


def test_appending_after_verify_still_works(conn, key):
    fill(conn, key, 2)
    assert audit.verify_chain(conn, key).ok
    audit.append_event(conn, key, "owner", "open_file", "F-abc")
    assert audit.verify_chain(conn, key).entries == 3


def test_works_with_real_kek_from_vault_crypto(conn):
    header = vc.new_vault_header("pw", {"n": 2 ** 10, "r": 8, "p": 1})
    kek = vc.unlock("pw", header)
    k = audit.derive_audit_key(kek)
    audit.append_event(conn, k, "owner", "login")
    assert audit.verify_chain(conn, k).ok


# ---- db.py's triggers (first line of defence) --------------------------------

def test_triggers_block_edits_through_the_app(conn, key):
    fill(conn, key, 2)
    with pytest.raises(sqlite3.IntegrityError):
        with conn:
            conn.execute("UPDATE audit_log SET actor='x' WHERE seq=1")
    with pytest.raises(sqlite3.IntegrityError):
        with conn:
            conn.execute("DELETE FROM audit_log WHERE seq=1")
    assert audit.verify_chain(conn, key).ok


# ---- tampering by someone who bypasses the triggers --------------------------

def test_edited_entry_detected(conn, key):
    fill(conn, key, 5)
    drop_triggers(conn)
    with conn:
        conn.execute("UPDATE audit_log SET actor='intruder' WHERE seq=3")
    r = audit.verify_chain(conn, key)
    assert not r.ok and r.broken_at == 3


def test_edited_details_detected(conn, key):
    fill(conn, key, 5)
    drop_triggers(conn)
    with conn:
        conn.execute("""UPDATE audit_log SET details='{"n": 99}' WHERE seq=2""")
    assert not audit.verify_chain(conn, key).ok


def test_deleted_middle_entry_detected(conn, key):
    fill(conn, key, 5)
    drop_triggers(conn)
    with conn:
        conn.execute("DELETE FROM audit_log WHERE seq=3")
    r = audit.verify_chain(conn, key)
    assert not r.ok and r.broken_at == 4


def test_deleted_first_entry_detected(conn, key):
    fill(conn, key, 5)
    drop_triggers(conn)
    with conn:
        conn.execute("DELETE FROM audit_log WHERE seq=1")
    assert not audit.verify_chain(conn, key).ok


def test_deleted_last_entries_detected_by_signed_head(conn, key):
    # The chain alone cannot see this - only the HMAC head can.
    fill(conn, key, 5)
    drop_triggers(conn)
    with conn:
        conn.execute("DELETE FROM audit_log WHERE seq IN (4,5)")
    r = audit.verify_chain(conn, key)
    assert not r.ok and "deleted" in r.reason


def test_wiped_log_detected(conn, key):
    fill(conn, key, 3)
    drop_triggers(conn)
    with conn:
        conn.execute("DELETE FROM audit_log")
    r = audit.verify_chain(conn, key)
    assert not r.ok and "wiped" in r.reason


def test_reordered_entries_detected(conn, key):
    fill(conn, key, 5)
    drop_triggers(conn)
    with conn:  # swap seq numbers of entries 2 and 3
        conn.execute("UPDATE audit_log SET seq=100 WHERE seq=2")
        conn.execute("UPDATE audit_log SET seq=2 WHERE seq=3")
        conn.execute("UPDATE audit_log SET seq=3 WHERE seq=100")
    assert not audit.verify_chain(conn, key).ok


def test_rebuilt_chain_without_key_detected(conn, key):
    """Attacker edits an entry, then recomputes every hash after it (needs no key)."""
    fill(conn, key, 4)
    drop_triggers(conn)
    with conn:
        conn.execute("UPDATE audit_log SET actor='intruder' WHERE seq=2")
    prev = db.GENESIS_HASH
    for row in db.get_audit_rows(conn):
        h = audit.compute_entry_hash(row["ts"], row["actor"], row["action"],
                                     row["file_id"], row["details"], prev)
        with conn:
            conn.execute("UPDATE audit_log SET prev_hash=?, entry_hash=? WHERE seq=?",
                         (prev, h, row["seq"]))
        prev = h
    r = audit.verify_chain(conn, key)       # chain is now self-consistent...
    assert not r.ok and "head" in r.reason  # ...but the signed head no longer matches


def test_forged_head_detected(conn, key):
    fill(conn, key, 3)
    head = json.loads(db.get_meta(conn, audit.HEAD_META_KEY))
    head["seq"] = 2
    with conn:
        conn.execute("UPDATE vault_meta SET value=? WHERE key=?",
                     (json.dumps(head), audit.HEAD_META_KEY))
    r = audit.verify_chain(conn, key)
    assert not r.ok and "signature" in r.reason


def test_missing_head_detected(conn, key):
    fill(conn, key, 3)
    with conn:
        conn.execute("DELETE FROM vault_meta WHERE key=?", (audit.HEAD_META_KEY,))
    assert not audit.verify_chain(conn, key).ok


def test_wrong_key_fails(conn, key):
    fill(conn, key, 3)
    other = audit.derive_audit_key(os.urandom(32))
    r = audit.verify_chain(conn, other)
    assert not r.ok and "signature" in r.reason


# ---- append must not "heal" a tampered log -----------------------------------

def test_append_refused_after_tail_deletion_and_evidence_survives(conn, key):
    """Attacker deletes the newest entries; the next normal action must NOT re-sign over it."""
    fill(conn, key, 5)
    drop_triggers(conn)
    with conn:
        conn.execute("DELETE FROM audit_log WHERE seq IN (4,5)")
    with pytest.raises(audit.AuditTamperedError):
        audit.append_event(conn, key, "owner", "open_file", "F-1")
    r = audit.verify_chain(conn, key)
    assert not r.ok and "deleted" in r.reason          # evidence is still there


def test_append_refused_when_head_missing(conn, key):
    fill(conn, key, 2)
    with conn:
        conn.execute("DELETE FROM vault_meta WHERE key=?", (audit.HEAD_META_KEY,))
    with pytest.raises(audit.AuditTamperedError):
        audit.append_event(conn, key, "owner", "x")


def test_append_refused_after_wipe(conn, key):
    fill(conn, key, 2)
    drop_triggers(conn)
    with conn:
        conn.execute("DELETE FROM audit_log")
    with pytest.raises(audit.AuditTamperedError):
        audit.append_event(conn, key, "owner", "x")


def test_forged_extra_row_is_not_legitimised(conn, key):
    """Attacker appends a row (no key needed for the chain); the next append must refuse."""
    fill(conn, key, 2)
    last = db.get_last_audit_row(conn)
    ts, h = "2026-01-01T00:00:00+00:00", None
    h = audit.compute_entry_hash(ts, "intruder", "open_file", "F-1", None, last["entry_hash"])
    db.append_audit_row(conn, ts, "intruder", "open_file", last["entry_hash"], h, file_id="F-1")
    with pytest.raises(audit.AuditTamperedError):
        audit.append_event(conn, key, "owner", "add_file")
    assert not audit.verify_chain(conn, key).ok


def test_head_problem_reports_reason_or_none(conn, key):
    assert audit.head_problem(conn, key) is None
    fill(conn, key, 2)
    assert audit.head_problem(conn, key) is None
    assert audit.head_problem(conn, audit.derive_audit_key(os.urandom(32))) is not None


def test_row_and_head_are_written_atomically(conn, key, monkeypatch):
    fill(conn, key, 1)

    def boom(*a, **k):
        raise RuntimeError("crash while writing the head")

    monkeypatch.setattr(audit, "_write_head", boom)
    with pytest.raises(RuntimeError):
        audit.append_event(conn, key, "owner", "add_file")
    monkeypatch.undo()
    assert len(db.get_audit_rows(conn)) == 1          # the row was rolled back too
    assert audit.verify_chain(conn, key).ok
    audit.append_event(conn, key, "owner", "add_file")  # and the log still works