"""
Phase 5 attack suite - audit log (Mariyam).

The attacker has the vault folder (stolen laptop, curious insider) but NOT
the passphrase. They open childvault.db with any SQLite tool, drop the
append-only triggers, and edit, delete, reorder or insert log entries to
hide what was done. Every attack MUST be detected by `childvault verify`.

Unlike Laiba's unit tests (tests/test_audit.py), these run end-to-end:
  * the log is written by REAL CLI commands (pseudonymize, add-file, ...),
  * the attack edits the real database file, exactly as an attacker would,
  * detection is checked through the real `verify` command.

Docstring convention (read by scripts/attack_report.py for the results table):
    "<what the attacker does> -> <what detects it>"
"""

import re
import shutil
import sqlite3

import pytest
from typer.testing import CliRunner

from childvault import audit, config
from childvault.cli import app

PW = "log attack passphrase"
runner = CliRunner()


# ---------------------------------------------------------------- the vault under attack

def _cli(*args):
    result = runner.invoke(app, [*args, "--passphrase", PW])
    assert result.exit_code == 0, result.output
    return result.output


@pytest.fixture(scope="module")
def template_vault(tmp_path_factory):
    """
    Built ONCE with real commands, then copied for every test.
    Log afterwards: 1 pseudonymize, 2 pseudonymize, 3 add_file, 4 open_file, 5 lookup, 6 status
    """
    root = tmp_path_factory.mktemp("log_template")
    vault = root / "vault"
    mp = pytest.MonkeyPatch()
    mp.setenv(config.ENV_VAR, str(vault))
    try:
        assert runner.invoke(app, ["init", "--passphrase", PW]).exit_code == 0
        a = re.search(r"CH-[0-9A-F]{4}", _cli("pseudonymize", "--name", "Test Child A")).group(0)
        _cli("pseudonymize", "--name", "Test Child B")
        src = root / "obs.csv"
        src.write_text("time,behaviour\n0.0,looks_at_toy\n")
        fid = re.search(r"F-[0-9a-f]{16}", _cli("add-file", str(src), "--type", "csv", "--child", a)).group(0)
        _cli("open-file", fid, "--out", str(root / "back.csv"))
        _cli("lookup", a)
        _cli("status")
    finally:
        mp.undo()
    return vault


@pytest.fixture
def vault(template_vault, tmp_path, monkeypatch):
    v = tmp_path / "vault"
    shutil.copytree(template_vault, v)
    monkeypatch.setenv(config.ENV_VAR, str(v))
    return v


# ---------------------------------------------------------------- attacker tools

def open_db(vault):
    """What an attacker does first: open the file directly and remove the guards."""
    conn = sqlite3.connect(vault / "childvault.db", isolation_level=None)   # autocommit
    conn.row_factory = sqlite3.Row
    conn.execute("DROP TRIGGER IF EXISTS audit_log_no_update")
    conn.execute("DROP TRIGGER IF EXISTS audit_log_no_delete")
    return conn


def rows(conn):
    return [dict(r) for r in conn.execute("SELECT * FROM audit_log ORDER BY seq")]


def rehash_chain(conn):
    """
    The strongest attacker move without the passphrase: after doctoring the log,
    recompute EVERY entry_hash and prev_hash so the chain is perfect again.
    SHA-256 is public, so this is easy. Only the HMAC-signed head (keyed by
    the passphrase) is beyond reach.
    """
    prev = audit.GENESIS_HASH
    for r in rows(conn):
        h = audit.compute_entry_hash(r["ts"], r["actor"], r["action"], r["file_id"], r["details"], prev)
        conn.execute("UPDATE audit_log SET prev_hash = ?, entry_hash = ? WHERE seq = ?", (prev, h, r["seq"]))
        prev = h


def swap_contents(conn, a, b):
    """Exchange everything except seq between entries a and b."""
    ra, rb = (dict(conn.execute("SELECT * FROM audit_log WHERE seq = ?", (s,)).fetchone()) for s in (a, b))
    cols = ["ts", "actor", "action", "file_id", "details", "prev_hash", "entry_hash"]
    # entry_hash is UNIQUE, so move BOTH rows to placeholder hashes before swapping
    conn.execute("UPDATE audit_log SET entry_hash = ? WHERE seq = ?", ("0" * 63 + "1", a))
    conn.execute("UPDATE audit_log SET entry_hash = ? WHERE seq = ?", ("0" * 63 + "2", b))
    sets = ", ".join(c + " = ?" for c in cols)
    conn.execute(f"UPDATE audit_log SET {sets} WHERE seq = ?", [rb[c] for c in cols] + [a])
    conn.execute(f"UPDATE audit_log SET {sets} WHERE seq = ?", [ra[c] for c in cols] + [b])


def verify():
    return runner.invoke(app, ["verify", "--passphrase", PW])


def assert_detected(result, reason=None, at=None):
    assert result.exit_code == 1, result.output
    assert "TAMPERING DETECTED" in result.output, result.output
    if reason:
        assert reason in result.output, result.output
    if at is not None:
        assert f"first bad entry: #{at}" in result.output, result.output


N = 6           # entries in the template log
MIDDLE = [2, 3, 4, 5]


# ================================================================ control

def test_control_untouched_log_verifies(vault):
    """No attack: the real log verifies -> OK."""
    r = verify()
    assert r.exit_code == 0, r.output
    assert f"{N} entries verified" in r.output


# ================================================================ 1. EDITED entries

@pytest.mark.parametrize("seq", range(1, N + 1))
def test_attack_edit_actor(vault, seq):
    """Change who did an action (actor) in any entry -> that entry's SHA-256 no longer matches."""
    c = open_db(vault)
    c.execute("UPDATE audit_log SET actor = 'researcher' WHERE seq = ?", (seq,))
    assert_detected(verify(), "was modified", at=seq)


@pytest.mark.parametrize("new_action", ["status", "verify", "failed:open_file"])
def test_attack_edit_action(vault, new_action):
    """Disguise the file opening (open_file) as a harmless action -> entry hash mismatch."""
    c = open_db(vault)
    c.execute("UPDATE audit_log SET action = ? WHERE seq = 4", (new_action,))
    assert_detected(verify(), "was modified", at=4)


def test_attack_edit_timestamp(vault):
    """Move the time of the file opening by one second -> entry hash mismatch."""
    c = open_db(vault)
    ts = rows(c)[3]["ts"]
    c.execute("UPDATE audit_log SET ts = ? WHERE seq = 4", (ts[:-7] + ("0" if ts[-7] != "0" else "1") + ts[-6:],))
    assert_detected(verify(), "was modified", at=4)


def test_attack_edit_file_id(vault):
    """Point the open_file entry at a different file -> entry hash mismatch."""
    c = open_db(vault)
    c.execute("UPDATE audit_log SET file_id = 'F-ffffffffffffffff' WHERE seq = 4")
    assert_detected(verify(), "was modified", at=4)


def test_attack_edit_details(vault):
    """Change which child was looked up (details) -> entry hash mismatch."""
    c = open_db(vault)
    c.execute("""UPDATE audit_log SET details = '{"child": "CH-0000"}' WHERE seq = 5""")
    assert_detected(verify(), "was modified", at=5)


def test_attack_edit_and_fix_own_hash(vault):
    """Edit an entry AND recompute its own hash -> the next entry's prev_hash no longer links to it."""
    c = open_db(vault)
    r = rows(c)[3]
    h = audit.compute_entry_hash(r["ts"], "researcher", r["action"], r["file_id"], r["details"], r["prev_hash"])
    c.execute("UPDATE audit_log SET actor = 'researcher', entry_hash = ? WHERE seq = 4", (h,))
    assert_detected(verify(), "chain broken at entry 5", at=5)


@pytest.mark.parametrize("seq", range(1, N + 1))
def test_attack_edit_and_rebuild_whole_chain(vault, seq):
    """Edit any entry and recompute every hash after it -> the HMAC-signed head no longer matches."""
    c = open_db(vault)
    c.execute("UPDATE audit_log SET actor = 'researcher' WHERE seq = ?", (seq,))
    rehash_chain(c)
    assert_detected(verify(), "does not match its signed head")


def test_attack_edit_prev_hash_link(vault):
    """Rewrite one entry's prev_hash link -> chain broken at that entry."""
    c = open_db(vault)
    c.execute("UPDATE audit_log SET prev_hash = ? WHERE seq = 3", ("a" * 64,))
    assert_detected(verify(), "chain broken at entry 3", at=3)


# ================================================================ 2. DELETED entries

@pytest.mark.parametrize("seq", MIDDLE)
def test_attack_delete_middle_entry(vault, seq):
    """Delete one entry from the middle of the log -> the following entry's prev_hash points at nothing."""
    c = open_db(vault)
    c.execute("DELETE FROM audit_log WHERE seq = ?", (seq,))
    assert_detected(verify(), f"chain broken at entry {seq + 1}", at=seq + 1)


def test_attack_delete_first_entry(vault):
    """Delete the very first entry -> entry 2 no longer links to the genesis hash."""
    c = open_db(vault)
    c.execute("DELETE FROM audit_log WHERE seq = 1")
    assert_detected(verify(), "chain broken at entry 2", at=2)


@pytest.mark.parametrize("k", [1, 2, N - 1])
def test_attack_delete_last_entries(vault, k):
    """Delete the newest k entries (the chain that is left is perfect) -> signed head records more entries."""
    c = open_db(vault)
    c.execute("DELETE FROM audit_log WHERE seq > ?", (N - k,))
    assert_detected(verify(), f"entries after #{N - k} were deleted", at=N - k + 1)


def test_attack_wipe_whole_log(vault):
    """Delete every entry -> signed head says the log had entries (log was wiped)."""
    c = open_db(vault)
    c.execute("DELETE FROM audit_log")
    assert_detected(verify(), "log was wiped")


def test_attack_delete_entries_and_signed_head(vault):
    """Delete the last entries AND the signed head record -> signed head is missing."""
    c = open_db(vault)
    c.execute("DELETE FROM audit_log WHERE seq > 3")
    c.execute("DELETE FROM vault_meta WHERE key = ?", (audit.HEAD_META_KEY,))
    assert_detected(verify(), "signed head is missing")


def test_attack_delete_and_renumber_to_hide_gap(vault):
    """Delete entry 3 and renumber the rest so seq has no gap -> chain still broken where 3 was."""
    c = open_db(vault)
    c.execute("DELETE FROM audit_log WHERE seq = 3")
    for s in range(4, N + 1):
        c.execute("UPDATE audit_log SET seq = ? WHERE seq = ?", (s - 1, s))
    assert_detected(verify(), "chain broken at entry 3", at=3)


def test_attack_delete_and_rebuild_chain(vault):
    """Delete the file-opening entry and recompute all hashes -> signed head no longer matches."""
    c = open_db(vault)
    c.execute("DELETE FROM audit_log WHERE seq = 4")
    rehash_chain(c)
    assert_detected(verify(), "does not match its signed head")


# ================================================================ 3. REORDERED entries

@pytest.mark.parametrize("a,b", [(1, 2), (3, 4), (2, 5), (1, N)])
def test_attack_swap_two_entries(vault, a, b):
    """Swap the contents of two entries (seq numbers stay) -> chain broken at the earlier one."""
    c = open_db(vault)
    swap_contents(c, a, b)
    assert_detected(verify(), at=a)


def test_attack_swap_seq_numbers(vault):
    """Swap the seq numbers of entries 3 and 4 so they are read in the wrong order -> chain broken."""
    c = open_db(vault)
    c.execute("UPDATE audit_log SET seq = -1 WHERE seq = 3")
    c.execute("UPDATE audit_log SET seq = 3 WHERE seq = 4")
    c.execute("UPDATE audit_log SET seq = 4 WHERE seq = -1")
    assert_detected(verify(), "chain broken at entry 3", at=3)


def test_attack_move_last_entry_to_front(vault):
    """Move the newest entry to the start of the log -> sequence numbers are out of order."""
    c = open_db(vault)
    c.execute("UPDATE audit_log SET seq = 0 WHERE seq = ?", (N,))
    assert_detected(verify(), "entry 0 is out of order", at=0)


def test_attack_reverse_whole_log(vault):
    """Reverse the order of every entry -> chain broken at the first entry."""
    c = open_db(vault)
    for s in range(1, N + 1):
        c.execute("UPDATE audit_log SET seq = ? WHERE seq = ?", (-s, s))
    for s in range(1, N + 1):
        c.execute("UPDATE audit_log SET seq = ? WHERE seq = ?", (N + 1 - s, -s))
    assert_detected(verify(), "chain broken at entry 1", at=1)


def test_attack_reorder_and_rebuild_chain(vault):
    """Reorder entries and recompute all hashes so the chain is valid -> signed head no longer matches."""
    c = open_db(vault)
    swap_contents(c, 2, 5)
    rehash_chain(c)
    assert_detected(verify(), "does not match its signed head")


# ================================================================ 4. INSERTED / forged entries

def test_attack_insert_forged_entry_in_middle(vault):
    """Insert a fake entry between two real ones -> the real entry after it no longer links."""
    c = open_db(vault)
    r = rows(c)[1]
    fake_hash = audit.compute_entry_hash(r["ts"], "owner", "status", None, None, r["entry_hash"])
    for s in range(N, 2, -1):                                     # make room at seq 3
        c.execute("UPDATE audit_log SET seq = ? WHERE seq = ?", (s + 1, s))
    c.execute("INSERT INTO audit_log (seq, ts, actor, action, file_id, details, prev_hash, entry_hash) "
              "VALUES (3, ?, 'owner', 'status', NULL, NULL, ?, ?)", (r["ts"], r["entry_hash"], fake_hash))
    assert_detected(verify(), "chain broken at entry 4", at=4)


def test_attack_append_correctly_chained_fake_entry(vault):
    """Append a perfectly chained fake entry at the end -> signed head does not cover it."""
    c = open_db(vault)
    last = rows(c)[-1]
    h = audit.compute_entry_hash(last["ts"], "owner", "verify", None, None, last["entry_hash"])
    c.execute("INSERT INTO audit_log (ts, actor, action, file_id, details, prev_hash, entry_hash) "
              "VALUES (?, 'owner', 'verify', NULL, NULL, ?, ?)", (last["ts"], last["entry_hash"], h))
    assert_detected(verify(), "does not match its signed head")


# ================================================================ 5. the signed head itself

def test_attack_forge_signed_head(vault):
    """Rewrite the head to match a truncated log, with a made-up HMAC -> head signature invalid."""
    c = open_db(vault)
    c.execute("DELETE FROM audit_log WHERE seq > 3")
    h3 = rows(c)[-1]["entry_hash"]
    c.execute("UPDATE vault_meta SET value = ? WHERE key = ?",
              ('{"hash": "%s", "mac": "%s", "seq": 3}' % (h3, "0" * 64), audit.HEAD_META_KEY))
    assert_detected(verify(), "invalid signature")


def test_attack_corrupt_signed_head(vault):
    """Replace the signed head with garbage -> head is malformed."""
    c = open_db(vault)
    c.execute("UPDATE vault_meta SET value = 'garbage' WHERE key = ?", (audit.HEAD_META_KEY,))
    assert_detected(verify(), "malformed")


# ================================================================ 6. after the attack

def test_attack_tail_deletion_blocks_further_use(vault):
    """Delete the last entries, then keep using the vault -> commands refuse, evidence is not overwritten."""
    c = open_db(vault)
    c.execute("DELETE FROM audit_log WHERE seq > 4")
    c.close()
    r = runner.invoke(app, ["pseudonymize", "--name", "Test Child C", "--passphrase", PW])
    assert r.exit_code == 1 and "integrity check" in r.output, r.output
    assert_detected(verify(), "entries after #4 were deleted")


def test_attack_middle_edit_survives_further_use(vault):
    """Edit an old entry, then the owner keeps working normally -> verify still finds the edit."""
    c = open_db(vault)
    c.execute("UPDATE audit_log SET actor = 'researcher' WHERE seq = 2")
    c.close()
    _cli("status")
    _cli("pseudonymize", "--name", "Test Child C")
    assert_detected(verify(), "was modified", at=2)


def test_attack_hidden_from_audit_show(vault):
    """Delete an entry and look at `audit show` instead of verify -> audit show prints a warning."""
    c = open_db(vault)
    c.execute("DELETE FROM audit_log WHERE seq = 4")
    c.close()
    r = runner.invoke(app, ["audit", "show", "--passphrase", PW])
    assert "WARNING: audit log failed verification" in r.output, r.output


def test_attack_wrong_passphrase_cannot_verify_or_sign(vault):
    """Try to verify (or re-sign the head) with a guessed passphrase -> refused before reading the log."""
    r = runner.invoke(app, ["verify", "--passphrase", "guessed passphrase"])
    assert r.exit_code == 1 and "wrong passphrase" in r.output
