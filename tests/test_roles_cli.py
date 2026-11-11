"""CLI tests: researcher accounts, role checks and audit entries (Laiba)."""
import pytest
from typer.testing import CliRunner

from childvault import audit, config, db
from childvault import vault_crypto as vc
from childvault.cli import app

OWNER_PW = "owner-passphrase-1"
RANA_PW = "rana-passphrase-1"
runner = CliRunner()


@pytest.fixture
def vault(tmp_path, monkeypatch):
    monkeypatch.setenv(config.ENV_VAR, str(tmp_path / "vault"))
    config.ensure_vault_dirs()
    conn = db.connect()
    db.create_schema(conn)
    db.save_header(conn, vc.new_vault_header(OWNER_PW, {"n": 2 ** 10, "r": 8, "p": 1}))
    conn.close()
    return tmp_path


def owner(*args):
    return runner.invoke(app, [*args, "--passphrase", OWNER_PW])


def rana(*args):
    return runner.invoke(app, ["--user", "rana", *args, "--passphrase", RANA_PW])


def log_actions():
    conn = db.connect()
    try:
        return [(e["actor"], e["action"]) for e in audit.show(conn)]
    finally:
        conn.close()


@pytest.fixture
def with_rana(vault):
    r = runner.invoke(app, ["add-user", "rana", "--user-passphrase", RANA_PW, "--passphrase", OWNER_PW])
    assert r.exit_code == 0, r.output
    return vault


def test_owner_creates_researcher_and_it_is_logged(with_rana):
    assert ("owner", "add_user") in log_actions()
    r = owner("users")
    assert "rana (researcher)" in r.output


def test_researcher_can_log_in(with_rana):
    r = rana("status")
    assert r.exit_code == 0 and "Vault unlocked" in r.output
    assert ("rana", "status") in log_actions()


def test_researcher_wrong_passphrase_rejected(with_rana):
    r = runner.invoke(app, ["--user", "rana", "status", "--passphrase", "totally-wrong-1"])
    assert r.exit_code == 1 and "wrong passphrase" in r.output


def test_unknown_user_rejected_with_same_message(with_rana):
    r = runner.invoke(app, ["--user", "ghost", "status", "--passphrase", RANA_PW])
    assert r.exit_code == 1 and "wrong passphrase" in r.output


def test_owner_passphrase_does_not_work_for_researcher_account(with_rana):
    r = runner.invoke(app, ["--user", "rana", "status", "--passphrase", OWNER_PW])
    assert r.exit_code == 1


@pytest.mark.parametrize("args", [
    ["lookup", "CH-4F7A"],
    ["pseudonymize", "--name", "Test Child"],
    ["audit", "show"],
    ["users"],
])
def test_researcher_is_denied_owner_only_commands_and_it_is_logged(with_rana, args):
    r = rana(*args)
    assert r.exit_code == 1
    assert "may not" in r.output
    denied = [a for a in log_actions() if a[0] == "rana" and a[1].startswith("denied:")]
    assert len(denied) == 1


def test_researcher_cannot_create_users(with_rana):
    r = runner.invoke(app, ["--user", "rana", "add-user", "evil", "--user-passphrase", "evil-passphrase",
                            "--passphrase", RANA_PW])
    assert r.exit_code == 1 and "may not" in r.output
    assert ("rana", "denied:add_user") in log_actions()
    assert "evil" not in owner("users").output


def test_denied_entry_never_contains_a_real_name(with_rana):
    rana("pseudonymize", "--name", "Ayesha Khan")
    conn = db.connect()
    text = str(audit.show(conn))
    conn.close()
    assert "Ayesha" not in text


def test_researcher_verify_is_allowed(with_rana):
    r = rana("verify")
    assert r.exit_code == 0 and "Audit log OK" in r.output


def test_removed_researcher_cannot_log_in(with_rana):
    assert owner("remove-user", "rana").exit_code == 0
    assert rana("status").exit_code == 1
    assert ("owner", "remove_user") in log_actions()


def test_log_stays_valid_through_all_of_it(with_rana):
    rana("status")
    rana("lookup", "CH-4F7A")
    owner("users")
    assert owner("verify").exit_code == 0


def test_commands_refuse_to_run_on_a_tampered_log(with_rana):
    for _ in range(3):
        owner("status")
    conn = db.connect()
    with conn:
        conn.execute("DROP TRIGGER audit_log_no_delete")
        conn.execute("DELETE FROM audit_log WHERE seq IN (3, 4)")
    conn.close()
    r = owner("users")                                   # a normal, strict command
    assert r.exit_code == 1 and "integrity check" in r.output
    # read-only commands still work so the owner can investigate, and still report the damage
    v = owner("verify")
    assert v.exit_code == 1 and "TAMPERING" in v.output
    assert "WARNING" in owner("audit", "show").output
    # and the failed attempts did not heal the evidence
    assert owner("verify").exit_code == 1