"""CLI tests for `childvault verify` and `childvault audit show` (Laiba)."""
import pytest
from typer.testing import CliRunner

from childvault import audit, config, db
from childvault import vault_crypto as vc
from childvault.cli import app

PW = "test-passphrase-123"
runner = CliRunner()


@pytest.fixture
def vault(tmp_path, monkeypatch):
    """A tiny initialised vault in a temp folder (fast scrypt; no identity map needed)."""
    monkeypatch.setenv(config.ENV_VAR, str(tmp_path / "vault"))
    config.ensure_vault_dirs()
    conn = db.connect()
    db.create_schema(conn)
    header = vc.new_vault_header(PW, {"n": 2 ** 10, "r": 8, "p": 1})
    db.save_header(conn, header)
    key = audit.derive_audit_key(vc.unlock(PW, header))
    for i in range(3):
        audit.append_event(conn, key, "owner", "add_file", f"F-{i:016x}")
    conn.close()
    return tmp_path


def test_verify_ok(vault):
    r = runner.invoke(app, ["verify", "--passphrase", PW])
    assert r.exit_code == 0
    assert "3 entries verified" in r.output


def test_verify_wrong_passphrase(vault):
    r = runner.invoke(app, ["verify", "--passphrase", "not-the-passphrase"])
    assert r.exit_code == 1


def test_verify_detects_tampering(vault):
    conn = db.connect()
    with conn:
        conn.execute("DROP TRIGGER audit_log_no_update")
        conn.execute("UPDATE audit_log SET actor='intruder' WHERE seq=2")
    conn.close()
    r = runner.invoke(app, ["verify", "--passphrase", PW])
    assert r.exit_code == 1
    assert "TAMPERING" in r.output and "#2" in r.output


def test_audit_show_lists_entries(vault):
    r = runner.invoke(app, ["audit", "show", "--passphrase", PW])
    assert r.exit_code == 0
    assert r.output.count("add_file") == 3


def test_audit_show_limit(vault):
    r = runner.invoke(app, ["audit", "show", "--limit", "1", "--passphrase", PW])
    assert r.exit_code == 0 and r.output.count("add_file") == 1


def test_audit_show_warns_when_tampered(vault):
    conn = db.connect()
    with conn:
        conn.execute("DROP TRIGGER audit_log_no_delete")
        conn.execute("DELETE FROM audit_log WHERE seq=3")
    conn.close()
    r = runner.invoke(app, ["audit", "show", "--passphrase", PW])
    assert "WARNING" in r.output