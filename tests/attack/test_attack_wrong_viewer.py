"""
Attack family 3 - WRONG REVIEWER KEY (Laiba, Phase 5).

Reviewer B gets hold of reviewer A's bundle (or key file) and tries to use it.

Run with a results table:  $env:ATTACK_REPORT="attack_results.md"; python -m pytest tests/attack -q
"""
import json

import pytest

from attack_support import refused, retarget_to_reviewer_b
from childvault import keyshare as ks


@pytest.mark.attack("Wrong reviewer: B imports a bundle made for A", "Refused: made for a different reviewer key")
def test_other_reviewer_cannot_import(world):
    refused(world.import_bundle(world.bundle, who="B"), "different reviewer")


@pytest.mark.attack("Wrong reviewer: B opens a file with A's bundle", "Refused; nothing decrypted")
def test_other_reviewer_cannot_open(world, tmp_path):
    out = tmp_path / "plain"
    refused(world.open_shared(world.bundle, world.fid1, world.enc1, out, who="B"), "different reviewer")
    assert not out.exists()


@pytest.mark.attack("Wrong reviewer: B rewrites the reviewer fingerprint to their own", "Refused: signature invalid")
def test_other_reviewer_cannot_retarget_the_bundle(world, tmp_path):
    path = world.mutated_bundle("retarget", lambda d: retarget_to_reviewer_b(d, world))
    refused(world.import_bundle(path, who="B"), "signature")
    out = tmp_path / "plain"
    refused(world.open_shared(path, world.fid1, world.enc1, out, who="B"), "signature")
    assert not out.exists()


@pytest.mark.attack("Wrong reviewer: B uses A's key file without A's passphrase", "Refused: cannot open private key")
def test_stolen_key_file_without_passphrase(world):
    refused(world.import_bundle(world.bundle, who="A", pw="not-the-passphrase"), "cannot open private key")


@pytest.mark.attack("Wrong reviewer: B skips the checks and unwraps the keys directly", "Fails: the keys are locked to A's key")
def test_other_reviewer_cannot_unwrap_keys(world):
    payload = json.loads(world.bundle.read_text(encoding="utf-8"))["payload"]
    priv_b = ks.load_private_key(world.key["B"], world.pw["B"])
    with pytest.raises(ks.ShareUnwrapError):
        ks.unwrap_files_for_reviewer(payload["files"], priv_b)