"""Smoke test for scripts/benchmark.py: the quick profile runs end to end and its numbers make sense."""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import benchmark  # noqa: E402
from childvault import vault_crypto as vc  # noqa: E402

pytest.importorskip("matplotlib")


@pytest.fixture(scope="module")
def result(tmp_path_factory):
    out = tmp_path_factory.mktemp("bench_out")
    work = tmp_path_factory.mktemp("bench_work")
    res = benchmark.run("quick", out, work_dir=work)
    return res, out, work


def test_writes_all_outputs(result):
    _, out, _ = result
    for name in ["results.json", "results.md", "time_by_size.png", "size_overhead.png",
                 "chunk_size.png", "end_to_end.png"]:
        assert (out / name).is_file() and (out / name).stat().st_size > 0, name
    md = (out / "results.md").read_text(encoding="utf-8")
    for heading in ["## 1. Storage overhead", "## 2. Encrypt and decrypt speed", "## 3. Fixed costs",
                    "## 4. End to end", "## 5. Chunk size"]:
        assert heading in md
    json.loads((out / "results.json").read_text(encoding="utf-8"))


def test_encrypted_sizes_match_the_format(result):
    res, _, _ = result
    assert all(r["matches_formula"] for r in res["sizes"])
    assert all(r["overhead_bytes"] > 0 for r in res["chunks"])


def test_size_formula():
    per_chunk = vc.NONCE_LEN + vc.TAG_LEN
    assert benchmark.expected_enc_size(0) == vc.HEADER_LEN + per_chunk           # empty file = one empty chunk
    assert benchmark.expected_enc_size(vc.CHUNK_SIZE) == vc.HEADER_LEN + vc.CHUNK_SIZE + per_chunk
    assert benchmark.expected_enc_size(vc.CHUNK_SIZE + 1) == vc.HEADER_LEN + vc.CHUNK_SIZE + 1 + 2 * per_chunk


def test_timings_are_positive_and_end_to_end_adds_up(result):
    res, _, _ = result
    for r in res["sizes"]:
        assert r["copy_s"] > 0 and r["encrypt_s"] > 0 and r["decrypt_s"] > 0
    e = res["end_to_end"]
    assert e["add_file_s"] > 0 and e["open_file_s"] > 0
    assert e["add_other_s"] >= 0 and e["open_other_s"] >= 0
    f = res["fixed"]
    assert f["unlock_s"] > 0 and f["wrap_us"] > 0 and f["audit_append_ms"] > 0


def test_cleans_up_its_temporary_files(result):
    _, _, work = result
    assert list(work.iterdir()) == []

