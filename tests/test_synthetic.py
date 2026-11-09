"""Sanity tests for the synthetic data generator itself."""
import csv, hashlib
import xml.etree.ElementTree as ET
from generate_synthetic import generate, MIB


def test_expected_files_exist(synthetic_dir):
    for name in ["observations.csv", "session_1.eaf", "big_random.bin",
                 "exact_chunk.bin", "empty.bin", "children.txt"]:
        assert (synthetic_dir / name).exists(), name


def test_chunk_boundary_sizes(synthetic_dir):
    assert (synthetic_dir / "empty.bin").stat().st_size == 0
    assert (synthetic_dir / "exact_chunk.bin").stat().st_size == MIB
    assert (synthetic_dir / "big_random.bin").stat().st_size == 3 * MIB + MIB // 2


def test_csv_has_names_and_rows(synthetic_dir):
    rows = list(csv.DictReader(open(synthetic_dir / "observations.csv", encoding="utf-8")))
    assert len(rows) == 60 and rows[0]["child_name"]


def test_eaf_is_valid_xml(synthetic_dir):
    root = ET.parse(synthetic_dir / "session_1.eaf").getroot()
    assert root.tag == "ANNOTATION_DOCUMENT"
    assert len(root.findall(".//ANNOTATION")) == 12


def test_deterministic(tmp_path):
    generate(tmp_path / "a", seed=7, video=False)
    generate(tmp_path / "b", seed=7, video=False)
    h = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    for name in ["observations.csv", "big_random.bin", "session_1.eaf"]:
        assert h(tmp_path / "a" / name) == h(tmp_path / "b" / name)


def test_sample_files_are_copies(sample_files, synthetic_dir):
    sample_files["observations.csv"].write_bytes(b"tampered")
    assert (synthetic_dir / "observations.csv").read_bytes() != b"tampered"


def test_video_generated_when_ffmpeg_present(synthetic_dir):
    import shutil, pytest
    if not shutil.which("ffmpeg"):
        pytest.skip("ffmpeg not installed")
    assert (synthetic_dir / "session_1.mp4").stat().st_size > 1000