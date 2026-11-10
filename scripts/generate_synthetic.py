#!/usr/bin/env python3
"""Generate SYNTHETIC test data for ChildVault. No real child data is ever used.

Usage:
    python scripts/generate_synthetic.py --out data/synthetic --seed 42
    python scripts/generate_synthetic.py --out data/synthetic --no-video   # if ffmpeg missing

Produces (deterministic for a given --seed, except ffmpeg video bytes):
    session_<n>.mp4          small test video (ffmpeg testsrc2 + sine tone)
    big_random.bin           3.5 MiB random file -> 4 chunks (3 full + 1 partial)
    exact_chunk.bin          exactly 1 MiB -> chunk boundary case
    empty.bin                0 bytes -> edge case
    observations.csv         fake child names + behaviour codes
    session_<n>.eaf          ELAN-style annotation XML
    children.txt             the fake names used (handy for pseudonymization tests)
"""
import argparse, csv, random, shutil, subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from xml.sax.saxutils import escape

MIB = 1024 * 1024
FIRST = ["Ayesha", "Hamza", "Zara", "Ali", "Noor", "Bilal", "Sana", "Omar", "Hira", "Usman"]
LAST = ["Khan", "Malik", "Sheikh", "Butt", "Raza", "Qureshi", "Chaudhry", "Mirza"]
CODES = {"SOC": "social engagement", "STM": "stereotypy", "AGG": "aggression",
         "ATT": "joint attention", "WTH": "withdrawal", "PLY": "solo play"}
NOTES = ["Avoided eye contact during task.", "Responded to name on second call.",
         "Smiled when shown picture cards.", "Became distressed at loud noise.",
         "Shared toy with peer unprompted.", "Repeated hand-flapping for ~10s."]


def fake_children(rng, n):
    names = set()
    while len(names) < n:
        names.add(f"{rng.choice(FIRST)} {rng.choice(LAST)}")
    return sorted(names)


def make_csv(path, rng, children, rows=60):
    start = datetime(2026, 1, 12, 9, 0, tzinfo=timezone.utc)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["child_name", "session", "timestamp", "behaviour_code", "behaviour", "clinician_note"])
        for i in range(rows):
            code = rng.choice(list(CODES))
            w.writerow([rng.choice(children), rng.randint(1, 3),
                        (start + timedelta(seconds=30 * i)).isoformat(),
                        code, CODES[code], rng.choice(NOTES)])


def make_eaf(path, rng, child, media_name, annotations=12):
    anns, t = [], 0
    for i in range(annotations):
        dur = rng.randint(1500, 5000)
        code = rng.choice(list(CODES))
        anns.append((f"a{i+1}", t, t + dur, f"{code}: {rng.choice(NOTES)}"))
        t += dur + rng.randint(200, 1000)
    times = sorted({x for a in anns for x in a[1:3]})
    sid = {v: f"ts{i}" for i, v in enumerate(times, 1)}
    slots = "".join(f'<TIME_SLOT TIME_SLOT_ID="{sid[v]}" TIME_VALUE="{v}"/>' for v in times)
    body = "".join(
        f'<ANNOTATION><ALIGNABLE_ANNOTATION ANNOTATION_ID="{a}" TIME_SLOT_REF1="{sid[s]}" '
        f'TIME_SLOT_REF2="{sid[e]}"><ANNOTATION_VALUE>{escape(txt)}</ANNOTATION_VALUE>'
        f'</ALIGNABLE_ANNOTATION></ANNOTATION>' for a, s, e, txt in anns)
    xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<ANNOTATION_DOCUMENT AUTHOR="synthetic" DATE="2026-01-12T09:00:00+00:00" FORMAT="3.0" VERSION="3.0">
<HEADER MEDIA_FILE="" TIME_UNITS="milliseconds"><MEDIA_DESCRIPTOR MEDIA_URL="file:///{media_name}" MIME_TYPE="video/mp4"/>
<PROPERTY NAME="participant">{escape(child)}</PROPERTY></HEADER>
<TIME_ORDER>{slots}</TIME_ORDER>
<TIER LINGUISTIC_TYPE_REF="default-lt" TIER_ID="Behaviour">{body}</TIER>
<LINGUISTIC_TYPE GRAPHIC_REFERENCES="false" LINGUISTIC_TYPE_ID="default-lt" TIME_ALIGNABLE="true"/>
</ANNOTATION_DOCUMENT>
'''
    Path(path).write_text(xml, encoding="utf-8")


def make_video(path, seconds=3):
    if not shutil.which("ffmpeg"):
        return False
    cmd = ["ffmpeg", "-y", "-loglevel", "error",
           "-f", "lavfi", "-i", f"testsrc2=size=320x240:rate=15:duration={seconds}",
           "-f", "lavfi", "-i", f"sine=frequency=440:duration={seconds}",
           "-c:v", "libx264", "-pix_fmt", "yuv420p", "-c:a", "aac", "-shortest", str(path)]
    subprocess.run(cmd, check=True)
    return True


def generate(out, seed=42, sessions=2, video=True):
    out = Path(out); out.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    children = fake_children(rng, 5)
    made = []
    make_csv(out / "observations.csv", rng, children); made.append("observations.csv")
    for n in range(1, sessions + 1):
        make_eaf(out / f"session_{n}.eaf", rng, children[n - 1], f"session_{n}.mp4")
        made.append(f"session_{n}.eaf")
        if video and make_video(out / f"session_{n}.mp4"):
            made.append(f"session_{n}.mp4")
    (out / "big_random.bin").write_bytes(rng.randbytes(3 * MIB + MIB // 2)); made.append("big_random.bin")
    (out / "exact_chunk.bin").write_bytes(rng.randbytes(MIB)); made.append("exact_chunk.bin")
    (out / "empty.bin").write_bytes(b""); made.append("empty.bin")
    (out / "children.txt").write_text("\n".join(children) + "\n"); made.append("children.txt")
    return children, made


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="data/synthetic")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--sessions", type=int, default=2)
    ap.add_argument("--no-video", action="store_true")
    a = ap.parse_args()
    _, made = generate(a.out, a.seed, a.sessions, not a.no_video)
    print("Generated in", a.out)
    for m in made:
        print("  ", m)
    if not a.no_video and not shutil.which("ffmpeg"):
        print("WARNING: ffmpeg not found - videos skipped")