#!/usr/bin/env python3
"""Overhead benchmark for ChildVault (Aaleen, Phase 6).

How much does protecting a file cost, compared with keeping it as plaintext?

    python scripts/benchmark.py                       full run (about a minute)
    python scripts/benchmark.py --quick               tiny run, used by the smoke test
    python scripts/benchmark.py --out-dir docs/benchmark

Writes to --out-dir (default docs/benchmark):
    results.json          every raw number, plus the machine it ran on
    results.md            the tables, with the charts embedded
    time_by_size.png      copy vs encrypt vs decrypt, per file size
    size_overhead.png     extra bytes on disk, relative to the file size
    chunk_size.png        the chunk-size trade-off (time and peak memory)
    end_to_end.png        where the time of a real add-file / open-file goes

Five measurements:
  1. Size     - real .enc sizes, checked against the format's exact formula
  2. Speed    - encrypt_file / decrypt_file vs a plain copy of the same file.
                The copy also fsyncs, like encrypt/decrypt do, so the difference
                is the cost of the cryptography, not of the disk.
  3. Fixed    - scrypt unlock, key wrap/unwrap, one audit-log append, verify
  4. End to end - the real CLI add-file / open-file (in-process, so Python
                start-up time is NOT included)
  5. Chunk size - 64 KiB .. 4 MiB: time, on-disk overhead and peak memory

Every timing is the MEDIAN of --repeats runs. Data is random bytes (encryption
speed does not depend on content). Numbers depend on the machine, the disk and
the OS file cache, so the machine is recorded next to them.
"""

import argparse
import json
import math
import os
import platform
import shutil
import statistics
import sys
import tempfile
import time
import tracemalloc
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))          # so `import childvault` works from any folder

from childvault import audit, db  # noqa: E402
from childvault import vault_crypto as vc  # noqa: E402

KiB = 1024
MiB = 1024 * KiB
PASSPHRASE = "benchmark passphrase"
FID = "F-0123456789abcdef"

PROFILES = {
    "full": dict(sizes=[0, KiB, 64 * KiB, MiB, 10 * MiB, 100 * MiB], repeats=5,
                 chunk_file=100 * MiB, chunk_sizes=[64 * KiB, 256 * KiB, MiB, 4 * MiB],
                 e2e_size=10 * MiB, audit_entries=1000, wrap_iters=2000),
    "quick": dict(sizes=[0, KiB, MiB + 1], repeats=1,
                  chunk_file=2 * MiB, chunk_sizes=[64 * KiB, MiB],
                  e2e_size=MiB, audit_entries=20, wrap_iters=20),
}

COLORS = {"copy": "#94a3b8", "encrypt": "#2563eb", "decrypt": "#16a34a",
          "unlock": "#f59e0b", "other": "#a855f7", "memory": "#0f766e"}


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def human(n: int) -> str:
    if n == 0:
        return "0 B"
    for unit, size in (("MiB", MiB), ("KiB", KiB)):
        if n >= size:
            v = n / size
            return f"{v:.0f} {unit}" if v == int(v) else f"{v:.2f} {unit}"
    return f"{n} B"


def timed(fn, repeats: int) -> dict:
    """Run fn `repeats` times; return median and all runs, in seconds."""
    runs = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        fn()
        runs.append(time.perf_counter() - t0)
    return {"median": statistics.median(runs), "min": min(runs), "max": max(runs), "runs": runs}


def plain_copy(src: Path, dst: Path, chunk: int = vc.CHUNK_SIZE) -> None:
    """The baseline: copy the file in the same chunk size and fsync it, like encrypt/decrypt do."""
    with open(src, "rb") as s, open(dst, "wb") as d:
        while True:
            block = s.read(chunk)
            if not block:
                break
            d.write(block)
        d.flush()
        os.fsync(d.fileno())


def expected_enc_size(n: int, chunk: int = vc.CHUNK_SIZE) -> int:
    """Exact size of an encrypted file: header + data + (nonce + tag) per chunk (at least one)."""
    chunks = max(1, math.ceil(n / chunk))
    return vc.HEADER_LEN + n + chunks * (vc.NONCE_LEN + vc.TAG_LEN)


def make_file(path: Path, size: int) -> Path:
    with open(path, "wb") as f:
        left = size
        while left:
            step = min(left, 8 * MiB)
            f.write(os.urandom(step))
            left -= step
    return path


def mib_per_s(size: int, seconds: float) -> float | None:
    return size / MiB / seconds if size >= MiB and seconds > 0 else None


def machine_info() -> dict:
    import cryptography
    return {
        "date_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "os": f"{platform.system()} {platform.release()} ({platform.version()})",
        "cpu": platform.processor() or platform.machine(),
        "cpu_count": os.cpu_count(),
        "python": platform.python_version(),
        "cryptography": cryptography.__version__,
        "openssl": _openssl_version(),
        "chunk_size": vc.CHUNK_SIZE,
        "scrypt": vc.DEFAULT_SCRYPT_PARAMS,
    }


def _openssl_version() -> str:
    try:
        from cryptography.hazmat.backends.openssl import backend
        return backend.openssl_version_text()
    except Exception:          # pragma: no cover - depends on the cryptography build
        return "unknown"


# --------------------------------------------------------------------------
# 1 + 2. size and speed per file size
# --------------------------------------------------------------------------

def bench_sizes(work: Path, sizes: list[int], repeats: int) -> list[dict]:
    rows = []
    key = vc.generate_data_key()
    for size in sizes:
        src = make_file(work / f"plain_{size}.bin", size)
        enc, out, cpy = work / f"x_{size}.enc", work / f"x_{size}.out", work / f"x_{size}.copy"

        copy_t = timed(lambda: plain_copy(src, cpy), repeats)
        enc_t = timed(lambda: vc.encrypt_file(src, enc, key, FID), repeats)
        dec_t = timed(lambda: vc.decrypt_file(enc, out, key, FID), repeats)
        assert out.read_bytes() == src.read_bytes() if size <= 10 * MiB else out.stat().st_size == size

        enc_size = enc.stat().st_size
        expected = expected_enc_size(size)
        rows.append({
            "size": size, "label": human(size),
            "enc_size": enc_size, "expected_enc_size": expected, "matches_formula": enc_size == expected,
            "overhead_bytes": enc_size - size,
            "overhead_pct": (enc_size - size) / size * 100 if size else None,
            "copy_s": copy_t["median"], "encrypt_s": enc_t["median"], "decrypt_s": dec_t["median"],
            "encrypt_min_s": enc_t["min"], "encrypt_max_s": enc_t["max"],
            "decrypt_min_s": dec_t["min"], "decrypt_max_s": dec_t["max"],
            "copy_runs": copy_t["runs"], "encrypt_runs": enc_t["runs"], "decrypt_runs": dec_t["runs"],
            "copy_mibs": mib_per_s(size, copy_t["median"]),
            "encrypt_mibs": mib_per_s(size, enc_t["median"]),
            "decrypt_mibs": mib_per_s(size, dec_t["median"]),
        })
        for p in (src, enc, out, cpy):
            p.unlink(missing_ok=True)
    return rows


# --------------------------------------------------------------------------
# 3. fixed per-operation costs
# --------------------------------------------------------------------------

def bench_fixed(work: Path, repeats: int, wrap_iters: int, audit_entries: int) -> dict:
    header = vc.new_vault_header(PASSPHRASE)
    unlock_t = timed(lambda: vc.unlock(PASSPHRASE, header), repeats)
    kek = vc.unlock(PASSPHRASE, header)

    dk = vc.generate_data_key()
    t0 = time.perf_counter()
    for _ in range(wrap_iters):
        wrapped = vc.wrap_key(kek, dk, FID)
    wrap_us = (time.perf_counter() - t0) / wrap_iters * 1e6
    t0 = time.perf_counter()
    for _ in range(wrap_iters):
        vc.unwrap_key(kek, wrapped, FID)
    unwrap_us = (time.perf_counter() - t0) / wrap_iters * 1e6

    conn = db.connect(work / "audit_bench.db")
    try:
        db.create_schema(conn)
        akey = audit.derive_audit_key(kek)
        appends = []
        for i in range(audit_entries):
            t0 = time.perf_counter()
            audit.append_event(conn, akey, "owner", "open_file", FID, {"n": i})
            appends.append(time.perf_counter() - t0)
        verify_t = timed(lambda: audit.verify_chain(conn, akey), repeats)
        assert audit.verify_chain(conn, akey).ok
    finally:
        conn.close()

    return {
        "unlock_s": unlock_t["median"], "unlock_runs": unlock_t["runs"],
        "wrap_us": wrap_us, "unwrap_us": unwrap_us,
        "audit_append_ms": statistics.median(appends) * 1000,
        "audit_entries": audit_entries,
        "audit_verify_s": verify_t["median"],
        "audit_verify_per_entry_us": verify_t["median"] / audit_entries * 1e6,
    }


# --------------------------------------------------------------------------
# 4. end to end through the real CLI
# --------------------------------------------------------------------------

def bench_end_to_end(work: Path, size: int, repeats: int) -> dict:
    from typer.testing import CliRunner
    from childvault.cli import app

    runner = CliRunner()
    old = os.environ.get("CHILDVAULT_HOME")
    os.environ["CHILDVAULT_HOME"] = str(work / "vault")
    try:
        r = runner.invoke(app, ["init", "--passphrase", PASSPHRASE])
        assert r.exit_code == 0, r.output
        src = make_file(work / "e2e.bin", size)
        ids, adds, opens = [], [], []
        for _ in range(repeats):
            t0 = time.perf_counter()
            r = runner.invoke(app, ["add-file", str(src), "--type", "other", "--passphrase", PASSPHRASE])
            adds.append(time.perf_counter() - t0)
            assert r.exit_code == 0, r.output
            ids.append(r.output.split("Added ")[1].split()[0])
        for i, fid in enumerate(ids):
            out = work / f"e2e_out_{i}.bin"
            t0 = time.perf_counter()
            r = runner.invoke(app, ["open-file", fid, "--out", str(out), "--passphrase", PASSPHRASE])
            opens.append(time.perf_counter() - t0)
            assert r.exit_code == 0, r.output
            out.unlink()

        # The parts we can isolate, measured on the same file and machine.
        key = vc.generate_data_key()
        enc = work / "e2e.enc"
        enc_t = timed(lambda: vc.encrypt_file(src, enc, key, FID), repeats)["median"]
        dec_t = timed(lambda: vc.decrypt_file(enc, work / "e2e.dec", key, FID), repeats)["median"]
        header = vc.new_vault_header(PASSPHRASE)
        unlock_t = timed(lambda: vc.unlock(PASSPHRASE, header), repeats)["median"]
    finally:
        if old is None:
            os.environ.pop("CHILDVAULT_HOME", None)
        else:
            os.environ["CHILDVAULT_HOME"] = old

    add_s, open_s = statistics.median(adds), statistics.median(opens)
    return {
        "size": size, "label": human(size),
        "add_file_s": add_s, "open_file_s": open_s, "add_runs": adds, "open_runs": opens,
        "unlock_s": unlock_t, "encrypt_s": enc_t, "decrypt_s": dec_t,
        "add_other_s": max(0.0, add_s - unlock_t - enc_t),
        "open_other_s": max(0.0, open_s - unlock_t - dec_t),
    }


# --------------------------------------------------------------------------
# 5. chunk size
# --------------------------------------------------------------------------

def _peak_memory(fn) -> int:
    tracemalloc.start()
    try:
        fn()
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def crypto_only(data: memoryview, chunk_size: int, key: bytes, repeats: int) -> tuple[float, float]:
    """
    The exact per-chunk work of encrypt_file / decrypt_file (random nonce, the same
    AAD, AES-256-GCM), done on bytes in memory with no file I/O. Isolates the cost
    of the cryptography from the disk and the OS cache. Returns (enc MiB/s, dec MiB/s).
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    aead = AESGCM(key)
    header = vc._HEADER.pack(vc.MAGIC, vc.FORMAT_VERSION, chunk_size)
    n = max(1, math.ceil(len(data) / chunk_size))
    pieces = [data[i * chunk_size:(i + 1) * chunk_size] for i in range(n)]
    aads = [vc._chunk_aad(header, FID, i, i == n - 1) for i in range(n)]
    # Ciphertexts for the decrypt timing are made once, outside the timed part.
    sealed = []
    for piece, aad in zip(pieces, aads):
        nonce = os.urandom(vc.NONCE_LEN)
        sealed.append((nonce, aead.encrypt(nonce, piece, aad)))

    # Both timed loops treat their output the same way (made, then dropped), so the
    # comparison is not skewed by one of them keeping 100 MiB alive in memory.
    def enc():
        for piece, aad in zip(pieces, aads):
            nonce = os.urandom(vc.NONCE_LEN)
            aead.encrypt(nonce, piece, aad)

    def dec():
        for (nonce, ct), aad in zip(sealed, aads):
            aead.decrypt(nonce, ct, aad)

    e = timed(enc, repeats)["median"]
    d = timed(dec, repeats)["median"]
    return len(data) / MiB / e, len(data) / MiB / d


def bench_chunks(work: Path, file_size: int, chunk_sizes: list[int], repeats: int) -> list[dict]:
    src = make_file(work / "chunks.bin", file_size)
    key = vc.generate_data_key()
    data = memoryview(src.read_bytes())
    rows = []
    for cs in chunk_sizes:
        mem_enc, mem_dec = crypto_only(data, cs, key, repeats)
        enc, out = work / f"c_{cs}.enc", work / f"c_{cs}.out"
        enc_t = timed(lambda: vc.encrypt_file(src, enc, key, FID, chunk_size=cs), repeats)
        dec_t = timed(lambda: vc.decrypt_file(enc, out, key, FID), repeats)
        # Separate runs for memory: tracemalloc slows Python down, so it must not touch the timings.
        enc_mem = _peak_memory(lambda: vc.encrypt_file(src, enc, key, FID, chunk_size=cs))
        dec_mem = _peak_memory(lambda: vc.decrypt_file(enc, out, key, FID))
        enc_size = enc.stat().st_size
        assert enc_size == expected_enc_size(file_size, cs)
        rows.append({
            "chunk_size": cs, "label": human(cs), "file_size": file_size,
            "chunks": math.ceil(file_size / cs),
            "encrypt_s": enc_t["median"], "decrypt_s": dec_t["median"],
            "encrypt_min_s": enc_t["min"], "encrypt_max_s": enc_t["max"],
            "decrypt_min_s": dec_t["min"], "decrypt_max_s": dec_t["max"],
            "mem_encrypt_mibs": mem_enc, "mem_decrypt_mibs": mem_dec,
            "encrypt_mibs": mib_per_s(file_size, enc_t["median"]),
            "decrypt_mibs": mib_per_s(file_size, dec_t["median"]),
            "overhead_bytes": enc_size - file_size,
            "overhead_pct": (enc_size - file_size) / file_size * 100,
            "encrypt_peak_mem": enc_mem, "decrypt_peak_mem": dec_mem,
        })
        enc.unlink(missing_ok=True)
        out.unlink(missing_ok=True)
    src.unlink(missing_ok=True)
    return rows


# --------------------------------------------------------------------------
# charts
# --------------------------------------------------------------------------

def make_charts(res: dict, out_dir: Path) -> list[str]:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update({"figure.dpi": 130, "axes.spines.top": False, "axes.spines.right": False,
                         "axes.grid": True, "grid.alpha": 0.3, "font.size": 10})
    made = []

    # 1. time by size
    rows = res["sizes"]
    fig, ax = plt.subplots(figsize=(8, 4.2))
    x = range(len(rows))
    w = 0.27
    for i, (k, name) in enumerate((("copy_s", "plain copy"), ("encrypt_s", "encrypt"), ("decrypt_s", "decrypt"))):
        ax.bar([p + (i - 1) * w for p in x], [r[k] * 1000 for r in rows], w,
               label=name, color=COLORS[name.split()[-1]])
    ax.set_yscale("log")
    ax.set_xticks(list(x), [r["label"] for r in rows])
    ax.set_xlabel("file size")
    ax.set_ylabel("time (ms, log scale)")
    ax.set_title("Encrypt and decrypt vs a plain copy (median)", pad=14)
    ax.set_ylim(top=max(r["encrypt_s"] for r in rows) * 1000 * 4)   # room for the labels
    ax.legend(frameon=False)
    for p, r in zip(x, rows):
        if r["encrypt_mibs"]:
            ax.annotate(f"{r['encrypt_mibs']:.0f} / {r['decrypt_mibs']:.0f} MiB/s", (p, r["encrypt_s"] * 1000),
                        textcoords="offset points", xytext=(0, 14), ha="center", fontsize=8, color="#334155")
    fig.tight_layout()
    fig.savefig(out_dir / "time_by_size.png")
    plt.close(fig)
    made.append("time_by_size.png")

    # 2. size overhead
    nz = [r for r in rows if r["size"] > 0]
    fig, ax = plt.subplots(figsize=(8, 3.6))
    ax.plot([r["size"] for r in nz], [r["overhead_pct"] for r in nz], "o-", color=COLORS["encrypt"])
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("file size (bytes, log scale)")
    ax.set_ylabel("extra bytes on disk (%, log scale)")
    ax.set_title("Storage overhead: 9-byte header + 28 bytes per 1 MiB chunk")
    for i, r in enumerate(nz):
        last = i == len(nz) - 1                      # the last two points sit close: put the last one below
        ax.annotate(f"+{r['overhead_bytes']:,} B ({r['overhead_pct']:.3g}%)", (r["size"], r["overhead_pct"]),
                    textcoords="offset points", xytext=(-40, -16) if last else (6, 6),
                    fontsize=8, color="#334155")
    ax.set_xlim(right=max(r["size"] for r in nz) * 8)       # room for the last label
    ax.set_ylim(bottom=min(r["overhead_pct"] for r in nz) / 4)
    fig.tight_layout()
    fig.savefig(out_dir / "size_overhead.png")
    plt.close(fig)
    made.append("size_overhead.png")

    # 3. chunk size
    ch = res["chunks"]
    fig, (a1, a2, a3) = plt.subplots(1, 3, figsize=(12, 3.8))
    x = range(len(ch))
    w = 0.38
    names = [r["label"] for r in ch]

    def pair(ax, ke, kd, scale, ylabel, title):
        ax.bar([p - w / 2 for p in x], [r[ke] * scale for r in ch], w, label="encrypt", color=COLORS["encrypt"])
        ax.bar([p + w / 2 for p in x], [r[kd] * scale for r in ch], w, label="decrypt", color=COLORS["decrypt"])
        ax.set_xticks(list(x), names)
        ax.set_xlabel("chunk size")
        ax.set_ylabel(ylabel)
        ax.set_title(title, fontsize=10)
        ax.legend(frameon=False, fontsize=8)

    pair(a1, "mem_encrypt_mibs", "mem_decrypt_mibs", 1, "MiB/s", "Pure AES-GCM, in memory")
    pair(a2, "encrypt_s", "decrypt_s", 1000, "ms", f"With the disk, {human(ch[0]['file_size'])} file")
    pair(a3, "encrypt_peak_mem", "decrypt_peak_mem", 1 / MiB, "MiB", "Peak Python memory")
    fig.tight_layout()
    fig.savefig(out_dir / "chunk_size.png")
    plt.close(fig)
    made.append("chunk_size.png")

    # 4. end to end
    e = res["end_to_end"]
    fig, ax = plt.subplots(figsize=(8, 3.0))
    labels = [f"add-file ({e['label']})", f"open-file ({e['label']})"]
    unlock = [e["unlock_s"], e["unlock_s"]]
    crypto = [e["encrypt_s"], e["decrypt_s"]]
    other = [e["add_other_s"], e["open_other_s"]]
    ax.barh(labels, unlock, color=COLORS["unlock"], label="scrypt unlock")
    ax.barh(labels, crypto, left=unlock, color=COLORS["encrypt"], label="encrypt / decrypt")
    ax.barh(labels, other, left=[a + b for a, b in zip(unlock, crypto)], color=COLORS["other"],
            label="database, audit log, CLI")
    ax.invert_yaxis()
    ax.set_xlabel("seconds (median)")
    ax.set_title("Where the time of a real command goes")
    ax.legend(frameon=False, fontsize=8, ncol=3, loc="upper center", bbox_to_anchor=(0.5, -0.3))
    fig.tight_layout()
    fig.savefig(out_dir / "end_to_end.png", bbox_inches="tight")
    plt.close(fig)
    made.append("end_to_end.png")
    return made


# --------------------------------------------------------------------------
# markdown
# --------------------------------------------------------------------------

def _ms(s: float) -> str:
    ms = s * 1000
    return f"{ms:.2f}" if ms < 10 else f"{ms:.0f}"


def _rate(v) -> str:
    return f"{v:.0f}" if v else "-"


def build_markdown(res: dict) -> str:
    m = res["machine"]
    L = ["# Benchmark results", "",
         "Generated by `python scripts/benchmark.py`. Do not edit by hand.", "",
         f"Machine: {m['cpu']}, {m['cpu_count']} logical CPUs, {m['os']}. "
         f"Python {m['python']}, cryptography {m['cryptography']} ({m['openssl']}). "
         f"Run on {m['date_utc']}, profile `{res['profile']}`, median of {res['repeats']} runs.", ""]

    L += ["## 1. Storage overhead", "",
          "| File size | Encrypted size | Extra bytes | Extra % | Matches formula |",
          "|---:|---:|---:|---:|:---:|"]
    for r in res["sizes"]:
        pct = f"{r['overhead_pct']:.4g}%" if r["overhead_pct"] is not None else "-"
        L.append(f"| {r['label']} | {r['enc_size']:,} B | {r['overhead_bytes']:,} B | {pct} | "
                 f"{'yes' if r['matches_formula'] else '**NO**'} |")
    L += ["", "Every file also has a 60-byte wrapped data key in the database.", "",
          "![Storage overhead](size_overhead.png)", ""]

    L += ["## 2. Encrypt and decrypt speed", "",
          "| File size | Plain copy (ms) | Encrypt (ms) | Encrypt range | Decrypt (ms) | Decrypt range | Copy MiB/s | Encrypt MiB/s | Decrypt MiB/s |",
          "|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for r in res["sizes"]:
        L.append(f"| {r['label']} | {_ms(r['copy_s'])} | {_ms(r['encrypt_s'])} | {_ms(r['encrypt_min_s'])}-{_ms(r['encrypt_max_s'])} | "
                 f"{_ms(r['decrypt_s'])} | {_ms(r['decrypt_min_s'])}-{_ms(r['decrypt_max_s'])} | "
                 f"{_rate(r['copy_mibs'])} | {_rate(r['encrypt_mibs'])} | {_rate(r['decrypt_mibs'])} |")
    L += ["", "The plain copy reads and writes in the same 1 MiB blocks and also calls fsync, so the "
          "difference to encrypt/decrypt is the cost of the cryptography, not of the disk. "
          "Range = fastest and slowest of the runs.", "",
          "![Time by size](time_by_size.png)", ""]

    f = res["fixed"]
    L += ["## 3. Fixed costs per operation", "",
          "| Operation | Time |", "|---|---:|",
          f"| Unlock: scrypt (n={m['scrypt']['n']}, r={m['scrypt']['r']}, p={m['scrypt']['p']}) + check value | {f['unlock_s'] * 1000:.0f} ms |",
          f"| Wrap one data key (AES-GCM) | {f['wrap_us']:.1f} µs |",
          f"| Unwrap one data key | {f['unwrap_us']:.1f} µs |",
          f"| Append one audit-log entry (one SQLite transaction) | {f['audit_append_ms']:.2f} ms |",
          f"| Verify the audit log ({f['audit_entries']:,} entries) | {f['audit_verify_s'] * 1000:.0f} ms "
          f"({f['audit_verify_per_entry_us']:.1f} µs per entry) |", ""]

    e = res["end_to_end"]
    L += ["## 4. End to end (real CLI commands)", "",
          f"`add-file` and `open-file` on a {e['label']} file, run in-process (Python start-up not included).", "",
          "| Command | Total | scrypt unlock | Encrypt / decrypt | Database, audit log, CLI |",
          "|---|---:|---:|---:|---:|",
          f"| add-file | {_ms(e['add_file_s'])} ms | {_ms(e['unlock_s'])} ms | {_ms(e['encrypt_s'])} ms | {_ms(e['add_other_s'])} ms |",
          f"| open-file | {_ms(e['open_file_s'])} ms | {_ms(e['unlock_s'])} ms | {_ms(e['decrypt_s'])} ms | {_ms(e['open_other_s'])} ms |",
          "", "![End to end](end_to_end.png)", ""]

    L += ["## 5. Chunk size", "",
          f"One {human(res['chunks'][0]['file_size'])} file, encrypted with each chunk size.", "",
          "| Chunk size | Chunks | In memory: encrypt MiB/s | In memory: decrypt MiB/s | With disk: encrypt ms (range) | With disk: decrypt ms (range) | Extra bytes | Peak memory encrypt | Peak memory decrypt |",
          "|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for r in res["chunks"]:
        L.append(f"| {r['label']} | {r['chunks']:,} | {_rate(r['mem_encrypt_mibs'])} | {_rate(r['mem_decrypt_mibs'])} | "
                 f"{_ms(r['encrypt_s'])} ({_ms(r['encrypt_min_s'])}-{_ms(r['encrypt_max_s'])}) | "
                 f"{_ms(r['decrypt_s'])} ({_ms(r['decrypt_min_s'])}-{_ms(r['decrypt_max_s'])}) | {r['overhead_bytes']:,} B | "
                 f"{r['encrypt_peak_mem'] / MiB:.1f} MiB | {r['decrypt_peak_mem'] / MiB:.1f} MiB |")
    L += ["", "*In memory* does exactly the per-chunk work of encrypt/decrypt (random nonce, same AAD, "
          "AES-256-GCM) with no file I/O, so it shows the cost of the cryptography alone. *With disk* is the "
          "real encrypt_file / decrypt_file: median, with the fastest and slowest run in brackets.", "",
          "Peak memory is measured with `tracemalloc` in separate runs, so it does not slow the timings.", "",
          "![Chunk size](chunk_size.png)", ""]
    return "\n".join(L)


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def run(profile: str, out_dir: Path, work_dir: Path | None = None, charts: bool = True) -> dict:
    p = PROFILES[profile]
    out_dir.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="cv_bench_", dir=work_dir))
    try:
        print("1-2. size and speed ...", flush=True)
        sizes = bench_sizes(tmp, p["sizes"], p["repeats"])
        print("3.   fixed costs ...", flush=True)
        fixed = bench_fixed(tmp, p["repeats"], p["wrap_iters"], p["audit_entries"])
        print("4.   end to end ...", flush=True)
        e2e = bench_end_to_end(tmp, p["e2e_size"], p["repeats"])
        print("5.   chunk size ...", flush=True)
        chunks = bench_chunks(tmp, p["chunk_file"], p["chunk_sizes"], p["repeats"])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    res = {"profile": profile, "repeats": p["repeats"], "machine": machine_info(),
           "sizes": sizes, "fixed": fixed, "end_to_end": e2e, "chunks": chunks}
    (out_dir / "results.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    if charts:
        make_charts(res, out_dir)
    (out_dir / "results.md").write_text(build_markdown(res), encoding="utf-8")
    return res


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quick", action="store_true", help="tiny run (seconds), for the smoke test")
    ap.add_argument("--out-dir", default=str(ROOT / "docs" / "benchmark"))
    ap.add_argument("--work-dir", default=None, help="where temporary test files go (default: system temp)")
    args = ap.parse_args()

    res = run("quick" if args.quick else "full", Path(args.out_dir),
              Path(args.work_dir) if args.work_dir else None)
    bad = [r["label"] for r in res["sizes"] if not r["matches_formula"]]
    print(f"\nWritten to {args.out_dir}: results.md, results.json and 4 charts.")
    if bad:
        print(f"WARNING: encrypted size did not match the formula for: {', '.join(bad)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
