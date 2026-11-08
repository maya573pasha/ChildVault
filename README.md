# ChildVault

Encrypted, tamper-evident storage for sensitive child-behaviour data.
CS3002 Information Security, Fall 2026 term project.

**Team:** Mariyam Pasha (23L-0809), Aaleen Fatima (23L-0652), Laiba Amjad (23L-0642)

## What it is

A prototype offline vault that encrypts sensitive child-behaviour recordings and
annotations, pseudonymizes identities, and logs every access in a tamper-evident
audit log. It is built only from standard cryptography. All demos use synthetic
test files, never real child data.

## Goals

- Encrypt every file at rest with AES-256-GCM, using a separate random key per file
- Pseudonymize identities, with the ID-name map kept in a separate encrypted file
- Keep a SHA-256 hash-chained audit log that detects edited, deleted, or reordered entries
- Support scoped, time-limited sharing with a reviewer
- Demonstrate attacks (bit-flip, chunk swap, truncation, log edit) and show the vault detects them

## Tech stack

Python 3.11, `cryptography`, SQLite, Typer (CLI), FastAPI (web UI), pytest, ffmpeg (synthetic test videos).

## Setup

```bash
git clone <repo-url>
cd childvault
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Running the tests

```bash
python -m pytest
```

## Project structure

```
childvault/
├── childvault/        # Python package (crypto, identity, audit, sharing, CLI, web UI)
├── tests/             # unit tests and the attack suite
├── scripts/           # synthetic data generator, benchmark
├── demo/              # end-to-end demo script
└── docs/              # report and slides
```

## Status

Work in progress. Phase 1 (key management) is in place; the other modules are being built.

## Limitations

- Expiry of shared access is enforced by the honest client software.
- Revocation works by re-encrypting the file under a new key.
- Not protected against malware running while the vault is unlocked, or a user who reveals the passphrase.