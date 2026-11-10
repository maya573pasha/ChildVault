<p align="center">
  <img src="docs/assets/hero.svg" alt="ChildVault: plaintext goes into a vault and comes out encrypted" width="100%">
</p>

<p align="center">
  <img alt="Python 3.11" src="https://img.shields.io/badge/python-3.11-3776AB?logo=python&logoColor=white">
  <img alt="AES-256-GCM" src="https://img.shields.io/badge/encryption-AES--256--GCM-1d4ed8">
  <img alt="Ed25519 + X25519" src="https://img.shields.io/badge/sharing-X25519%20%2B%20Ed25519-7c3aed">
  <img alt="Attack suite" src="https://img.shields.io/badge/attacks%20detected-79%2F79-16a34a">
  <img alt="Built with standard cryptography only" src="https://img.shields.io/badge/crypto-standard%20primitives%20only-0f766e">
</p>

<p align="center">
  <b>An offline vault for sensitive child-behaviour recordings and annotations.</b><br>
  Encrypts every file, hides every child's name behind a pseudonym, shares data with reviewers
  through signed, expiring bundles, and <i>proves</i> when someone tampers with it.
</p>

<p align="center">
  CS3002 Information Security, Fall 2026 term project<br>
  Mariyam Pasha (23L-0809) · Aaleen Fatima (23L-0652) · Laiba Amjad (23L-0642)
</p>

---

## See it work

<p align="center">
  <img src="docs/assets/terminal.svg" alt="Terminal demo: add a file, open it, then flip one bit and watch decryption fail" width="100%">
</p>

One flipped bit in a stored file and the vault refuses to hand over *any* of it. All demos use synthetic data, never real child data.

---

## Contents

- [Why this exists](#why-this-exists)
- [What you get](#what-you-get)
- [How it works](#how-it-works)
  - [Architecture](#architecture)
  - [Key hierarchy](#key-hierarchy)
  - [Encrypted file format](#encrypted-file-format)
  - [Tamper detection](#tamper-detection)
  - [Sharing with a reviewer](#sharing-with-a-reviewer)
  - [Revocation](#revocation)
- [Quick start](#quick-start)
- [Command reference](#command-reference)
- [Web UI](#web-ui)
- [Threat model and attack results](#threat-model-and-attack-results)
- [Testing](#testing)
- [Project structure](#project-structure)
- [Project status](#project-status)
- [Limitations](#limitations)

---

## Why this exists

Autism-research teams record children on video and annotate their behaviour. That data is
about as sensitive as data gets: it identifies a child *and* describes their health.
A stolen laptop, a shared drive, or a careless collaborator should not be able to expose it,
and nobody should be able to quietly alter the evidence either.

ChildVault is a small, readable prototype that shows how to do this with **only standard,
well-reviewed cryptography** (no home-made ciphers), and how to *demonstrate* that it works by attacking it.

## What you get

| | Feature | How |
|---|---|---|
| 🔐 | **Encryption at rest** | AES-256-GCM in 1 MiB chunks, a separate random key for every file |
| 🔑 | **Passphrase-protected vault** | scrypt turns the passphrase into a key-encryption key (KEK) that only lives in memory |
| 🪪 | **Pseudonymization** | Children become `CH-4F7A`. The ID-to-name map is a separate encrypted file |
| 🧱 | **Tamper evidence** | Chunk number, file ID and a "final chunk" flag are bound into every chunk, so edits, swaps and truncation all fail loudly |
| 📤 | **Scoped, expiring sharing** | Per-reviewer X25519 key wrapping, Ed25519-signed bundle, expiry date |
| ♻️ | **Revocation** | Re-encrypt a file under a brand-new key; old bundles stop working on the vault copy |
| 🖥️ | **CLI and local web UI** | Typer commands, plus a FastAPI page on `127.0.0.1` only |
| ⚔️ | **Attack suite** | 32 attack types, 79 variants, every one must be detected ([results](docs/attack_results.md)) |

---

## How it works

### Architecture

The CLI and the web UI are thin shells over the same operations, so they cannot drift apart.

```mermaid
flowchart LR
    subgraph UI["Interfaces"]
        CLI["Typer CLI"]
        WEB["FastAPI web UI<br/>127.0.0.1 only"]
    end

    OPS["ops.py<br/>add / open / revoke"]

    subgraph CRYPTO["Cryptography"]
        VC["vault_crypto<br/>scrypt, AES-GCM chunks,<br/>key wrapping"]
        KS["keyshare<br/>X25519 reviewer wrap"]
        BN["bundle<br/>Ed25519 signed bundles"]
    end

    ID["identity<br/>pseudonyms + encrypted map"]

    subgraph DISK["Vault folder"]
        DB[("childvault.db<br/>SQLite: files, audit_log, meta")]
        ENC[("files/*.enc<br/>encrypted data")]
        MAP[("identity_map.enc<br/>names, encrypted")]
    end

    CLI --> OPS
    WEB --> OPS
    CLI --> KS
    CLI --> BN
    CLI --> ID
    WEB --> ID
    OPS --> VC
    KS --> VC
    BN --> KS
    OPS --> DB
    OPS --> ENC
    ID --> MAP
```

### Key hierarchy

Your passphrase is the root of everything. Nothing secret is stored in plaintext, and the
KEK is never written to disk.

```mermaid
flowchart TD
    P["Vault passphrase"] -->|"scrypt + random salt"| KEK["KEK<br/>256-bit, memory only"]
    KEK -->|"AES-GCM wrap,<br/>bound to the file ID"| DK["Data key<br/>one per file"]
    KEK -->|"AES-GCM wrap"| SK["Ed25519 signing key<br/>signs share bundles"]
    KEK -->|"encrypts"| MAP["ID-to-name map"]
    DK -->|"AES-256-GCM, 1 MiB chunks"| ENC["file.enc"]
```

Because every file has its own key, revoking one file never touches the others.

### Encrypted file format

```text
┌──────────── header (9 bytes) ────────────┐
│ "CVLT" │ version (1) │ chunk size (4)    │
└──────────────────────────────────────────┘
┌─ chunk 0 ─────────────┐┌─ chunk 1 ─────────────┐   ┌─ last chunk ──────────┐
│ nonce │ data │ tag    ││ nonce │ data │ tag    │ … │ nonce │ data │ tag    │
│  12   │ 1 MiB│  16    ││  12   │ 1 MiB│  16    │   │  12   │ ≤1 MiB│ 16    │
└───────────────────────┘└───────────────────────┘   └───────────────────────┘

Each chunk's authenticated data (AAD) =
    header  +  file ID  +  chunk number  +  "is this the final chunk?" flag
```

### Tamper detection

Binding those four things into every chunk is what makes each attack fail. Decryption writes
to a temporary file and only moves it into place after the *last* chunk verifies, so a failed
decrypt never leaves usable plaintext behind.

<p align="center">
  <img src="docs/assets/tamper-detection.svg" alt="Animation: one flipped bit in chunk 2 is caught, decryption stops, nothing is written" width="100%">
</p>

| Attack | What stops it |
|---|---|
| Flip a bit anywhere | The chunk's GCM authentication tag no longer matches |
| Swap, reorder or duplicate chunks | The chunk number in the AAD no longer matches |
| Truncate the file (even at a clean chunk boundary) | The new last chunk has no "final" flag |
| Append data | The old last chunk is no longer marked final |
| Move a chunk or a whole file to another ID | The file ID is part of the AAD |
| Move a wrapped key to another file | The file ID is part of the key wrap too |
| Put an old copy back after a revoke | It no longer matches the new key |

### Sharing with a reviewer

A reviewer gets exactly the files you choose, until the date you choose, and can check the
bundle really came from you.

```mermaid
sequenceDiagram
    autonumber
    actor R as Reviewer
    actor O as Owner

    R->>R: keygen (X25519 key pair)
    R-->>O: public key (.pub)
    R-->>O: fingerprint, read out by phone
    Note over O: compare fingerprints to catch a swapped key

    O->>O: unlock vault, unwrap each chosen file key
    O->>O: wrap each key to the reviewer<br/>(ephemeral X25519, HKDF, AES-GCM)
    O->>O: sign bundle with Ed25519 + expiry date
    O-->>R: bundle.json + the .enc files
    O-->>R: owner fingerprint, by phone

    R->>R: import-bundle: check signature,<br/>pinned owner, own key, expiry
    R->>R: open-shared: unwrap key, decrypt file
```

What the reviewer's software checks, in this order, *before* trusting anything in the bundle:

1. The Ed25519 signature is valid (so the bundle was not edited)
2. The signer matches the owner fingerprint the reviewer pinned (so it was not forged)
3. The bundle was made for the reviewer's own key
4. It has not expired

### Revocation

```mermaid
flowchart LR
    A["Decrypt with old key<br/>(integrity checked first)"] --> B["Generate new data key"]
    B --> C["Encrypt under new key"]
    C --> D{"Update database and<br/>swap file together"}
    D -->|success| E["key version + 1<br/>old bundles stop working"]
    D -->|failure| F["rolled back,<br/>nothing changed"]
```

A tampered file is *refused* rather than re-encrypted, so revocation can never launder damaged data into a "valid" file.

---

## Quick start

```bash
git clone https://github.com/maya573pasha/ChildVault.git
cd ChildVault
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Run everything as a module from the project root (`python -m childvault ...`, not `python childvault ...`).

```bash
# 1. Create a vault (you will be asked for a passphrase)
python -m childvault init

# 2. Give a child a pseudonym; use this ID instead of the name from now on
python -m childvault pseudonymize

# 3. Encrypt a file into the vault and attach it to that pseudonym
python -m childvault add-file recording.mp4 --type video --child CH-4F7A

# 4. Get it back (fails if the stored file was tampered with)
python -m childvault open-file F-0123456789abcdef --out copy.mp4

# 5. Or use the browser: http://127.0.0.1:8000
python -m childvault web
```

The vault lives in `./vault_data` by default. Set `CHILDVAULT_HOME` to put it somewhere else.

**Share a file with a reviewer**

```bash
# Reviewer: make a key pair and read the fingerprint to the owner by phone
python -m childvault keygen --out alice

# Owner: create a signed bundle that expires at the end of 2026-12-31
python -m childvault share F-0123456789abcdef --reviewer-key alice.pub \
       --expires 2026-12-31 --out bundle.json

# Reviewer: verify the bundle (pin the owner's fingerprint!) and open the file
python -m childvault import-bundle bundle.json --key alice.key --owner-fingerprint <fingerprint>
python -m childvault open-shared bundle.json F-0123456789abcdef F-0123456789abcdef.enc \
       --out reviewed.mp4 --key alice.key --owner-fingerprint <fingerprint>
```

**Pull access back**

```bash
python -m childvault revoke F-0123456789abcdef
```

---

## Command reference

| Command | Who | What it does | Status |
|---|---|---|---|
| `init` | owner | Create a new vault protected by a passphrase | ✅ |
| `status` | owner | Check the passphrase, show file and log counts | ✅ |
| `pseudonymize` | owner | Create a random pseudonym (`CH-XXXX`) for a child | ✅ |
| `lookup CH-XXXX` | owner | Show the real name behind a pseudonym | ✅ |
| `add-file` | owner | Encrypt a file (`--type video\|csv\|annotation\|other`, `--child`) | ✅ |
| `open-file` | owner | Decrypt a file, failing on any tampering | ✅ |
| `revoke` | owner | Re-encrypt a file under a new key | ✅ |
| `keygen` | reviewer | Create an X25519 key pair for receiving bundles | ✅ |
| `fingerprint` | anyone | Show a public key's fingerprint | ✅ |
| `share` | owner | Create a signed, expiring bundle for a reviewer | ✅ |
| `import-bundle` | reviewer | Verify a bundle (signature, signer, key, expiry) | ✅ |
| `open-shared` | reviewer | Decrypt one file from a verified bundle | ✅ |
| `web` | owner | Start the local web UI on `127.0.0.1` | ✅ |
| `verify` | owner | Walk the audit hash chain and report tampering | 🚧 in progress |
| `audit show` | owner | Show recent audit log entries | 🚧 in progress |

---

## Web UI

`python -m childvault web` starts a page on **`http://127.0.0.1:8000`**. It listens on this computer only, never on the network.

| Page | What it does |
|---|---|
| `/login` | Unlock the vault with the passphrase. The key stays in server memory, the browser only gets a random token |
| `/files` | List files, upload (encrypts on arrival), download (decrypts), revoke with a confirmation page |
| `/lookup` | Resolve a pseudonym to a name and list that child's files |

Built defensively:

- Session cookie is `HttpOnly` and `SameSite=Strict`; sessions expire after 15 idle minutes; five wrong passphrases lock the form for a minute
- Strict Content-Security-Policy with no scripts at all, plus `nosniff`, `no-referrer` and `no-store` on every response
- Everything shown on a page is HTML-escaped
- Uploaded file names are never stored or shown (they can contain a child's name), only a plain extension is kept
- Uploads are size-limited (500 MiB) before the body is read; downloads are sent as attachments
- Every state change is a `POST`; nothing changes on a `GET`

---

## Threat model and attack results

| Threat | Defence |
|---|---|
| Stolen laptop or disk | Everything on disk is ciphertext; the KEK exists only in memory after unlocking |
| Wrong passphrase | scrypt check value rejects it, with a brute-force slowdown from the scrypt cost |
| Child identity leaks from the database | Only pseudonyms are stored; names live in a separate encrypted file |
| Someone edits, reorders or truncates a stored file | Detected on open, no plaintext produced |
| Someone swaps keys or files between records | File ID is bound into every key wrap and every chunk |
| Forged or edited share bundle | Ed25519 signature plus a pinned owner fingerprint |
| Bundle used by the wrong person | Bundle names the reviewer's key; only that private key can unwrap |
| Bundle used after its expiry | Expiry is inside the signed payload and checked on import |

The attack suite ([tests/test_attack_files.py](tests/test_attack_files.py)) runs these as real attacks
against real vaults, through the crypto layer, the CLI, the web page, `revoke` and the reviewer's side.
It was also checked the other way round: deliberately weakening the encryption (dropping the final-chunk
flag, the chunk number, or the file ID) makes the matching tests fail.

**79 of 79 attack variants detected.** Full table: [docs/attack_results.md](docs/attack_results.md).
Regenerate it any time:

```bash
python scripts/attack_report.py --out docs/attack_results.md
```

---

## Testing

```bash
python -m pytest                      # everything (350+ tests)
python -m pytest tests/test_attack_files.py   # just the attack suite
```

Tests use synthetic data from [scripts/generate_synthetic.py](scripts/generate_synthetic.py)
(fake children, behaviour CSVs, ELAN-style annotations, chunk-boundary edge-case files).
Install `ffmpeg` to also generate small test videos; the one video test is skipped without it.

---

## Project structure

```text
ChildVault/
├── childvault/
│   ├── vault_crypto.py   key derivation, key wrapping, chunked AES-256-GCM
│   ├── ops.py            add / open / revoke, shared by CLI and web
│   ├── keyshare.py       X25519 key wrapping for reviewers
│   ├── bundle.py         Ed25519-signed, expiring share bundles
│   ├── identity.py       pseudonyms and the encrypted ID-to-name map
│   ├── db.py             SQLite schema: files, audit_log, meta
│   ├── config.py         where the vault lives on disk
│   ├── cli.py            Typer commands
│   └── web/              FastAPI app: login, files page, lookup page
├── tests/                unit tests and the attack suite (test_attack_*.py)
├── scripts/              synthetic data generator, attack-results table
├── demo/                 end-to-end demo script
└── docs/                 interface spec, attack results, README animations
```

---

## Project status

| Phase | Aaleen | Mariyam | Laiba |
|---|---|---|---|
| 1. Foundation | ✅ Key management | ✅ Repo, schema, CLI skeleton | ✅ Synthetic data, test setup, spec |
| 2. Core security | ✅ File encryption, `add-file`, `open-file` | ✅ Pseudonymization | 🚧 Audit log hash chain |
| 3. Access control | ✅ Signed bundles, revocation | ✅ Key wrapping, `share`, `import-bundle` | 🚧 Role checks, audit logging |
| 4. Web UI | ✅ Files page | ✅ Login, lookup | 🚧 Share page, audit viewer |
| 5. Attack suite | ✅ File integrity attacks | 🚧 Log attacks | 🚧 Formal bundle attacks (basics already tested) |
| 6. Evaluation | 🚧 Benchmark | 🚧 Demo recording, results table | 🚧 Report, slides |

✅ done · 🚧 in progress or not started

## Limitations

- **Expiry is enforced by honest client software.** A reviewer who modifies the program, or who copied the data key out earlier, is not stopped by software alone.
- **Revocation re-encrypts the vault's copy.** A reviewer who already saved the old encrypted file can still read that copy; nothing can take back data someone already holds.
- **No protection against malware running while the vault is unlocked**, or a user who reveals the passphrase.
- **Plaintext touches disk briefly** in temporary files during decrypt, upload and revoke. They are deleted, not securely wiped.
- **Single owner for now.** Researcher and reviewer roles are still being added.
- This is a course prototype, not a certified medical-data system.
