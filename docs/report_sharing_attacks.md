# ChildVault: Sharing With Reviewers and the Attack Suite

CS3002 Information Security, Fall 2026 | Report chapter for Phases 4 and 5

## 1. Goal

The proposal asks for scoped, time-limited sharing: a reviewer opens only chosen files, and only until a set expiry, while an expired or altered bundle is refused. The cryptographic parts (key wrapping, signing) were built by teammates. My part was the owner's web page for creating bundles, the audit-log viewer, and the attack suite that tries to break the whole sharing path through the real command line. This chapter explains how sharing works end to end and what the attacks showed.

## 2. How sharing works

### 2.1 The pieces

| Piece | Mechanism |
| --- | --- |
| Reviewer key pair | The reviewer runs childvault keygen. It makes an X25519 key pair. The private key is saved encrypted under the reviewer's own passphrase, and the public key is a small file the reviewer sends to the owner |
| Key wrapping | For each chosen file the owner unwraps the file's data key with the KEK, then wraps it again for the reviewer: a fresh ephemeral X25519 key, key agreement, HKDF-SHA256 over both public keys, then AES-256-GCM with the file ID as authenticated data |
| Signed bundle | A JSON file holding the version, the owner's Ed25519 public key, the reviewer's key fingerprint, creation and expiry times, and one wrapped key per chosen file. The owner signs a canonical form of it with a domain-separation prefix |
| Owner signing key | One long-term Ed25519 key. Its seed is wrapped under the KEK in the database, so it can only be used while the vault is unlocked |
| Fingerprints | The first 16 hex characters of SHA-256 of a public key, written as four groups of four. Used for out-of-band checks by phone or in person |

The bundle holds only keys. The encrypted file itself is sent separately.

### 2.2 The reviewer's side

The reviewer needs no vault and no account:

- childvault import-bundle checks a bundle and lists what it grants.
- childvault open-shared checks the bundle, makes sure the file is in it, unwraps the key and decrypts the file to a new output path. It refuses to overwrite an existing file.

Before trusting anything in a bundle, the reviewer's side checks in this order: the structure, the Ed25519 signature, the pinned owner fingerprint (if given), that the bundle was made for this reviewer's key, and finally the expiry. Nothing in the payload is trusted until the signature has passed.

### 2.3 Revoking

revoke re-encrypts a file under a brand-new key and raises its key version. A bundle made earlier carries the old key, which no longer opens the vault's copy.

## 3. The web page for sharing (Phase 4)

The owner opens /share and goes through three steps:

1. Tick the files to share, paste the reviewer's public key and enter an expiry date.
2. A confirmation page shows the reviewer key's fingerprint. The owner compares it with the one the reviewer reads out, so a swapped key (a man in the middle) is noticed.
3. Only after the owner confirms is the bundle created and downloaded.

The final step re-checks everything and trusts nothing from the previous step. Private keys and keys of the wrong type are refused. The page shows the owner's own signing-key fingerprint to pass on to the reviewer. The audit log records the file IDs, the reviewer's fingerprint and the expiry, but never the key itself. Researchers and reviewers are refused, and the attempt is logged.

The audit-log viewer at /audit is described in the audit-log chapter.

## 4. The attack suite (Phase 5)

### 4.1 How it is built

The suite lives in tests/attack/ and drives the real command line exactly as a person would. A shared scenario builds a vault with two files, two reviewers (A and B) and a legitimate bundle that gives reviewer A file 1 only. Each attack is a pytest test carrying a marker with a plain-language description of the attack and of what must happen. A test passes when the system behaves as designed: the attack is refused, nothing is decrypted and no output file appears. Setting an environment variable makes the suite write a Markdown results table for the report, so the table comes from the run itself rather than from memory.

### 4.2 The four families

| Family | Tests | What the attacker tries | Required outcome |
| --- | --- | --- | --- |
| Tampered bundle | 13 | Nine edits to the signed content (extend the expiry, add a file, change a key version, put in their own fingerprint, swap the owner key, flip a signature byte, empty the signature, empty the file list, add an unexpected field), plus garbage, truncated and missing files, plus an untouched control bundle | Every edit is refused by both reviewer commands; the control works, so the refusals are not false alarms |
| Expired bundle | 4 | A validly signed bundle already past its expiry, a bundle that expires in real time during the test, and an owner asking for a past expiry | Refused after expiry; accepted before it |
| Wrong reviewer | 5 | Reviewer B imports or opens A's bundle, rewrites the fingerprint to their own, uses A's key file without the passphrase, or unwraps the keys directly | Refused every time; nothing decrypted |
| Outside the bundle | 13 | A file not in the bundle, another file's data under an allowed ID, five malformed or path-traversal file IDs, overwriting an existing output, a forged bundle signed with the attacker's own key (with and without the owner fingerprint pinned), an old bundle after a revoke, and two limits | Refused, or harmless, as described below |

In total there are 35 attacks, and all behave as designed.

### 4.3 Findings worth reporting

- **The owner cannot create an expired bundle**, because the share command refuses a past expiry. To test expiry fairly, the tests sign a bundle with the owner's real key and a past date, and also run a real-clock test where a bundle with a short expiry works and then stops working.
- **Pinning the owner's fingerprint matters.** If a reviewer does not pin it, a forged bundle signed by an attacker is accepted at import (with a visible warning). Even then it unlocks nothing, because its random keys cannot decrypt the real files. With the fingerprint pinned, the forgery is refused outright.
- **A revoked file really stops working** for an old bundle, because the key changed.

### 4.4 What the suite shows is not prevented

Three tests exist to document limits honestly. They appear as Not prevented in the results table:

| Limit | What the test shows |
| --- | --- |
| Expiry is enforced by honest client software | A reviewer with a patched client can still unwrap the keys of an expired bundle. Revoking the file is the real remedy |
| Revoking cannot unread a saved copy | A reviewer who kept the old encrypted file before the revoke can still open that copy |
| Reviewer actions are invisible to the owner | Rejected imports and opens leave no entry in the owner's log, because they happen on the reviewer's own machine |

## 5. Evidence

| Tests | What they cover |
| --- | --- |
| tests/test\_web\_share\_audit.py | The share page: validation, the confirmation step, a full run in which the reviewer opens the shared file, only chosen files in the bundle, no key in the log, tampering and expiry checks, tampered-log refusal, and the audit viewer |
| tests/attack/test\_attack\_bundle\_tamper.py | Tampered bundles |
| tests/attack/test\_attack\_bundle\_expiry.py | Expired bundles |
| tests/attack/test\_attack\_wrong\_reviewer.py | Wrong reviewer |
| tests/attack/test\_attack\_outside\_bundle.py | Access outside the bundle, forged bundles, revoke |
| tests/attack/attack\_support.py and conftest.py | The shared scenario and the results-table reporter |

The full table is in docs/attack\_results.md. Teammates can use the same marker for their own attacks, which then appear in the same table.

## 6. Limitations

- Expiry is checked by the client, not enforced by mathematics.
- A copy saved before a revoke stays readable.
- Reviewer actions cannot appear in the owner's audit log.
- The bundle protects the keys, not the delivery of the encrypted file, which is sent by a separate channel.
- Trust in the owner's fingerprint depends on the owner and reviewer actually comparing it out of band.

## 7. Summary

A reviewer can open exactly the files the owner chose, until the owner's expiry, using only a signed bundle and their own private key. Thirty-five attacks through the real command line, covering edited bundles, expired bundles, the wrong reviewer and access outside the bundle, were all refused or shown harmless. The three limits that cannot be prevented are tested and reported openly.
