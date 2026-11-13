# ChildVault: Threat Model

CS3002 Information Security, Fall 2026 t

## 1. Purpose and scope

This section states what ChildVault protects, from whom, how, and what it deliberately does not protect against. Each defence is paired with the automated test that demonstrates it. ChildVault is a single-machine, offline prototype, and all testing uses synthetic data only.

## 2. Assets

| Asset | Why it matters | How it is held |
| --- | --- | --- |
| File contents (video, CSV, ELAN annotations) | Faces and clinical notes: a leak harms the child | Encrypted blobs, one random key per file |
| Child identities | Re-identification of a child | Names exist only in a separately encrypted map; everything else uses random pseudonyms such as CH-4F7A |
| Integrity of data and annotations | An undetected edit corrupts research results | AES-GCM authentication tags |
| Audit log | Evidence of who accessed what | Hash chain plus an HMAC-signed head |
| Keys | Everything else depends on them | Passphrase, scrypt, key-encryption key (KEK); per-file data keys and the owner's Ed25519 signing key are wrapped under the KEK |
| Share bundles | They grant time-limited access | Signed JSON file given to one reviewer |

## 3. Actors

| Actor | What they have | Trust level |
| --- | --- | --- |
| Owner | The vault passphrase | Full rights |
| Researcher | Own account and passphrase (a key slot that unlocks the same KEK) | Can list, add and open files and verify the log. Models the curious insider |
| Reviewer | No account and no vault passphrase: only their own X25519 key and a signed bundle | Least trusted. Limited by cryptography, not by software checks |
| Outsider | A stolen laptop, a copied folder or a leaked shared drive, but no passphrase | None |
| Tamperer | Write access to the vault files, wanting to change results or hide access | None |

## 4. Assumptions

- The machine is free of malware while the vault is unlocked, and the passphrase is strong and not revealed.
- The standard primitives are sound: AES-256-GCM, scrypt (n = 2^15, r = 8, p = 1), HKDF-SHA256, X25519, Ed25519, SHA-256 and HMAC-SHA256, all from the Python cryptography library.
- The program running is the honest, unmodified ChildVault (the limit already stated in the proposal; see section 7).
- The web interface listens only on 127.0.0.1.

## 5. Threats and defences

### 5.1 Data at rest: stolen laptop, leaked folder

| Threat | Defence | Evidence |
| --- | --- | --- |
| Read files from a stolen disk or copied folder | Random 256-bit key per file, AES-256-GCM in 1 MB chunks. Keys are wrapped under a scrypt-derived KEK, and no plaintext is stored | Web upload test: no plaintext anywhere in the vault folder |
| Learn who the children are from the database or file names | Pseudonyms only. Names live in a separately encrypted map. Original file names are never stored, only a plain letters-and-digits extension | Web file test (name dropped); audit tests (no real name in any log entry) |
| Guess the passphrase offline or online | Memory-hard scrypt. Wrong passphrase, unknown user and damaged key slot all give the same message. Web login locks for 60 s after 5 failures | Web auth lockout tests; user tests |

### 5.2 Data integrity

| Threat | Defence | Evidence |
| --- | --- | --- |
| Flip bits, swap, duplicate, remove or append chunks | Every chunk is authenticated with the header, file ID, chunk number and a final-chunk flag. A failure writes no output file | File-integrity attack tests (Aaleen, Phase 5) |
| Present another file's data or key under an allowed file ID | The file ID is bound into both key wrapping and every chunk | Attack test: another file's data under an allowed ID |

### 5.3 Audit log

| Threat | Defence | Evidence |
| --- | --- | --- |
| Edit an entry | Each entry hashes the previous one (SHA-256 chain) | tests/test\_audit.py |
| Delete a middle or first entry, or reorder entries | The chain breaks at that point and verify names the entry | tests/test\_audit.py |
| Delete the newest entries or wipe the log | An HMAC-signed head records the last entry. The key is derived from the passphrase | tests/test\_audit.py |
| Edit an entry and recompute every hash after it | The attacker cannot forge the head without the passphrase | tests/test\_audit.py |
| Delete the newest entries, then keep using the vault so the next write heals the evidence | Appending refuses on a log that fails its head check. The vault will not change anything, while verify and audit show still work | tests/test\_audit.py, tests/test\_roles\_cli.py |
| Crash between writing the entry and the head | Entry and head are written in one database transaction | tests/test\_audit.py |

The database also has triggers that reject UPDATE and DELETE on the log. They only stop mistakes and casual edits, because anyone holding the file can drop them. The hash chain and signed head are the real defence.

### 5.4 Access control

| Threat | Defence | Evidence |
| --- | --- | --- |
| A researcher reads real names, shares files, revokes or reads the log | One permission table (access.py) shared by the CLI and the web UI. Anything not listed is denied. Denied attempts are logged | tests/test\_access.py, test\_roles\_cli.py, test\_web\_roles.py |
| A researcher edits their role to owner in the database | The role is part of the authenticated data of their wrapped KEK, so any edit makes the key slot fail to open | tests/test\_users.py |
| A reviewer gets vault access | Reviewer accounts are refused by design, so a reviewer never receives the KEK | tests/test\_users.py |
| Find which accounts exist | Unknown user and wrong passphrase give the same message and take the same scrypt work | tests/test\_users.py |

### 5.5 Sharing with reviewers

| Threat | Defence | Evidence |
| --- | --- | --- |
| Edit a bundle (extend the expiry, add files, swap keys) | Ed25519 signature over a canonical, domain-separated payload. Checked before anything else is trusted | tests/attack: 9 edit variants plus garbage, truncated and missing files |
| Use an expired bundle | Expiry is checked after the signature, in both import-bundle and open-shared | tests/attack: past expiry and a real-clock expiry |
| Another reviewer uses or retargets a bundle | Each key is wrapped to one reviewer's X25519 key (ephemeral key agreement, HKDF over both public keys). The bundle names that reviewer's fingerprint | tests/attack: wrong reviewer |
| Reach files outside the bundle | One wrapped key per file. File IDs are checked against a strict pattern | tests/attack: outside the bundle |
| Forged bundle signed with the attacker's own key | The reviewer pins the owner's fingerprint, checked by phone or in person. Even if they do not, forged keys decrypt nothing real | tests/attack: forged bundle, pinned and unpinned |
| Man in the middle swaps the reviewer's public key | The owner confirms the key fingerprint before the bundle is created (two-step web page) | tests/test\_web\_share\_audit.py |
| Replay an old bundle after the owner revokes a file | Revoking re-encrypts the file under a new key, so the old key opens nothing | tests/attack: replay after revoke |

### 5.6 Web interface

| Threat | Defence | Evidence |
| --- | --- | --- |
| Cross-site scripting from names, IDs or error text | Every shown value is escaped. The content policy is default-src none, so no scripts run at all | Web tests with script-tag names, IDs and audit entries |
| Cross-site request forgery | Session cookie is HttpOnly and SameSite=Strict. State changes happen only through POST | Web auth tests |
| Session theft or fixation | Random 256-bit token. The KEK stays in server memory. A new token on every login. 15-minute idle timeout. Logout drops the KEK | Web auth tests |
| Path traversal and oversize uploads | File IDs must match a strict pattern. Upload size is checked before the body is read (500 MiB limit) | Web file tests |
| Leaking information | No-store caching, localhost only. Log entries hold IDs only, and failures record just the exception class, never its message | tests/test\_web\_roles.py |

## 6. Out of scope

As stated in the proposal: malware running while the vault is unlocked, a user who reveals the passphrase, hardware and physical attacks, cloud storage and multi-device sync, legal or regulatory certification, and face blurring or machine learning.

## 7. Known limitations

1. **Researcher separation is software policy.** A logged-in researcher holds the KEK, so a researcher who modified the program could read the identity map. Only the reviewer role is enforced by cryptography.
2. **Expiry is enforced by honest client software.** A reviewer with a patched client can still unwrap keys after the expiry. Revoking the file is the real remedy. A test demonstrates this limit.
3. **Revoking cannot unread a saved copy.** A reviewer who kept the old encrypted file can still open it. A test demonstrates this limit.
4. **Rollback is undetectable.** Restoring an old, self-consistent copy of the whole database cannot be noticed. Keeping a copy of the head hash off the machine would reveal it (future work).
5. **Some events cannot enter the owner's log.** Wrong-passphrase attempts (no key to sign with) and reviewer-side actions (they happen on the reviewer's own machine) are invisible to the owner's audit log.
6. **Decrypted temporary files are deleted, not securely wiped,** and the KEK stays in memory while the vault or a web session is unlocked.
7. **Removing a researcher does not rotate the KEK.** After a real compromise, revoke the files and start a new vault.
8. **Single user, single process.** Concurrent writers are not supported.
9. **A tampered log makes the vault refuse changes** until the owner investigates. This is a deliberate choice: integrity is preferred over availability.

## 8. Summary

The design aims to make attacks on confidentiality, integrity and accountability fail loudly instead of silently. The automated test suite (585 tests at the time of writing, including 35 attack tests that run through the real command line) checks each defence in section 5 and demonstrates the limits in section 7 rather than hiding them.
