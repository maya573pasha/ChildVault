# ChildVault: Foundation, Pseudonymization, Key Wrapping, Web Login and the Log Attack Suite

Mariyam Pasha (23L-0809) | CS3002 Information Security, Fall 2026 | Report chapter for my parts of Phases 1 to 6

> **DRAFT - rewrite in your own words before submitting.**

## 1. Goal

My parts of ChildVault answer four questions. Where does the vault keep its data, and what is it allowed to keep? How do we stop a child's name from appearing anywhere except one protected place? How does the owner give a reviewer the key to chosen files without giving them anything else? And how does the web interface stay unlocked between clicks without the key ever leaving the server? The last part of my work attacks the audit log as an intruder would, to prove that every way of hiding activity is caught.

## 2. Foundation: storage and command line (Phase 1)

### 2.1 What the database stores, and what it refuses to store

The vault is one folder: a SQLite database, an encrypted identity map, and a folder of encrypted files. The location comes from one place (the CHILDVAULT\_HOME setting, default vault\_data), so every test runs in its own temporary vault and never touches a real one. The folder is excluded from Git.

| Table | Purpose | Notable rules |
| --- | --- | --- |
| vault\_meta | Key/value settings: the vault header, signing key, signed log head, researcher key slots | The header can never be overwritten. A second init would replace the salt and make every file unrecoverable, so it is refused |
| files | One row per encrypted file | No child name and **no original filename** (a name like ali\_session3.mp4 identifies a child even when the file is encrypted). Only the pseudonym is stored. The wrapped key must be exactly 60 bytes and the type one of four values, enforced by the database itself. key\_version supports revocation |
| audit\_log | The hash-chained log | Append-only triggers. file\_id is deliberately not a foreign key, so failed attempts on unknown IDs are still logged |

A test fails if anyone adds a name or filename column to the files table. All values reach SQL through placeholders, never by building query text, which rules out SQL injection.

The append-only triggers stop mistakes, not attackers: anyone holding the file can drop them. A test demonstrates this on purpose, which is why the hash chain is the real protection (section 6).

### 2.2 The command line

The command-line interface (Typer) was built first with a fixed stub for every team member's command, so three people could fill in their commands without changing each other's arguments. Shared helpers give every command the same behaviour: passphrases are typed hidden, errors are printed the same way with exit code 1, and one unlock helper derives the key-encryption key for every command.

## 3. Pseudonymization (Phase 2)

### 3.1 Random IDs, not hashes

Each child gets an ID such as CH-4F7A. The obvious shortcut, taking part of a hash of the name, would be a serious flaw: an attacker with a list of likely names (a class register) hashes every name and compares the results with our IDs. This is a dictionary attack, and a hash hides nothing when the set of inputs is small. Our IDs come from the operating system's secure random generator and have no connection to the name. The function that makes an ID does not even take the name as input.

### 3.2 How long must an ID be?

Four hex characters give only 65,536 IDs. By the birthday problem, random IDs collide much sooner than intuition suggests, at roughly the square root of the number of possible IDs:

| ID length | Possible IDs | 100 children | 300 children | 1,000 children |
| --- | --- | --- | --- | --- |
| 4 hex (CH-4F7A) | 65,536 | 7.3% | 49.6% | 99.95% |
| 6 hex | 16.7 million | 0.03% | 0.27% | 2.9% |
| 8 hex | 4.3 billion | ~0% | ~0% | 0.01% |

We kept 4 hex characters because researchers read and type these IDs, but we never rely on luck: every new ID is checked against the existing ones and drawn again if it is taken. A test creates 2,000 children, far past the 50% point, with no duplicates. An ID is not a secret, since guessing CH-4F7A reveals nothing without the encrypted map, so it only has to be unique and meaningless.

### 3.3 The encrypted ID-to-name map

The only link between CH-4F7A and a name is the file identity\_map.enc, kept apart from the database so that a leaked database reveals no names.

| Design choice | Reason |
| --- | --- |
| AES-256-GCM under a **fresh random key and fresh nonce on every save** | The map is rewritten every time a child is added. Reusing a key and nonce in GCM leaks the XOR of the two plaintexts and lets an attacker forge messages. A new key per save makes nonce reuse impossible |
| The map key is wrapped under the key-encryption key with the purpose label identity-map | A wrapped key copied from a file record cannot be used to open the map |
| The file header is authenticated data | Any change to the format marker or wrapped key is detected |
| Written to a temporary file, then renamed in one step | A crash mid-write leaves the old map intact. Losing the map would lose every child's identity |
| A missing map is an error, never "start empty" | Otherwise deleting the map would make the vault silently start over and overwrite the evidence. init creates the empty map before the vault header, so a vault never exists without one |
| The name is asked at a prompt, not given on the command line | Command lines are saved in shell history on a laptop the threat model says may be stolen |

Every flipped bit, truncation, wrong key and swapped header is reported as the same integrity error. The JSON inside is parsed only after authentication succeeds.

## 4. Key wrapping for reviewers (Phase 3)

The owner shares chosen files with an external reviewer. Each file already has its own random data key; the task is to lock those keys so that only that reviewer can open them.

1. The reviewer runs keygen and gets an X25519 key pair. The private key file is encrypted with the reviewer's own passphrase. keygen refuses to overwrite an existing key, because a lost private key would make every bundle for that reviewer unreadable.
2. For each file, the owner makes a throw-away X25519 key pair, computes a shared secret with the reviewer's public key, turns it into an AES key with HKDF-SHA256 (both public keys are bound in), and encrypts the data key with AES-256-GCM, with the file ID as authenticated data. The result is 92 bytes per file.
3. Only the listed files are wrapped, which is what makes sharing scoped. Each entry also records the file's key version, so it is clear which key a bundle was made for. After a revocation the old wrapped key simply no longer decrypts the re-encrypted file.

Two points matter for security:

- **X25519 gives secrecy, not proof of origin.** Anyone can encrypt to a public key, so a forged bundle would look just as valid. Aaleen's Ed25519 signature on the bundle provides the missing proof, and the reviewer verifies it before any key is unwrapped. The two parts form one protocol.
- **A swapped public key would send the keys to the wrong person.** Both sides therefore compare a short fingerprint (for example 8bfe:8420:aaf5:0f2b) by phone or in person. The fingerprint command shows it.

The code also rejects an all-zero public key (a low-order point that makes the shared secret predictable) and refuses an Ed25519 signing key offered in place of an X25519 encryption key.

## 5. Web login and the lookup page (Phase 4)

### 5.1 Keeping the vault unlocked without leaking the key

The command line forgets the key-encryption key after every command. A web page cannot, or the user would type the passphrase on every click. So after one login the key is kept **in server memory only**, and the browser receives a random 256-bit token in a cookie.

| Protection | What it prevents |
| --- | --- |
| Passphrase sent only in a POST body | Passphrases in URLs, browser history and logs |
| Cookie holds only a random token, HttpOnly, SameSite=Strict | Scripts reading the session; other websites using it (cross-site request forgery) |
| New token at every login, old session deleted | Session fixation |
| 15 minutes idle ends the session and drops the key | An unlocked laptop left alone |
| 5 wrong passphrases lock the form for 60 seconds | Online guessing |
| The key is hidden from the session's printed form | The key appearing in a debug message or log |
| Logout is a POST button | A link or image on another page logging the user out |
| Server listens on 127.0.0.1 only | Other computers on the network reaching the vault |

Every page gets the same security headers from one place: a content security policy that runs no scripts at all, framing forbidden (clickjacking), no caching (pages with names are never stored in the browser cache), no referrer, and no server version. FastAPI's automatic endpoint list is switched off. Every value from a user, file or the vault is HTML-escaped, which stops cross-site scripting. Laiba later extended the login with researcher accounts without weakening any of these.

### 5.2 The lookup page

The owner types a pseudonym and sees the real name and that child's files. It uses POST, so the ID being looked up never enters the URL or history. It is owner-only: a test confirms a researcher session gets a 403 and no name. A child whose stored "name" is a script tag is shown as harmless text, and so is malicious input echoed back in an error message.

## 6. Attack suite: the audit log (Phase 5)

Laiba built the hash chain and signed head. My task was to attack them end-to-end. The attacker has the vault folder but not the passphrase: they open the database with an ordinary SQLite tool, drop the append-only triggers, and edit the log. The log under attack is written by real commands (pseudonymize, add-file, open-file, lookup, status), and detection is checked through the real verify command, including the reason and the entry it names.

The strongest move without the passphrase is to edit the log and then **recompute every hash** so the chain is perfect again. SHA-256 is public, so this is easy. Only the HMAC on the signed head, keyed from the passphrase, is out of reach, and many attacks exist to prove that it is what stops a rebuilt chain.

| Group | Examples | Caught by |
| --- | --- | --- |
| Edited | Change actor, action, time, file ID or which child was looked up; edit and fix that entry's own hash | Entry hash mismatch, or the next entry no longer links |
| Deleted | Middle entry, first entry, renumbering to hide the gap | Chain broken |
| Deleted from the end | Last 1, 2 or 5 entries, the whole log, entries plus the head | Signed head |
| Reordered | Swap two entries, swap sequence numbers, reverse the log, move the last entry first | Chain broken or out of order |
| Rebuilt | Any of the above followed by recomputing every hash | Signed head |
| Inserted | Fake entry in the middle; perfectly chained fake entry at the end | Chain broken; signed head |
| After the attack | Delete the tail and keep working; edit an old entry and keep working | Commands refuse; verify still finds the edit |

**Result: 28 attack types, 48 variants, all detected,** plus a control showing that an untouched log passes.

**Proving the tests mean something.** I re-ran the suite with the signed-head check switched off. Seventeen variants then got through (every rebuilt chain, every deletion from the end, the forged appended entry and the attacks on the head itself), and the other thirty-one were still caught by the chain alone. Each test therefore fails for the reason its description gives, and the signed head is necessary.

The combined results table for the whole team (Aaleen's script) now reports 158 of 158 attack variants detected, 48 of them from this suite.

## 7. The demo (Phase 6)

demo/demo.py runs the real command line in a throw-away vault and checks every result, so it doubles as the backup if something fails live. It walks through 16 sections with 44 checks, including nine live attacks: a flipped bit in an encrypted file and in the map, a deleted map, a file outside the bundle, an edited bundle expiry, a different reviewer, an old bundle after revocation, an edited log entry and a deleted log tail. Passphrases, the reviewer's key passphrase and children's names are masked on screen because the demo is projected and recorded. A test runs the whole demo and checks that all checks pass, no secret is printed and the temporary vault is deleted.

## 8. Problems we found in our own work

| Problem | Found by | Fix |
| --- | --- | --- |
| The child's name was a command-line argument, so it was saved in shell history | Reviewing the threat model | Asked at a prompt instead |
| Opening a database at a mistyped path silently created an empty one | Reading the SQLite behaviour | Check that the file exists before connecting |
| The web app replaced a session store it was given, because an empty store counts as false in Python | The idle-timeout test failing | Test explicitly for "not given" |
| An invalid file type crashed with a full traceback | Running the real command | Fixed list of allowed values with a clean error |
| A test claimed to prove IDs are not derived from names but could never fail | Re-reading the test | Removed; the guarantee comes from the function having no name input |
| The server announced its software in every response | Inspecting the real headers | Header switched off |

## 9. Evidence

| Tests | What they cover |
| --- | --- |
| tests/test\_config.py, tests/test\_db.py (25) | Vault location, schema rules, header cannot be overwritten, no name columns, append-only triggers and their limit |
| tests/test\_identity.py (37) | ID format and uniqueness past the birthday bound, the map: round trip, fresh key and nonce, every flipped bit and truncation, purpose binding, atomic save, missing map |
| tests/test\_keyshare.py (34) | Wrap and unwrap, wrong reviewer, file-ID binding, every flipped bit, zero key, key files and fingerprints, scoped batches |
| tests/test\_web\_app.py, tests/test\_web\_auth.py, tests/test\_web\_lookup.py (38) | Security headers, escaping, sessions, cookie flags, timeout, lockout, lookup permissions and escaping |
| tests/test\_cli.py (my commands) | init, status, pseudonymize, lookup, keygen, fingerprint, web |
| tests/test\_attack\_log.py (49) | The log attack suite of section 6 |
| tests/test\_demo.py | The complete demo |

## 10. Limitations

- Passphrases can be given on the command line for scripts and tests; typed that way they can end up in shell history. Interactive use prompts instead.
- An attacker who restores an older, genuine copy of the identity map makes the newest children disappear without any error. Detecting this would need a version counter stored somewhere the attacker cannot edit.
- Python cannot reliably wipe a key from memory, so the key-encryption key stays in RAM until it is freed. This falls under the existing "malware while unlocked" exclusion.
- The web session cookie is not marked Secure because the interface runs over plain HTTP on 127.0.0.1. The traffic never leaves the laptop.
- The login lockout is shared by all accounts, so a researcher's wrong attempts also lock out the owner for a minute.
- Fingerprint comparison is a human step. If both people skip it, a swapped public key goes unnoticed.
- Four-character IDs allow at most 65,536 children per vault; the length is one setting if more are needed.

## 11. Cross-review

I reviewed Laiba's audit, access-control, account and web modules (docs/reviews/review\_of\_laiba.md). The two main findings, both reproduced: the vault keeps accepting changes after an older log entry is edited, although the report says it refuses (the tampering is still detected by verify); and if writing a log entry fails after a file is opened, the file is released with no log record.

## 12. Summary

My parts give ChildVault its storage rules, its identity protection, its reviewer key wrapping and its web sessions. The database never holds a name or filename; names live only in a separately encrypted map that is re-keyed on every save and fails loudly if deleted or altered. Reviewer keys are locked with X25519 so only the chosen reviewer can open the chosen files, while Aaleen's signature proves who made the bundle. The web interface keeps the key on the server and hands the browser only a random token. Finally, 48 attack variants on the audit log, and a run with one defence switched off, show that every way of hiding activity is detected and that each layer is needed.
