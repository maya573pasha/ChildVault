# ChildVault: Tamper-Evident Audit Log

&#32;CS3002 Information Security, Fall 2026 | Report chapter for Phases 2 and 3

## 1. Goal

A research team handling sensitive child data must be able to show an auditor who accessed which file, and that nobody changed the record afterwards. The proposal set one requirement: detect any edited, deleted or reordered log entry. This chapter describes how ChildVault meets it, the flaw we found in our own first design, and what the log cannot do.

## 2. What is recorded

Every action in the vault, from the command line and from the web interface, becomes one row in the audit\_log table.

| Field | Content |
| --- | --- |
| seq | Increasing sequence number |
| ts | UTC time |
| actor | Account name (owner, or a researcher's user name) |
| action | add\_file, open\_file, pseudonymize, lookup, share, revoke, verify, audit\_show, status, login, add\_user, remove\_user, list\_users |
| file\_id | Random file ID, or empty |
| details | Small JSON object holding IDs only |
| prev\_hash, entry\_hash | The two 64-character SHA-256 values that link the chain |

Refused and failed attempts are logged too, as denied:lookup or failed:open\_file for example. A failed entry stores only the exception class name, never the message. The log is kept in the unencrypted database, so a strict rule applies: real names, passphrases, paths and typed input never enter it. A test checks that a real name typed into a form field never reaches the log.

## 3. Design

### 3.1 Hash chain

Each entry stores the hash of the entry before it. The hash covers the time, actor, action, file ID, details and the previous hash, encoded as a JSON list so that one field's text can never slide into the next. The first entry links to 64 zeros.

| Entry | prev\_hash | entry\_hash |
| --- | --- | --- |
| 1 | 000...0 | H1 = SHA-256(entry 1 fields, 000...0) |
| 2 | H1 | H2 = SHA-256(entry 2 fields, H1) |
| 3 | H2 | H3 = SHA-256(entry 3 fields, H2) |

Editing entry 2 changes H2, so entry 3 no longer points to it. Deleting or reordering entries breaks a link in the same way. Verification walks the chain from the start and reports the first entry where it breaks.

### 3.2 Why a chain alone is not enough

Anyone can compute SHA-256, so a plain chain has two blind spots:

1. An attacker can delete the newest entries. What remains is still a valid chain.
2. An attacker can edit an entry and recompute every hash after it. The result is again a valid chain.

### 3.3 The signed head

After every append, ChildVault stores a head record: the newest sequence number, the newest hash, and an HMAC-SHA256 of the two. The HMAC key is derived from the vault passphrase (passphrase, scrypt, key-encryption key, then HKDF-SHA256 with a purpose label, so the key-encryption key itself is never used for two jobs). Without the passphrase an attacker cannot produce a valid head for a doctored log. This closes both blind spots: deleted tail entries no longer match the head, and a rebuilt chain does not match it either.

### 3.4 A flaw we found in our own design, and the fix

Our first version re-signed the head on every append. Consider this sequence: an attacker deletes the last two entries, then the owner does something ordinary such as opening a file. The new entry chains onto the shortened log and the head is re-signed over it. The evidence of the deletion is gone, and verification passes. The log could be healed by the very next normal action.

The fix has two parts:

- Appending now checks the head first. If the head does not match the log, the append is refused (AuditTamperedError).
- Every vault operation checks the log before it runs. On a tampered log the vault refuses to change anything. The read-only commands verify, audit show and status keep working, so the owner can investigate, and they still report the damage.

A related change made the entry and the head commit in one database transaction. A crash can no longer leave them out of step, which would otherwise have locked the vault after a power failure.

### 3.5 One place that logs everything

A single wrapper, audited(), surrounds each operation. It checks the permission table, runs the operation, and writes the entry: the action name on success, denied:action when the role is not allowed, failed:action when the operation raises an error. Because the command line and the web interface both use it, neither can forget to log or disagree about who may do what.

### 3.6 Reading the log

- childvault verify re-checks the whole log. It prints Audit log OK with the entry count, or AUDIT LOG TAMPERING DETECTED with the reason and the first bad entry, and exits with code 1.
- childvault audit show lists the newest entries and shows a warning above the table if verification fails.
- The web page /audit (owner only) does the same with a green or red banner and shows denied and failed rows in red. Every value is HTML-escaped. Viewing the log is itself logged.

## 4. What each attack looks like

| Attack | What verification reports |
| --- | --- |
| Edit an entry | The entry was modified; its hash does not match, with its number |
| Edit the details field | The same |
| Delete a middle entry | Chain broken at the next entry |
| Delete the first entry | Chain broken at the new first entry |
| Reorder two entries | Out of order, or chain broken |
| Delete the newest entries | Entries after the last remaining one were deleted |
| Wipe the whole log | Log is empty but the head says it had entries |
| Edit an entry and rebuild every hash | The log does not match its signed head |
| Forge or alter the head | Invalid signature |
| Remove the head | Signed head is missing |
| Verify with a wrong passphrase | Invalid signature |
| Append a forged row, then use the vault | The next append is refused, and verification fails |
| Delete the tail, then keep using the vault | The append is refused and the evidence survives |

The database also carries triggers that reject UPDATE and DELETE on the log. They only stop accidents and casual edits through the application, because anyone holding the file can drop them. The attack tests therefore drop them first, as a real attacker would, and show that the chain and the signed head still catch everything.

## 5. Evidence

| Tests | What they cover |
| --- | --- |
| tests/test\_audit.py | Chain, signed head, every attack in section 4, atomic append, refusing to append to a bad log |
| tests/test\_audit\_cli.py | verify and audit show on the command line |
| tests/test\_access.py | audited(): success, denied, failed, strict and non-strict modes |
| tests/test\_roles\_cli.py | Denied attempts logged, names never logged, refusing to run on a tampered log |
| tests/test\_web\_roles.py, tests/test\_web\_share\_audit.py | The same through the web interface, and the audit viewer page |

## 6. Limitations

- Someone who knows the passphrase can forge a valid log. This is outside the threat model.
- Restoring an old, self-consistent copy of the whole database cannot be detected. Only a copy of the head hash stored elsewhere would reveal it.
- Wrong-passphrase attempts cannot be logged, because there is no key to sign with.
- Actions by reviewers happen on their own machine and never reach the owner's log. The owner sees only that a bundle was created.
- Two processes writing at the same moment are not supported. ChildVault is a single-user tool.

## 7. Summary

The audit log combines a SHA-256 hash chain, which exposes edits, deletions and reordering, with an HMAC-signed head, which exposes truncation and rebuilt chains. Testing our own design found that re-signing on every append could erase evidence. Refusing to append to a log that fails its head check fixed that, and the same tests now guard against it coming back.
