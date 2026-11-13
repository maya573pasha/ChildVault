# Attack results

| # | Attack | How it is detected | Variants | Result |
|---|---|---|---|---|
| 1 | Flip one bit of the encrypted file (header, nonce, data or tag) | AES-GCM tag / header check fails. | 28/28 | Detected |
| 2 | Flip a bit in the middle of each of the 4 chunks in turn | that chunk's GCM tag fails. | 1/1 | Detected |
| 3 | Swap two chunks of a 4-chunk file | chunk number in the AAD no longer matches. | 1/1 | Detected |
| 4 | Reverse the chunk order | chunk number in the AAD no longer matches. | 1/1 | Detected |
| 5 | Overwrite chunk 2 with a copy of chunk 1 | chunk number in the AAD no longer matches. | 1/1 | Detected |
| 6 | Splice in a chunk from a different file under the same key | file ID in the AAD differs. | 1/1 | Detected |
| 7 | Cut off the last (partial) chunk | the new last chunk lacks the 'final' flag in its AAD. | 1/1 | Detected |
| 8 | Cut a file at an exact chunk boundary, looking like a clean end | missing 'final' flag. | 1/1 | Detected |
| 9 | Cut the file in the middle of a chunk | the partial chunk fails authentication. | 1/1 | Detected |
| 10 | Truncate to the header only, or to zero bytes | 'no chunks' / 'too short' is reported. | 1/1 | Detected |
| 11 | Cut the only chunk of an empty file's encryption | detected, an empty file is not 'nothing'. | 1/1 | Detected |
| 12 | Append random bytes to the end of the file | the old last chunk is no longer 'final'. | 4/4 | Detected |
| 13 | Append a valid copy of the last chunk | the original last chunk loses its 'final' flag. | 1/1 | Detected |
| 14 | Present a file under another file's ID | the file ID is bound into every chunk's AAD. | 1/1 | Detected |
| 15 | Swap the encrypted file for random bytes | magic / header check or first tag fails. | 1/1 | Detected |
| 16 | Tamper with the last chunk while an old output file exists | old file untouched, no partial plaintext. | 1/1 | Detected |
| 17 | Decrypt with a different data key | first chunk's GCM tag fails. | 1/1 | Detected |
| 18 | Flip a bit of a wrapped data key | unwrapping under the KEK fails authentication. | 6/6 | Detected |
| 19 | Copy file A's wrapped key next to file B | the file ID is bound into the key wrap. | 1/1 | Detected |
| 20 | Shorten or lengthen a wrapped key | the length check rejects it before any decryption. | 1/1 | Detected |
| 21 | Unwrap with a key from the wrong passphrase | GCM authentication fails. | 1/1 | Detected |
| 22 | Wrong passphrase, or edit the vault header | the check value fails, reported as wrong passphrase. | 1/1 | Detected |
| 23 | Tamper with a stored file, then open-file | CLI exits 1 with an integrity error, writes nothing. | 3/3 | Detected |
| 24 | Tamper with a stored file, then download it on the Files page | HTTP 500 page, no bytes of the file sent. | 3/3 | Detected |
| 25 | Tamper with a stored file, then revoke it | refused; the file and its key version stay unchanged. | 3/3 | Detected |
| 26 | Valid bundle but the encrypted file was tampered with in transit | reviewer's open-shared fails, writes nothing. | 3/3 | Detected |
| 27 | Swap the wrapped keys of two files in the database | each file ID is bound into its key wrap. | 1/1 | Detected |
| 28 | Swap two stored .enc files so each sits under the other's ID | file ID in the AAD no longer matches. | 1/1 | Detected |
| 29 | Put the pre-revoke encrypted file back after a revoke | it no longer matches the new data key. | 1/1 | Detected |
| 30 | Delete a stored .enc file | open-file reports the data as missing instead of failing silently. | 1/1 | Detected |
| 31 | Pass a crafted file ID with ../ or odd characters | the strict ID format check rejects it first. | 5/5 | Detected |
| 32 | Search every file in the vault folder for the plaintext | it is never present (only ciphertext). | 1/1 | Detected |
| 33 | Change who did an action (actor) in any entry | that entry's SHA-256 no longer matches. | 6/6 | Detected |
| 34 | Disguise the file opening (open_file) as a harmless action | entry hash mismatch. | 3/3 | Detected |
| 35 | Move the time of the file opening by one second | entry hash mismatch. | 1/1 | Detected |
| 36 | Point the open_file entry at a different file | entry hash mismatch. | 1/1 | Detected |
| 37 | Change which child was looked up (details) | entry hash mismatch. | 1/1 | Detected |
| 38 | Edit an entry AND recompute its own hash | the next entry's prev_hash no longer links to it. | 1/1 | Detected |
| 39 | Edit any entry and recompute every hash after it | the HMAC-signed head no longer matches. | 6/6 | Detected |
| 40 | Rewrite one entry's prev_hash link | chain broken at that entry. | 1/1 | Detected |
| 41 | Delete one entry from the middle of the log | the following entry's prev_hash points at nothing. | 4/4 | Detected |
| 42 | Delete the very first entry | entry 2 no longer links to the genesis hash. | 1/1 | Detected |
| 43 | Delete the newest k entries (the chain that is left is perfect) | signed head records more entries. | 3/3 | Detected |
| 44 | Delete every entry | signed head says the log had entries (log was wiped). | 1/1 | Detected |
| 45 | Delete the last entries AND the signed head record | signed head is missing. | 1/1 | Detected |
| 46 | Delete entry 3 and renumber the rest so seq has no gap | chain still broken where 3 was. | 1/1 | Detected |
| 47 | Delete the file-opening entry and recompute all hashes | signed head no longer matches. | 1/1 | Detected |
| 48 | Swap the contents of two entries (seq numbers stay) | chain broken at the earlier one. | 4/4 | Detected |
| 49 | Swap the seq numbers of entries 3 and 4 so they are read in the wrong order | chain broken. | 1/1 | Detected |
| 50 | Move the newest entry to the start of the log | sequence numbers are out of order. | 1/1 | Detected |
| 51 | Reverse the order of every entry | chain broken at the first entry. | 1/1 | Detected |
| 52 | Reorder entries and recompute all hashes so the chain is valid | signed head no longer matches. | 1/1 | Detected |
| 53 | Insert a fake entry between two real ones | the real entry after it no longer links. | 1/1 | Detected |
| 54 | Append a perfectly chained fake entry at the end | signed head does not cover it. | 1/1 | Detected |
| 55 | Rewrite the head to match a truncated log, with a made-up HMAC | head signature invalid. | 1/1 | Detected |
| 56 | Replace the signed head with garbage | head is malformed. | 1/1 | Detected |
| 57 | Delete the last entries, then keep using the vault | commands refuse, evidence is not overwritten. | 1/1 | Detected |
| 58 | Edit an old entry, then the owner keeps working normally | verify still finds the edit. | 1/1 | Detected |
| 59 | Delete an entry and look at `audit show` instead of verify | audit show prints a warning. | 1/1 | Detected |
| 60 | Try to verify (or re-sign the head) with a guessed passphrase | refused before reading the log. | 1/1 | Detected |

**127 of 127 attack variants detected** (60 attack types).

Controls (no attack, must succeed): test_control_untouched_files_decrypt 1/1, test_control_untouched_log_verifies 1/1
