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

**79 of 79 attack variants detected** (32 attack types).

Controls (no attack, must succeed): test_control_untouched_files_decrypt 1/1
