| # | Attack | Expected | Result |
|---|---|---|---|
| 1 | Expired bundle: validly signed, expiry already passed | Refused by import-bundle AND open-shared; nothing decrypted | PASS |
| 2 | Expired bundle: works now, then time runs out (real clock) | Accepted before expiry, refused after | PASS |
| 3 | Expired bundle: owner asks for an expiry in the past | Refused by share: expiry must be in the future | PASS |
| 4 | Expired bundle: dishonest client skips the expiry check | Not prevented (documented limit): expiry is enforced by honest client software; revoke is the remedy | PASS |
| 5 | Tampered bundle: edit the signed content  [extend the expiry date] | Refused by import-bundle AND open-shared; nothing decrypted | PASS |
| 6 | Tampered bundle: edit the signed content  [add a second file to the scope] | Refused by import-bundle AND open-shared; nothing decrypted | PASS |
| 7 | Tampered bundle: edit the signed content  [change a key version] | Refused by import-bundle AND open-shared; nothing decrypted | PASS |
| 8 | Tampered bundle: edit the signed content  [put own fingerprint as reviewer] | Refused by import-bundle AND open-shared; nothing decrypted | PASS |
| 9 | Tampered bundle: edit the signed content  [swap in the attacker's owner key] | Refused by import-bundle AND open-shared; nothing decrypted | PASS |
| 10 | Tampered bundle: edit the signed content  [flip one signature byte] | Refused by import-bundle AND open-shared; nothing decrypted | PASS |
| 11 | Tampered bundle: edit the signed content  [empty signature] | Refused by import-bundle AND open-shared; nothing decrypted | PASS |
| 12 | Tampered bundle: edit the signed content  [empty the file list] | Refused by import-bundle AND open-shared; nothing decrypted | PASS |
| 13 | Tampered bundle: edit the signed content  [add an unexpected field] | Refused by import-bundle AND open-shared; nothing decrypted | PASS |
| 14 | Tampered bundle: not even valid JSON | Refused: cannot read bundle | PASS |
| 15 | Tampered bundle: truncated file | Refused: cannot read bundle | PASS |
| 16 | Tampered bundle: file does not exist | Refused: cannot read bundle | PASS |
| 17 | Tampered bundle: control - the untouched bundle | Accepted (proves the refusals above are not false alarms) | PASS |
| 18 | Outside the bundle: ask for a file that is not in it | Refused: not in this bundle; nothing decrypted | PASS |
| 19 | Outside the bundle: use another file's encrypted data under the allowed ID | Refused: authentication failed; nothing decrypted | PASS |
| 20 | Outside the bundle: malformed or path-traversal file ID  [../../etc/passwd] | Refused: invalid file ID | PASS |
| 21 | Outside the bundle: malformed or path-traversal file ID  [F-123] | Refused: invalid file ID | PASS |
| 22 | Outside the bundle: malformed or path-traversal file ID  [f-0011223344556677] | Refused: invalid file ID | PASS |
| 23 | Outside the bundle: malformed or path-traversal file ID  [F-0011223344556677/../x] | Refused: invalid file ID | PASS |
| 24 | Outside the bundle: malformed or path-traversal file ID  [x] | Refused: invalid file ID | PASS |
| 25 | Outside the bundle: overwrite an existing file via --out | Refused: output already exists | PASS |
| 26 | Outside the bundle: forged bundle signed by the attacker (owner fingerprint pinned) | Refused: not the owner you trust | PASS |
| 27 | Outside the bundle: forged bundle, owner fingerprint NOT pinned | Import accepted with a warning, but nothing decrypts (keys are random) | PASS |
| 28 | Outside the bundle: replay an old bundle after the owner revokes the file | Refused: old key cannot open the re-encrypted file | PASS |
| 29 | Outside the bundle: reviewer kept a copy of the file before revoke | Not prevented (documented limit): an already-saved copy stays readable | PASS |
| 30 | Reviewer-side attempts: rejected imports and opens | Not logged (documented limit): they happen on the reviewer's machine, not in the owner's log | PASS |
| 31 | Wrong reviewer: B imports a bundle made for A | Refused: made for a different reviewer key | PASS |
| 32 | Wrong reviewer: B opens a file with A's bundle | Refused; nothing decrypted | PASS |
| 33 | Wrong reviewer: B rewrites the reviewer fingerprint to their own | Refused: signature invalid | PASS |
| 34 | Wrong reviewer: B uses A's key file without A's passphrase | Refused: cannot open private key | PASS |
| 35 | Wrong reviewer: B skips the checks and unwraps the keys directly | Fails: the keys are locked to A's key | PASS |

35 of 35 attacks behaved exactly as expected.
