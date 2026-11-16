# Code review: Laiba's modules

Reviewer: Mariyam Pasha · Reviewed at commit `940dd9f` · 2026-11-16

**Scope:** `childvault/audit.py`, `access.py`, `users.py`, `web/guard.py`, `web/share.py`,
`web/auditlog.py`, Laiba's changes to `web/auth.py`, and `tests/attack/` (bundle attacks).
Full suite at this commit: **589 passed, 1 skipped**.

## Summary

The code is careful and well documented. Two findings are worth fixing before submission,
because the report currently claims more than the code does. The rest are small.

| # | Severity | Finding | Where |
|---|---|---|---|
| 1 | Medium | "On a tampered log the vault refuses to change anything" is only true when the **signed head** fails, not after a mid-log edit | `access.audited`, `web/auditlog.py:46`, `docs/report_audit_log.md:57` |
| 2 | Medium-low | If writing the success entry fails, an `open_file` happens with **no log entry at all**, and the plaintext is already on disk | `access.audited` (+ Aaleen's `open_file`) |
| 3 | Low | Failed logins are never in the audit log (inherent). Stated in the audit chapter, but not in the threat model | `docs/threat_model.md` |
| 4 | Low | Key-slot scrypt parameters are read from the DB without bounds | `users.authenticate` |
| 5 | Nit | One expiry test sleeps 7 s on the real clock | `tests/attack/test_attack_bundle_expiry.py` |

---

## 1. "Refuses to change anything" only covers head problems (Medium)

`access.audited(strict=True)` calls `audit.head_problem()`, which is the O(1) check of the
**signed head against the newest row**. It does not walk the chain. So after an attacker edits an
**older** entry, `verify` correctly reports tampering, but every normal command keeps working.

**Reproduced** (scratch test, real CLI and web):
1. Edit `actor` of entry #1 directly in SQLite (drop the trigger first).
2. `childvault verify` → `TAMPERING DETECTED` ✅
3. `add-file`, `revoke`, `pseudonymize` → all exit **0** (vault changed)
4. Web `/audit` shows "TAMPERING DETECTED … **The vault refuses to change anything**", yet
   `POST /files/<id>/revoke` returns **200**.

**Evidence is not lost**: the edited entry stays broken, so `verify` keeps finding it
(see `test_attack_middle_edit_survives_further_use` in `tests/test_attack_log.py`). The problem is
that the **claim in the report and the banner is wrong**.

**Fix (pick one):**
- **A. Make the code match the claim:** in strict mode, call `audit.verify_chain()` instead of
  `head_problem()`. That's O(n) per operation, but the log is small (thousands of rows take
  milliseconds). `append_event` can keep its O(1) head check.
- **B. Make the claim match the code:** change the wording in `report_audit_log.md:57` and the
  `/audit` banner to say the vault refuses to change anything when *the newest entries were removed
  or the signed head is broken*. A mid-log edit is detected by `verify` / `audit show` and stays
  detectable, but doesn't block normal use.

I'd suggest **A**, since it's a few lines and the report text then stays true.

## 2. An access can go completely unlogged (Medium-low)

`audited()` writes the success entry **after** the operation (`access.py:139-140`), outside the
`try/except` that writes `failed:<action>`. If that last `append_event` fails (for example
`database is locked`, which happens if the owner has the `.db` open in a SQLite browser), then:

**Reproduced** with `append_event` failing only for the `open_file` entry:
- `open-file` exits **1** (looks like a failure),
- but the **decrypted file exists** at `--out`,
- and the log contains **neither** `open_file` **nor** `failed:open_file`.

So plaintext was released with no trace. That's exactly what the log is meant to prevent.

**Fix ideas:**
- Log the **intent first** (`open_file` before decrypting), and add `failed:open_file` if the
  decrypt then fails. A crash can then only over-report, never under-report.
- Or (with Aaleen, since it's her `open_file`): decrypt to `<out>.part` and only rename it to `<out>`
  **after** the log entry is committed. If logging fails, delete the `.part`.

## 3. Failed logins leave no trace in the audit log (Low)

A wrong passphrase means there's no KEK, so no audit key, so nothing *can* be appended. That's
correct and unavoidable, and `report_audit_log.md` already lists it under Limitations (line 105).
*(Correction: an earlier version of this review said it was not stated anywhere.)* Only
`threat_model.md:45` lists just the scrypt cost and the web lockout, so a reader of the threat model
alone may assume guessing attempts are logged. **Suggest one line there:** *"Failed login attempts
are not recorded in the audit log, because without the passphrase there is no key to sign an entry;
only the web lockout slows online guessing."*

## 4. Unbounded scrypt parameters from the database (Low)

`users.authenticate` uses `rec["scrypt"]` straight from `vault_meta`. Someone with write access to
the DB could set e.g. `n = 2**30`, and every login attempt for that user would then try to allocate
huge memory (denial of service). Low severity, because that attacker could also just delete the
vault, but a bounds check (e.g. `2**10 <= n <= 2**20`, `r <= 16`, `p <= 4`) is cheap.
(Aaleen's vault header has the same pattern in `vault_crypto.unlock`.)

## 5. Real-time expiry test (Nit)

`test_bundle_expires_in_real_time` sleeps 7 s, about a third of the bundle-attack suite's time.
Keeping one real-clock test is reasonable; just noting that `verify_bundle(now=...)` already
exists if it ever needs to be faster.

---

## Things done well

- **Fail-closed permission table:** any action not listed is denied (`access.PERMISSIONS`).
- **One wrapper for check + operation + log** (`audited`), so nobody can forget to log, and
  denied/failed attempts are recorded with the exception **class only** (no paths or names).
- **Key slots bind the role into the AAD**, so editing `researcher` → `owner` in the DB breaks the slot.
- **No account for reviewers**, which keeps the reviewer role enforced by cryptography, not policy.
- **Equal-time failure** for unknown users (dummy scrypt) and one generic error message.
- **Share page:** two-step flow with fingerprint confirmation, and step 2 re-validates everything.
- **Audit viewer:** escapes every field, re-verifies on every load, and works on a damaged log.
- **Attack tests** include honest `test_limit_*` cases (expiry is not cryptographic, revoke can't
  un-read a saved copy, reviewer attempts are invisible to the owner).
- Changes to `web/auth.py` kept the existing session protections (fresh token, HttpOnly/SameSite cookie).
