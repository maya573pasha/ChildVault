# ChildVault: Roles and Access Control

Laiba Amjad (23L-0642) | CS3002 Information Security, Fall 2026 | Report chapter for Phase 3

## 1. Goal

The proposal defines three roles: owner, researcher and reviewer. Each must be able to do only what its job needs, the same rules must hold on the command line and in the web interface, and every attempt, allowed or refused, must leave a trace in the audit log. This chapter explains the design and, just as important, how strongly each role is actually enforced.

## 2. The three roles

| Role | Who | How they get access |
| --- | --- | --- |
| Owner | The person who created the vault | The vault passphrase |
| Researcher | A team member who works with files and pseudonyms but must not see real names | A personal account and passphrase created by the owner |
| Reviewer | An outside person who may open a few chosen files until a set date | No account. A signed share bundle and their own private key |

## 3. The permission table

One table (PERMISSIONS in access.py) decides who may do what. The command line and the web interface both read it, so the two cannot disagree. Anything not in the table is denied, and so is an unknown role.

| Action | Owner | Researcher | Reviewer |
| --- | --- | --- | --- |
| add a file, open a file, list files | yes | yes | no |
| verify the audit log | yes | yes | no |
| status | yes | yes | no |
| pseudonymize (needs the real name) | yes | no | no |
| look up a real name | yes | no | no |
| share, revoke | yes | no | no |
| show the audit log | yes | no | no |
| add, remove or list researcher accounts | yes | no | no |
| import a bundle, open a shared file | no | no | yes |

Researchers can do all their work with pseudonyms such as CH-4F7A, which is the point of the design: a researcher never needs to see a child's name.

## 4. How a researcher logs in: key slots

### 4.1 The problem

With one vault passphrase, everyone who knows it is the owner, so a researcher role could never be real. A role stored in the database is no better, because anyone with the file could edit it.

### 4.2 The solution

We borrowed the idea of key slots from disk encryption. Each researcher gets a personal passphrase. It is turned into a key with scrypt, and that key wraps the same key-encryption key (KEK) that the owner's passphrase produces:

| Step | Owner | Researcher |
| --- | --- | --- |
| Secret typed | Vault passphrase | Personal passphrase |
| Derived with | scrypt, using the vault header | scrypt, using that account's own salt |
| Result | The KEK | A slot key that unwraps the KEK from the account's record |

The account record is stored in the database and holds the role, a salt, the scrypt settings and the wrapped KEK. The role and the user name are bound into the wrapped key as authenticated data. Changing the role to owner in the database, or copying one researcher's record to another name, makes the slot fail to open. Both cases are covered by tests.

### 4.3 Rules around accounts

- Only the owner can add, remove or list accounts. Each of these is logged.
- User names are 3 to 32 lowercase letters, digits, dash or underscore, starting with a letter. The name owner is reserved. Passphrases need at least 8 characters.
- A wrong passphrase, an unknown user and a damaged slot all give the same message, and an unknown user costs the same scrypt time, so an attacker cannot learn which accounts exist.
- **Reviewer accounts are refused by design.** An account hands out the KEK, which would destroy the one role that is enforced by cryptography.

## 5. Putting the checks everywhere

### 5.1 Command line

A global option selects the account: childvault --user rana add-file clip.mp4. Without it the owner is assumed. After unlocking, every command runs inside the audited() wrapper described in the audit-log chapter, which checks the table, runs the operation and logs the result. A refused attempt prints the reason and exits with code 1.

Example of a refused attempt, and what the owner then sees:

- childvault --user rana lookup CH-4F7A is refused with a message that role 'researcher' may not lookup.
- childvault audit show then lists a denied:lookup entry by rana.

### 5.2 Web interface

The login form has an Account field that defaults to owner. The session stores the role and the account name. Each route declares the action it needs, and a refusal returns 403 and logs a denied entry. The navigation bar shows only the pages the role can use. Researchers see Files, and only the owner sees Lookup, Share and Audit log.

## 6. How strongly is each role enforced?

The three roles are not equally strong, and the report should say so plainly.

| Role | Enforced by | Strength |
| --- | --- | --- |
| Reviewer | Cryptography. They never hold the vault passphrase or the KEK, so there is nothing for a software check to guard | Strong |
| Researcher | Software policy in access.py. A logged-in researcher holds the KEK, so a researcher who modified the program could read the identity map | Honest-client assumption, as stated in the proposal |
| Owner | The vault passphrase | Only as strong as the passphrase |

The design still helps against the realistic case of a curious insider using the normal tools: the checks stop them, and every attempt is logged for the owner to see.

## 7. Evidence

| Tests | What they cover |
| --- | --- |
| tests/test\_access.py | The whole permission table, unknown roles and actions, and the logging behaviour |
| tests/test\_users.py | Key slots: logins, wrong passphrases, role editing, copying a slot, bad names, refusing reviewer accounts |
| tests/test\_roles\_cli.py | Researcher accounts and refusals on the command line, logged denials, no real name in the log |
| tests/test\_web\_roles.py | The same through the web interface, 403 pages and role-aware navigation |

## 8. Limitations

- Researcher separation is a software policy, as explained in section 6.
- Removing a researcher deletes their slot but does not change the KEK. After a real compromise the files should be revoked and a new vault created.
- The owner and researchers share the same KEK, so there is no per-user encryption of files.
- Wrong-passphrase attempts cannot be recorded in the audit log, because there is no key to sign with.

## 9. Summary

A single permission table, applied identically on the command line and in the web interface, controls three roles. Researchers get their own login through key slots, with the role bound into the key so that it cannot be edited. Reviewers get no account at all, which makes them the strongest-protected role. Every allowed, refused and failed attempt is recorded.
