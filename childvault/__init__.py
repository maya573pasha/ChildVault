"""
ChildVault - encrypted, tamper-evident storage for sensitive child-behaviour data.

Modules (one per security feature):
  vault_crypto   key management + file encryption        (Aaleen)
  db             SQLite schema for metadata + audit log  (Mariyam)
  cli            Typer command-line interface            (Mariyam)
  identity       pseudonymization (Phase 2)              (Mariyam)
  audit          hash-chained audit log (Phase 2)        (Laiba)
  sharing        reviewer share bundles (Phase 3)        (all)
"""

__version__ = "0.1.0"
