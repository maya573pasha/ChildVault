"""
identity.py - pseudonymization (Mariyam, Phase 2).

Real child names are replaced by random IDs such as CH-4F7A. The ID-name
map is kept in a separate encrypted file (next step); this part only
creates and checks the IDs.

Design decisions:
  * IDs are RANDOM, never derived from the name (e.g. a hash of the name).
    A hash could be reversed by hashing a list of likely names and
    comparing - a dictionary attack that re-identifies children.
  * 4 hex characters = 65,536 possible IDs. By the birthday problem two
    random IDs collide with ~50% probability after only ~300 children, so
    we never rely on luck: every new ID is checked against the existing
    ones and redrawn if taken.
"""

import math
import re
import secrets
from collections.abc import Collection

PREFIX = "CH-"
ID_HEX_CHARS = 4
ID_SPACE = 16 ** ID_HEX_CHARS          # 65,536 possible IDs
MAX_ATTEMPTS = 1000                    # give up instead of looping forever

_ID_RE = re.compile(rf"^{PREFIX}[0-9A-F]{{{ID_HEX_CHARS}}}$")


class IdentityError(Exception):
    """Base class for pseudonymization errors."""


class InvalidChildIDError(IdentityError):
    """Text is not a well-formed child ID like CH-4F7A."""


class IDSpaceExhaustedError(IdentityError):
    """Could not find a free ID (the vault is close to 65,536 children)."""


def random_child_id() -> str:
    """One random ID from the OS's secure random generator, e.g. CH-4F7A."""
    n = secrets.randbelow(ID_SPACE)
    return f"{PREFIX}{n:0{ID_HEX_CHARS}X}"


def new_child_id(existing: Collection[str]) -> str:
    """A random ID that is not already in `existing` (redrawn on collision)."""
    for _ in range(MAX_ATTEMPTS):
        candidate = random_child_id()
        if candidate not in existing:
            return candidate
    raise IDSpaceExhaustedError(f"no free child ID after {MAX_ATTEMPTS} attempts")


def normalize_child_id(text: str) -> str:
    """Accept ' ch-4f7a ' style input; return 'CH-4F7A' or raise InvalidChildIDError."""
    cleaned = text.strip().upper()
    if not _ID_RE.match(cleaned):
        raise InvalidChildIDError(f"not a valid child ID: {text!r} (expected e.g. CH-4F7A)")
    return cleaned


def is_valid_child_id(text: str) -> bool:
    return bool(_ID_RE.match(text))


def collision_probability(n: int, space: int = ID_SPACE) -> float:
    """
    Birthday-problem estimate: chance that at least two of n random IDs
    are equal, if we did NOT check for duplicates. Used in the report.
        p ~= 1 - exp(-n(n-1) / 2N)
    """
    if n < 2:
        return 0.0
    return 1 - math.exp(-n * (n - 1) / (2 * space))
