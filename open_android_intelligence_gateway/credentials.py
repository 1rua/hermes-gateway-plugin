"""Account password credentials for the Hermes Gateway.

The password is the only secret a human enters, and contract section 5.2 keeps
it out of Android entirely: it is presented once over verified TLS and verified
by the Gateway. This module stores a stdlib-only scrypt digest so the plugin
keeps its empty dependency list, and it never stores or returns the password
itself.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

ALGORITHM = "scrypt"
# Interactive-login cost: ~16 MiB of memory, one pass, well under a second.
COST_N = 2 ** 14
BLOCK_R = 8
PARALLEL_P = 1
SALT_BYTES = 16
KEY_BYTES = 32
# scrypt hashes at most 1024 bytes of input (RFC 7914); longer input is a
# caller bug we refuse rather than silently truncate.
MAX_PASSWORD_BYTES = 1024


class CredentialFormatError(ValueError):
    """The stored credential is not in the one format this module writes."""


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _password_bytes(password: str) -> bytes:
    if not isinstance(password, str) or not password:
        raise ValueError("password must be a non-empty string")
    encoded = password.encode("utf-8")
    if len(encoded) > MAX_PASSWORD_BYTES:
        raise ValueError("password is too long")
    return encoded


def _derive(password: str, salt: bytes, cost: int, block: int, parallel: int) -> bytes:
    return hashlib.scrypt(
        _password_bytes(password),
        salt=salt,
        n=cost,
        r=block,
        p=parallel,
        dklen=KEY_BYTES,
        maxmem=132 * cost * block,
    )


def hash_password(
    password: str, *, cost: int = COST_N, block: int = BLOCK_R, parallel: int = PARALLEL_P,
) -> str:
    """Returns a self-describing digest: ``scrypt$n$r$p$salt$key``."""
    salt = secrets.token_bytes(SALT_BYTES)
    key = _derive(password, salt, cost, block, parallel)
    return "$".join((ALGORITHM, str(cost), str(block), str(parallel), _encode(salt), _encode(key)))


def verify_password(password: str, encoded: str) -> bool:
    """Constant-time verification of a stored digest.

    Any malformed stored value, any unknown algorithm and any non-string input
    is a failed verification rather than an exception: the caller is an
    authentication seam that must fail closed.
    """
    if not isinstance(encoded, str) or not encoded:
        return False
    parts = encoded.split("$")
    if len(parts) != 6 or parts[0] != ALGORITHM:
        return False
    try:
        cost = int(parts[1])
        block = int(parts[2])
        parallel = int(parts[3])
        salt = _decode(parts[4])
        expected = _decode(parts[5])
    except (ValueError, TypeError):
        return False
    if cost < 2 or block < 1 or parallel < 1 or not salt or len(expected) != KEY_BYTES:
        return False
    try:
        candidate = _derive(password, salt, cost, block, parallel)
    except (ValueError, TypeError, MemoryError):
        return False
    return hmac.compare_digest(candidate, expected)
