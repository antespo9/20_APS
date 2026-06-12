"""SHA-256 hashing helpers."""

from __future__ import annotations

import hashlib

from evoting.errors import CRYPTOGRAPHIC_ERROR_MESSAGE, CryptographicError


SHA256_DIGEST_SIZE = 32


def sha256_digest(data: bytes) -> bytes:
    """Return the SHA-256 digest of byte input."""

    if not isinstance(data, bytes):
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
    return hashlib.sha256(data).digest()


__all__ = ["SHA256_DIGEST_SIZE", "sha256_digest"]
