"""Educational Shamir Secret Sharing over a prime field.

This module implements the standard Shamir construction for the local WP4
prototype. It is intentionally small and documented for educational use only;
it is not production-ready cryptographic software.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
import secrets

from evoting.errors import CRYPTOGRAPHIC_ERROR_MESSAGE, CryptographicError


FIELD_PRIME = 2**521 - 1
WRAPPING_KEY_SIZE = 32


@dataclass(frozen=True, slots=True)
class ShamirShare:
    """A typed Shamir share represented by the field elements ``(x, y)``."""

    x: int
    y: int

    def __post_init__(self) -> None:
        _require_field_index(self.x)
        _require_field_element(self.y)


def split_secret(secret: bytes, threshold: int, share_count: int) -> tuple[ShamirShare, ...]:
    """Split a 32-byte secret into ``share_count`` shares with threshold ``threshold``."""

    _require_wrapping_key(secret)
    _require_threshold(threshold, share_count)
    if share_count >= FIELD_PRIME:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)

    secret_int = int.from_bytes(secret, "big", signed=False)
    coefficients = [secret_int]
    if threshold > 2:
        coefficients.extend(secrets.randbelow(FIELD_PRIME) for _ in range(threshold - 2))
    coefficients.append(_random_non_zero_field_element())

    return tuple(
        ShamirShare(x=x, y=_evaluate_polynomial(coefficients, x))
        for x in range(1, share_count + 1)
    )


def reconstruct_secret(shares: Sequence[ShamirShare], threshold: int) -> bytes:
    """Reconstruct the original 32-byte secret from at least ``threshold`` valid shares."""

    _require_reconstruction_input(shares, threshold)
    selected = tuple(shares[:threshold])
    secret_int = 0

    for index, current in enumerate(selected):
        numerator = 1
        denominator = 1
        for other_index, other in enumerate(selected):
            if index == other_index:
                continue
            numerator = (numerator * (-other.x)) % FIELD_PRIME
            denominator = (denominator * (current.x - other.x)) % FIELD_PRIME
        lagrange_basis = numerator * pow(denominator, -1, FIELD_PRIME)
        secret_int = (secret_int + current.y * lagrange_basis) % FIELD_PRIME

    if secret_int >= 2 ** (8 * WRAPPING_KEY_SIZE):
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
    return secret_int.to_bytes(WRAPPING_KEY_SIZE, "big")


def _evaluate_polynomial(coefficients: Sequence[int], x: int) -> int:
    value = 0
    for coefficient in reversed(coefficients):
        value = (value * x + coefficient) % FIELD_PRIME
    return value


def _random_non_zero_field_element() -> int:
    value = 0
    while value == 0:
        value = secrets.randbelow(FIELD_PRIME)
    return value


def _require_reconstruction_input(shares: Sequence[ShamirShare], threshold: int) -> None:
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 2:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
    if not isinstance(shares, Sequence) or isinstance(shares, (bytes, bytearray, str)):
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
    if len(shares) < threshold:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)

    seen_x: set[int] = set()
    for share in shares:
        if not isinstance(share, ShamirShare):
            raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
        if share.x in seen_x:
            raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
        seen_x.add(share.x)


def _require_threshold(threshold: int, share_count: int) -> None:
    if (
        not isinstance(threshold, int)
        or isinstance(threshold, bool)
        or not isinstance(share_count, int)
        or isinstance(share_count, bool)
        or threshold < 2
        or threshold > share_count
    ):
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)


def _require_wrapping_key(secret: bytes) -> None:
    if not isinstance(secret, bytes) or len(secret) != WRAPPING_KEY_SIZE:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)


def _require_field_index(value: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 < value < FIELD_PRIME:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)


def _require_field_element(value: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < FIELD_PRIME:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)


__all__ = [
    "FIELD_PRIME",
    "WRAPPING_KEY_SIZE",
    "ShamirShare",
    "reconstruct_secret",
    "split_secret",
]
