"""Scrypt password verifier and key derivation helpers."""

from __future__ import annotations

from dataclasses import dataclass
import os

from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from evoting.errors import CRYPTOGRAPHIC_ERROR_MESSAGE, CryptographicError


SCRYPT_DEFAULT_N = 2**15
SCRYPT_DEFAULT_R = 8
SCRYPT_DEFAULT_P = 1
SCRYPT_SALT_SIZE = 16
SCRYPT_VERIFIER_SIZE = 32


def _require_bytes(value: bytes) -> None:
    if not isinstance(value, bytes):
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)


def _is_power_of_two(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0 and value & (value - 1) == 0


@dataclass(frozen=True, slots=True)
class ScryptParameters:
    n: int = SCRYPT_DEFAULT_N
    r: int = SCRYPT_DEFAULT_R
    p: int = SCRYPT_DEFAULT_P
    length: int = SCRYPT_VERIFIER_SIZE

    def __post_init__(self) -> None:
        if not _is_power_of_two(self.n) or self.n <= 1:
            raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
        if not isinstance(self.r, int) or isinstance(self.r, bool) or self.r <= 0:
            raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
        if not isinstance(self.p, int) or isinstance(self.p, bool) or self.p <= 0:
            raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
        if not isinstance(self.length, int) or isinstance(self.length, bool) or self.length <= 0:
            raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)


@dataclass(frozen=True, slots=True)
class PasswordVerifier:
    salt: bytes
    verifier: bytes
    parameters: ScryptParameters

    def __post_init__(self) -> None:
        if not isinstance(self.salt, bytes) or len(self.salt) != SCRYPT_SALT_SIZE:
            raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
        if not isinstance(self.verifier, bytes) or len(self.verifier) == 0:
            raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
        if not isinstance(self.parameters, ScryptParameters):
            raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
        if len(self.verifier) != self.parameters.length:
            raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)


def create_password_verifier(
    password: bytes,
    parameters: ScryptParameters = ScryptParameters(),
) -> PasswordVerifier:
    """Create a persistible Scrypt verifier with a fresh 16-byte salt."""

    _require_bytes(password)
    if not isinstance(parameters, ScryptParameters):
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
    salt = os.urandom(SCRYPT_SALT_SIZE)
    verifier = derive_key(password, salt, parameters, length=parameters.length)
    return PasswordVerifier(salt=salt, verifier=verifier, parameters=parameters)


def verify_password(password: bytes, verifier: PasswordVerifier) -> bool:
    """Return True only when the password matches the stored Scrypt verifier."""

    _require_bytes(password)
    if not isinstance(verifier, PasswordVerifier):
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
    candidate = derive_key(
        password,
        verifier.salt,
        verifier.parameters,
        length=verifier.parameters.length,
    )
    return constant_time.bytes_eq(candidate, verifier.verifier)


def derive_key(
    password: bytes,
    salt: bytes,
    parameters: ScryptParameters = ScryptParameters(),
    *,
    length: int = 32,
) -> bytes:
    """Derive a byte key with Scrypt and explicit persistible parameters."""

    _require_bytes(password)
    if not isinstance(salt, bytes) or len(salt) != SCRYPT_SALT_SIZE:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
    if not isinstance(parameters, ScryptParameters):
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
    if not isinstance(length, int) or isinstance(length, bool) or length <= 0:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
    try:
        kdf = Scrypt(salt=salt, length=length, n=parameters.n, r=parameters.r, p=parameters.p)
        return kdf.derive(password)
    except Exception as exc:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE) from exc


__all__ = [
    "SCRYPT_DEFAULT_N",
    "SCRYPT_DEFAULT_P",
    "SCRYPT_DEFAULT_R",
    "SCRYPT_SALT_SIZE",
    "SCRYPT_VERIFIER_SIZE",
    "PasswordVerifier",
    "ScryptParameters",
    "create_password_verifier",
    "derive_key",
    "verify_password",
]
