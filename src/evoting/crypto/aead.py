"""AES-256-GCM authenticated encryption helpers."""

from __future__ import annotations

from dataclasses import dataclass
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from evoting.errors import CRYPTOGRAPHIC_ERROR_MESSAGE, CryptographicError


AES256_GCM_KEY_SIZE = 32
AES_GCM_NONCE_SIZE = 12
AES_GCM_TAG_SIZE = 16


@dataclass(frozen=True, slots=True)
class AeadCiphertext:
    nonce: bytes
    ciphertext: bytes
    tag: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.nonce, bytes) or len(self.nonce) != AES_GCM_NONCE_SIZE:
            raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
        if not isinstance(self.ciphertext, bytes):
            raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
        if not isinstance(self.tag, bytes) or len(self.tag) != AES_GCM_TAG_SIZE:
            raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)


def encrypt_aead(key: bytes, plaintext: bytes, aad: bytes) -> AeadCiphertext:
    """Encrypt bytes with AES-256-GCM using a fresh nonce and mandatory AAD."""

    _require_key(key)
    _require_bytes(plaintext)
    _require_aad(aad)
    nonce = os.urandom(AES_GCM_NONCE_SIZE)
    try:
        encrypted = AESGCM(key).encrypt(nonce, plaintext, aad)
    except Exception as exc:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE) from exc
    return AeadCiphertext(
        nonce=nonce,
        ciphertext=encrypted[:-AES_GCM_TAG_SIZE],
        tag=encrypted[-AES_GCM_TAG_SIZE:],
    )


def decrypt_aead(key: bytes, value: AeadCiphertext, aad: bytes) -> bytes:
    """Decrypt AES-256-GCM data, returning a generic application error on failure."""

    _require_key(key)
    if not isinstance(value, AeadCiphertext):
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
    _require_aad(aad)
    try:
        return AESGCM(key).decrypt(value.nonce, value.ciphertext + value.tag, aad)
    except Exception as exc:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE) from exc


def _require_key(value: bytes) -> None:
    if not isinstance(value, bytes) or len(value) != AES256_GCM_KEY_SIZE:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)


def _require_bytes(value: bytes) -> None:
    if not isinstance(value, bytes):
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)


def _require_aad(value: bytes) -> None:
    if not isinstance(value, bytes) or len(value) == 0:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)


__all__ = [
    "AES256_GCM_KEY_SIZE",
    "AES_GCM_NONCE_SIZE",
    "AES_GCM_TAG_SIZE",
    "AeadCiphertext",
    "decrypt_aead",
    "encrypt_aead",
]
