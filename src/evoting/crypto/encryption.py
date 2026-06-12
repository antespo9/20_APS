"""RSA-OAEP encryption with SHA-256."""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from evoting.errors import CRYPTOGRAPHIC_ERROR_MESSAGE, CryptographicError


ENCRYPTION_KEY_SIZE = 2048
PUBLIC_EXPONENT = 65537


def generate_encryption_private_key(key_size: int = ENCRYPTION_KEY_SIZE) -> rsa.RSAPrivateKey:
    """Generate an RSA private key suitable for RSA-OAEP encryption."""

    try:
        return rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=key_size)
    except ValueError as exc:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE) from exc


def encryption_public_key_to_pem(public_key: rsa.RSAPublicKey) -> bytes:
    """Serialize an RSA public key as PEM SubjectPublicKeyInfo bytes."""

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def encryption_private_key_to_pem(private_key: rsa.RSAPrivateKey) -> bytes:
    """Serialize an RSA private key as unencrypted PEM PKCS8 bytes."""

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_encryption_public_key(public_key_pem: bytes) -> rsa.RSAPublicKey:
    """Load an RSA public key from PEM bytes."""

    _require_bytes(public_key_pem)
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
    except (TypeError, ValueError) as exc:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE) from exc
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
    return public_key


def load_encryption_private_key(private_key_pem: bytes) -> rsa.RSAPrivateKey:
    """Load an RSA private key from PEM bytes."""

    _require_bytes(private_key_pem)
    try:
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    except (TypeError, ValueError) as exc:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE) from exc
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
    return private_key


def encrypt_vote(public_key: rsa.RSAPublicKey, plaintext: bytes) -> bytes:
    """Encrypt byte input with RSA-OAEP using SHA-256 for OAEP and MGF1."""

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
    _require_bytes(plaintext)
    try:
        return public_key.encrypt(plaintext, _oaep_padding())
    except Exception as exc:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE) from exc


def decrypt_vote(private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    """Decrypt RSA-OAEP ciphertext, returning a generic application error on failure."""

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
    _require_bytes(ciphertext)
    try:
        return private_key.decrypt(ciphertext, _oaep_padding())
    except Exception as exc:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE) from exc


def _oaep_padding() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def _require_bytes(value: bytes) -> None:
    if not isinstance(value, bytes):
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)


__all__ = [
    "ENCRYPTION_KEY_SIZE",
    "PUBLIC_EXPONENT",
    "decrypt_vote",
    "encrypt_vote",
    "encryption_private_key_to_pem",
    "encryption_public_key_to_pem",
    "generate_encryption_private_key",
    "load_encryption_private_key",
    "load_encryption_public_key",
]
