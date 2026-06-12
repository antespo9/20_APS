"""RSA-PSS signatures with SHA-256."""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from evoting.errors import CRYPTOGRAPHIC_ERROR_MESSAGE, CryptographicError


SIGNATURE_KEY_SIZE = 2048
PUBLIC_EXPONENT = 65537


def generate_signature_private_key(key_size: int = SIGNATURE_KEY_SIZE) -> rsa.RSAPrivateKey:
    """Generate an RSA private key suitable for RSA-PSS signatures."""

    try:
        return rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=key_size)
    except ValueError as exc:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE) from exc


def signature_public_key_to_pem(public_key: rsa.RSAPublicKey) -> bytes:
    """Serialize an RSA public key as PEM SubjectPublicKeyInfo bytes."""

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def signature_private_key_to_pem(private_key: rsa.RSAPrivateKey) -> bytes:
    """Serialize an RSA private key as unencrypted PEM PKCS8 bytes."""

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_signature_public_key(public_key_pem: bytes) -> rsa.RSAPublicKey:
    """Load an RSA public key from PEM bytes."""

    _require_bytes(public_key_pem)
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
    except (TypeError, ValueError) as exc:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE) from exc
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
    return public_key


def load_signature_private_key(private_key_pem: bytes) -> rsa.RSAPrivateKey:
    """Load an RSA private key from PEM bytes."""

    _require_bytes(private_key_pem)
    try:
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    except (TypeError, ValueError) as exc:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE) from exc
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
    return private_key


def sign_message(private_key: rsa.RSAPrivateKey, message: bytes) -> bytes:
    """Sign byte input with RSA-PSS, MGF1 SHA-256 and maximum salt length."""

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
    _require_bytes(message)
    try:
        return private_key.sign(message, _pss_padding(), hashes.SHA256())
    except Exception as exc:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE) from exc


def verify_signature(public_key: rsa.RSAPublicKey, message: bytes, signature: bytes) -> bool:
    """Return True only when the RSA-PSS signature verifies for the byte input."""

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
    _require_bytes(message)
    _require_bytes(signature)
    try:
        public_key.verify(signature, message, _pss_padding(), hashes.SHA256())
    except InvalidSignature:
        return False
    except Exception as exc:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE) from exc
    return True


def _pss_padding() -> padding.PSS:
    return padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    )


def _require_bytes(value: bytes) -> None:
    if not isinstance(value, bytes):
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)


__all__ = [
    "PUBLIC_EXPONENT",
    "SIGNATURE_KEY_SIZE",
    "generate_signature_private_key",
    "load_signature_private_key",
    "load_signature_public_key",
    "sign_message",
    "signature_private_key_to_pem",
    "signature_public_key_to_pem",
    "verify_signature",
]
