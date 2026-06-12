"""Cryptographic primitives used by the protocol prototype."""

from evoting.crypto.aead import AeadCiphertext, decrypt_aead, encrypt_aead
from evoting.crypto.encryption import (
    decrypt_vote,
    encryption_public_key_to_pem,
    encrypt_vote,
    generate_encryption_private_key,
    load_encryption_private_key,
    load_encryption_public_key,
)
from evoting.crypto.hashes import SHA256_DIGEST_SIZE, sha256_digest
from evoting.crypto.password import (
    SCRYPT_DEFAULT_N,
    SCRYPT_DEFAULT_P,
    SCRYPT_DEFAULT_R,
    SCRYPT_SALT_SIZE,
    PasswordVerifier,
    ScryptParameters,
    create_password_verifier,
    derive_key,
    verify_password,
)
from evoting.crypto.shamir import (
    FIELD_PRIME,
    WRAPPING_KEY_SIZE,
    ShamirShare,
    reconstruct_secret,
    split_secret,
)
from evoting.crypto.signatures import (
    generate_signature_private_key,
    load_signature_private_key,
    load_signature_public_key,
    signature_public_key_to_pem,
    sign_message,
    verify_signature,
)

__all__ = [
    "AeadCiphertext",
    "FIELD_PRIME",
    "PasswordVerifier",
    "SCRYPT_DEFAULT_N",
    "SCRYPT_DEFAULT_P",
    "SCRYPT_DEFAULT_R",
    "SCRYPT_SALT_SIZE",
    "SHA256_DIGEST_SIZE",
    "ScryptParameters",
    "ShamirShare",
    "WRAPPING_KEY_SIZE",
    "create_password_verifier",
    "decrypt_aead",
    "decrypt_vote",
    "derive_key",
    "encrypt_aead",
    "encrypt_vote",
    "encryption_public_key_to_pem",
    "generate_encryption_private_key",
    "generate_signature_private_key",
    "load_encryption_private_key",
    "load_encryption_public_key",
    "load_signature_private_key",
    "load_signature_public_key",
    "reconstruct_secret",
    "sha256_digest",
    "sign_message",
    "signature_public_key_to_pem",
    "split_secret",
    "verify_password",
    "verify_signature",
]
