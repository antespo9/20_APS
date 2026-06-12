import pytest
from cryptography.hazmat.primitives.asymmetric import padding

from evoting.crypto.encryption import (
    decrypt_vote,
    encryption_private_key_to_pem,
    encryption_public_key_to_pem,
    encrypt_vote,
    generate_encryption_private_key,
    load_encryption_private_key,
    load_encryption_public_key,
)
from evoting.errors import CRYPTOGRAPHIC_ERROR_MESSAGE, CryptographicError


def test_rsa_oaep_encrypts_and_decrypts_vote() -> None:
    private_key = generate_encryption_private_key()
    plaintext = b"LIST-001"

    ciphertext = encrypt_vote(private_key.public_key(), plaintext)

    assert ciphertext != plaintext
    assert decrypt_vote(private_key, ciphertext) == plaintext


def test_rsa_oaep_with_loaded_keys_encrypts_and_decrypts() -> None:
    private_key = generate_encryption_private_key()
    private_key_pem = encryption_private_key_to_pem(private_key)
    public_key_pem = encryption_public_key_to_pem(private_key.public_key())
    loaded_private_key = load_encryption_private_key(private_key_pem)
    loaded_public_key = load_encryption_public_key(public_key_pem)

    ciphertext = encrypt_vote(loaded_public_key, b"LIST-002")

    assert decrypt_vote(loaded_private_key, ciphertext) == b"LIST-002"


def test_rsa_oaep_encryption_uses_fresh_randomness() -> None:
    public_key = generate_encryption_private_key().public_key()
    plaintext = b"LIST-001"

    first = encrypt_vote(public_key, plaintext)
    second = encrypt_vote(public_key, plaintext)

    assert first != second


def test_altered_ciphertext_is_rejected() -> None:
    private_key = generate_encryption_private_key()
    ciphertext = bytearray(encrypt_vote(private_key.public_key(), b"LIST-001"))
    ciphertext[-1] ^= 1

    with pytest.raises(CryptographicError) as exc_info:
        decrypt_vote(private_key, bytes(ciphertext))

    assert str(exc_info.value) == CRYPTOGRAPHIC_ERROR_MESSAGE


def test_wrong_private_key_is_rejected() -> None:
    private_key = generate_encryption_private_key()
    wrong_key = generate_encryption_private_key()
    ciphertext = encrypt_vote(private_key.public_key(), b"LIST-001")

    with pytest.raises(CryptographicError) as exc_info:
        decrypt_vote(wrong_key, ciphertext)

    assert str(exc_info.value) == CRYPTOGRAPHIC_ERROR_MESSAGE


def test_pkcs1v15_ciphertext_is_rejected_by_oaep_decryptor() -> None:
    private_key = generate_encryption_private_key()
    ciphertext = private_key.public_key().encrypt(b"LIST-001", padding.PKCS1v15())

    with pytest.raises(CryptographicError) as exc_info:
        decrypt_vote(private_key, ciphertext)

    assert str(exc_info.value) == CRYPTOGRAPHIC_ERROR_MESSAGE


@pytest.mark.parametrize(
    ("public_key", "plaintext"),
    [
        (object(), b"LIST-001"),
        (None, b"LIST-001"),
        (generate_encryption_private_key().public_key(), "LIST-001"),
    ],
)
def test_encrypt_vote_rejects_invalid_structure(public_key: object, plaintext: object) -> None:
    with pytest.raises(CryptographicError) as exc_info:
        encrypt_vote(public_key, plaintext)  # type: ignore[arg-type]

    assert str(exc_info.value) == CRYPTOGRAPHIC_ERROR_MESSAGE


@pytest.mark.parametrize("ciphertext", ["ciphertext", bytearray(b"ciphertext")])
def test_decrypt_vote_rejects_invalid_structure(ciphertext: object) -> None:
    private_key = generate_encryption_private_key()

    with pytest.raises(CryptographicError) as exc_info:
        decrypt_vote(private_key, ciphertext)  # type: ignore[arg-type]

    assert str(exc_info.value) == CRYPTOGRAPHIC_ERROR_MESSAGE


def test_loading_invalid_encryption_key_uses_generic_error() -> None:
    with pytest.raises(CryptographicError) as exc_info:
        load_encryption_private_key(b"not a pem key")

    assert str(exc_info.value) == CRYPTOGRAPHIC_ERROR_MESSAGE
