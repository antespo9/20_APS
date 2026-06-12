import pytest

from evoting.crypto.aead import AeadCiphertext, decrypt_aead, encrypt_aead
from evoting.crypto.encryption import decrypt_vote, encrypt_vote, generate_encryption_private_key
from evoting.crypto.signatures import generate_signature_private_key, sign_message, verify_signature
from evoting.errors import CRYPTOGRAPHIC_ERROR_MESSAGE, CryptographicError


def test_signature_tampering_returns_clear_rejection_without_internal_exception() -> None:
    private_key = generate_signature_private_key()
    signature = bytearray(sign_message(private_key, b"message"))
    signature[0] ^= 1

    assert verify_signature(private_key.public_key(), b"message", bytes(signature)) is False


def test_signature_wrong_key_returns_clear_rejection() -> None:
    private_key = generate_signature_private_key()
    wrong_key = generate_signature_private_key().public_key()
    signature = sign_message(private_key, b"message")

    assert verify_signature(wrong_key, b"message", signature) is False


def test_rsa_oaep_tampering_and_wrong_key_use_uniform_error() -> None:
    private_key = generate_encryption_private_key()
    wrong_key = generate_encryption_private_key()
    ciphertext = bytearray(encrypt_vote(private_key.public_key(), b"LIST-001"))
    ciphertext[-1] ^= 1
    errors: list[str] = []

    for key, value in [(private_key, bytes(ciphertext)), (wrong_key, encrypt_vote(private_key.public_key(), b"LIST-001"))]:
        with pytest.raises(CryptographicError) as exc_info:
            decrypt_vote(key, value)
        errors.append(str(exc_info.value))

    assert errors == [CRYPTOGRAPHIC_ERROR_MESSAGE, CRYPTOGRAPHIC_ERROR_MESSAGE]


def test_aead_tampering_uses_uniform_error_for_ciphertext_tag_and_aad() -> None:
    key = b"k" * 32
    aad = b"context:election-2026"
    encrypted = encrypt_aead(key, b"secret payload", aad)
    altered_ciphertext = AeadCiphertext(
        nonce=encrypted.nonce,
        ciphertext=encrypted.ciphertext[:-1] + bytes([encrypted.ciphertext[-1] ^ 1]),
        tag=encrypted.tag,
    )
    altered_tag = AeadCiphertext(
        nonce=encrypted.nonce,
        ciphertext=encrypted.ciphertext,
        tag=encrypted.tag[:-1] + bytes([encrypted.tag[-1] ^ 1]),
    )
    errors: list[str] = []

    for value, used_aad in [
        (altered_ciphertext, aad),
        (altered_tag, aad),
        (encrypted, b"context:other-election"),
    ]:
        with pytest.raises(CryptographicError) as exc_info:
            decrypt_aead(key, value, used_aad)
        errors.append(str(exc_info.value))

    assert errors == [
        CRYPTOGRAPHIC_ERROR_MESSAGE,
        CRYPTOGRAPHIC_ERROR_MESSAGE,
        CRYPTOGRAPHIC_ERROR_MESSAGE,
    ]


@pytest.mark.parametrize(
    "operation",
    [
        lambda: decrypt_vote(generate_encryption_private_key(), b"not a valid ciphertext"),
        lambda: encrypt_vote(object(), b"LIST-001"),
        lambda: decrypt_aead(b"short", AeadCiphertext(nonce=b"n" * 12, ciphertext=b"x", tag=b"t" * 16), b"aad"),
        lambda: decrypt_aead(b"k" * 32, object(), b"aad"),
    ],
)
def test_structurally_invalid_crypto_inputs_use_generic_application_error(operation: object) -> None:
    with pytest.raises(CryptographicError) as exc_info:
        operation()

    assert str(exc_info.value) == CRYPTOGRAPHIC_ERROR_MESSAGE
