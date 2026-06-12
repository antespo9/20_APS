import pytest

from evoting.crypto.aead import (
    AES256_GCM_KEY_SIZE,
    AES_GCM_NONCE_SIZE,
    AES_GCM_TAG_SIZE,
    AeadCiphertext,
    decrypt_aead,
    encrypt_aead,
)
from evoting.errors import CRYPTOGRAPHIC_ERROR_MESSAGE, CryptographicError


KEY = b"k" * AES256_GCM_KEY_SIZE
AAD = b"context:election-2026"


def test_aes_256_gcm_encrypts_and_decrypts() -> None:
    encrypted = encrypt_aead(KEY, b"secret payload", AAD)

    assert len(encrypted.nonce) == AES_GCM_NONCE_SIZE
    assert len(encrypted.tag) == AES_GCM_TAG_SIZE
    assert encrypted.ciphertext != b"secret payload"
    assert decrypt_aead(KEY, encrypted, AAD) == b"secret payload"


def test_aes_256_gcm_uses_fresh_nonce() -> None:
    first = encrypt_aead(KEY, b"secret payload", AAD)
    second = encrypt_aead(KEY, b"secret payload", AAD)

    assert first.nonce != second.nonce
    assert first.ciphertext != second.ciphertext


def test_altered_ciphertext_is_rejected() -> None:
    encrypted = encrypt_aead(KEY, b"secret payload", AAD)
    altered = AeadCiphertext(
        nonce=encrypted.nonce,
        ciphertext=encrypted.ciphertext[:-1] + bytes([encrypted.ciphertext[-1] ^ 1]),
        tag=encrypted.tag,
    )

    with pytest.raises(CryptographicError) as exc_info:
        decrypt_aead(KEY, altered, AAD)

    assert str(exc_info.value) == CRYPTOGRAPHIC_ERROR_MESSAGE


def test_altered_tag_is_rejected() -> None:
    encrypted = encrypt_aead(KEY, b"secret payload", AAD)
    altered = AeadCiphertext(
        nonce=encrypted.nonce,
        ciphertext=encrypted.ciphertext,
        tag=encrypted.tag[:-1] + bytes([encrypted.tag[-1] ^ 1]),
    )

    with pytest.raises(CryptographicError) as exc_info:
        decrypt_aead(KEY, altered, AAD)

    assert str(exc_info.value) == CRYPTOGRAPHIC_ERROR_MESSAGE


def test_altered_aad_is_rejected() -> None:
    encrypted = encrypt_aead(KEY, b"secret payload", AAD)

    with pytest.raises(CryptographicError) as exc_info:
        decrypt_aead(KEY, encrypted, b"context:other-election")

    assert str(exc_info.value) == CRYPTOGRAPHIC_ERROR_MESSAGE


@pytest.mark.parametrize(
    "factory",
    [
        lambda: encrypt_aead(b"short", b"secret", AAD),
        lambda: encrypt_aead(KEY, "secret", AAD),
        lambda: encrypt_aead(KEY, b"secret", b""),
        lambda: encrypt_aead(KEY, b"secret", "aad"),
        lambda: decrypt_aead(KEY, object(), AAD),
        lambda: AeadCiphertext(nonce=b"short", ciphertext=b"x", tag=b"t" * AES_GCM_TAG_SIZE),
        lambda: AeadCiphertext(nonce=b"n" * AES_GCM_NONCE_SIZE, ciphertext=b"x", tag=b"short"),
    ],
)
def test_aead_inputs_with_invalid_structure_are_rejected(factory: object) -> None:
    with pytest.raises(CryptographicError) as exc_info:
        factory()

    assert str(exc_info.value) == CRYPTOGRAPHIC_ERROR_MESSAGE
