import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from evoting.crypto.signatures import (
    generate_signature_private_key,
    load_signature_private_key,
    load_signature_public_key,
    sign_message,
    signature_private_key_to_pem,
    signature_public_key_to_pem,
    verify_signature,
)
from evoting.errors import CRYPTOGRAPHIC_ERROR_MESSAGE, CryptographicError


def test_rsa_pss_signature_verifies() -> None:
    private_key = generate_signature_private_key()
    message = b"canonical vote message"

    signature = sign_message(private_key, message)

    assert verify_signature(private_key.public_key(), message, signature) is True


def test_rsa_pss_signature_with_loaded_keys_verifies() -> None:
    private_key = generate_signature_private_key()
    private_key_pem = signature_private_key_to_pem(private_key)
    public_key_pem = signature_public_key_to_pem(private_key.public_key())
    loaded_private_key = load_signature_private_key(private_key_pem)
    loaded_public_key = load_signature_public_key(public_key_pem)

    signature = sign_message(loaded_private_key, b"message")

    assert verify_signature(loaded_public_key, b"message", signature) is True


def test_altered_signature_is_rejected() -> None:
    private_key = generate_signature_private_key()
    message = b"message"
    signature = bytearray(sign_message(private_key, message))
    signature[-1] ^= 1

    assert verify_signature(private_key.public_key(), message, bytes(signature)) is False


def test_altered_message_is_rejected() -> None:
    private_key = generate_signature_private_key()
    signature = sign_message(private_key, b"message")

    assert verify_signature(private_key.public_key(), b"tampered", signature) is False


def test_wrong_public_key_is_rejected() -> None:
    private_key = generate_signature_private_key()
    wrong_key = generate_signature_private_key().public_key()
    signature = sign_message(private_key, b"message")

    assert verify_signature(wrong_key, b"message", signature) is False


def test_pkcs1v15_signature_is_rejected_by_pss_verifier() -> None:
    private_key = generate_signature_private_key()
    message = b"message"
    signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())

    assert verify_signature(private_key.public_key(), message, signature) is False


@pytest.mark.parametrize(
    ("private_key", "message"),
    [
        (object(), b"message"),
        (None, b"message"),
        ("not a key", b"message"),
        (generate_signature_private_key(), "message"),
    ],
)
def test_sign_message_rejects_invalid_structure(private_key: object, message: object) -> None:
    with pytest.raises(CryptographicError) as exc_info:
        sign_message(private_key, message)  # type: ignore[arg-type]

    assert str(exc_info.value) == CRYPTOGRAPHIC_ERROR_MESSAGE


@pytest.mark.parametrize(
    ("message", "signature"),
    [
        ("message", b"signature"),
        (b"message", "signature"),
    ],
)
def test_verify_signature_rejects_invalid_structure(message: object, signature: object) -> None:
    public_key = generate_signature_private_key().public_key()

    with pytest.raises(CryptographicError) as exc_info:
        verify_signature(public_key, message, signature)  # type: ignore[arg-type]

    assert str(exc_info.value) == CRYPTOGRAPHIC_ERROR_MESSAGE


def test_loading_invalid_signature_key_uses_generic_error() -> None:
    with pytest.raises(CryptographicError) as exc_info:
        load_signature_public_key(b"not a pem key")

    assert str(exc_info.value) == CRYPTOGRAPHIC_ERROR_MESSAGE
