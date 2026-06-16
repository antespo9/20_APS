import base64
from dataclasses import replace
import inspect

import pytest

import evoting.crypto.ta_blob as ta_blob_module
from evoting.crypto.ta_blob import (
    BLOB_TA_CONTEXT,
    HMAC_SHA256_TAG_SIZE,
    TaBlob,
    derive_ta_blob_keys,
    open_ta_private_key,
    protect_ta_private_key,
    ta_blob_authenticated_bytes,
    ta_blob_hkdf_context,
)
from evoting.errors import CRYPTOGRAPHIC_ERROR_MESSAGE, CryptographicError
from evoting.serialization import canonical_bytes


ELECTION_ID = "election-2026"
WRAPPING_KEY = bytes(range(32))
PRIVATE_KEY_PEM = (
    b"-----BEGIN PRIVATE KEY-----\n"
    b"unit-test-ta-private-key-material\n"
    b"-----END PRIVATE KEY-----"
)


def _blob(wrapping_key: bytes = WRAPPING_KEY) -> TaBlob:
    return protect_ta_private_key(
        election_id=ELECTION_ID,
        private_key_pem=PRIVATE_KEY_PEM,
        wrapping_key=wrapping_key,
        threshold_t=3,
        threshold_n=5,
    )


def _assert_generic_error(operation: object) -> None:
    with pytest.raises(CryptographicError) as exc_info:
        operation()

    assert str(exc_info.value) == CRYPTOGRAPHIC_ERROR_MESSAGE


def test_derive_ta_blob_keys_is_deterministic_distinct_and_32_bytes() -> None:
    first = derive_ta_blob_keys(WRAPPING_KEY, ELECTION_ID)
    second = derive_ta_blob_keys(WRAPPING_KEY, ELECTION_ID)

    assert first.kenc == second.kenc
    assert first.kmac == second.kmac
    assert len(first.kenc) == 32
    assert len(first.kmac) == 32
    assert first.kenc != first.kmac
    assert ta_blob_hkdf_context(ELECTION_ID, "encryption") != ta_blob_hkdf_context(
        ELECTION_ID,
        "authentication",
    )


def test_derive_ta_blob_keys_binds_election_and_context() -> None:
    baseline = derive_ta_blob_keys(WRAPPING_KEY, ELECTION_ID)

    assert derive_ta_blob_keys(WRAPPING_KEY, "election-2027").kenc != baseline.kenc
    assert derive_ta_blob_keys(
        WRAPPING_KEY,
        ELECTION_ID,
        context=BLOB_TA_CONTEXT + ".next",
    ).kmac != baseline.kmac


@pytest.mark.parametrize("wrapping_key", [b"", b"k" * 31, b"k" * 33])
def test_wrapping_key_must_be_exactly_32_bytes(wrapping_key: bytes) -> None:
    _assert_generic_error(lambda: derive_ta_blob_keys(wrapping_key, ELECTION_ID))
    _assert_generic_error(
        lambda: protect_ta_private_key(
            election_id=ELECTION_ID,
            private_key_pem=PRIVATE_KEY_PEM,
            wrapping_key=wrapping_key,
            threshold_t=3,
            threshold_n=5,
        )
    )


def test_same_plaintext_encrypts_differently_with_fresh_iv() -> None:
    first = _blob()
    second = _blob()

    assert first.iv != second.iv
    assert first.ciphertext != second.ciphertext
    assert open_ta_private_key(first, WRAPPING_KEY) == PRIVATE_KEY_PEM
    assert open_ta_private_key(second, WRAPPING_KEY) == PRIVATE_KEY_PEM


def test_ta_blob_contains_no_clear_secrets_or_gcm_fields() -> None:
    blob = _blob()
    keys = derive_ta_blob_keys(WRAPPING_KEY, ELECTION_ID)
    encoded_blob = canonical_bytes(blob)

    assert set(blob.__dataclass_fields__) == {
        "election_id",
        "context",
        "iv",
        "ciphertext",
        "mac",
        "threshold_t",
        "threshold_n",
    }
    assert not hasattr(blob, "nonce")
    assert not hasattr(blob, "tag")
    assert not hasattr(blob, "kwrap")
    assert not hasattr(blob, "kenc")
    assert not hasattr(blob, "kmac")
    assert base64.b64encode(WRAPPING_KEY) not in encoded_blob
    assert base64.b64encode(keys.kenc) not in encoded_blob
    assert base64.b64encode(keys.kmac) not in encoded_blob
    assert base64.b64encode(PRIVATE_KEY_PEM) not in encoded_blob
    assert PRIVATE_KEY_PEM not in repr(blob).encode("utf-8")


def test_authenticated_bytes_are_canonical_and_cover_required_fields() -> None:
    blob = _blob()

    assert ta_blob_authenticated_bytes(blob) == canonical_bytes(
        {
            "ciphertext": blob.ciphertext,
            "context": blob.context,
            "election_id": blob.election_id,
            "iv": blob.iv,
            "threshold_n": blob.threshold_n,
            "threshold_t": blob.threshold_t,
        }
    )


def test_mac_is_verified_before_cbc_decryption_and_unpadding(monkeypatch: pytest.MonkeyPatch) -> None:
    blob = _blob()
    altered = replace(blob, mac=blob.mac[:-1] + bytes([blob.mac[-1] ^ 1]))
    called = {"decrypt": False, "unpad": False}

    def fail_decrypt(*args: object) -> bytes:
        called["decrypt"] = True
        raise AssertionError("CBC decryptor was created before MAC verification")

    def fail_unpad(*args: object) -> bytes:
        called["unpad"] = True
        raise AssertionError("PKCS7 unpadding was attempted before MAC verification")

    monkeypatch.setattr(ta_blob_module, "_decrypt_cbc", fail_decrypt)
    monkeypatch.setattr(ta_blob_module, "_remove_pkcs7_padding", fail_unpad)

    _assert_generic_error(lambda: open_ta_private_key(altered, WRAPPING_KEY))

    assert called == {"decrypt": False, "unpad": False}


def test_invalid_padding_is_reported_as_generic_error(monkeypatch: pytest.MonkeyPatch) -> None:
    blob = _blob()

    def invalid_plaintext(*args: object) -> bytes:
        return b"\x00" * 16

    monkeypatch.setattr(ta_blob_module, "_decrypt_cbc", invalid_plaintext)

    _assert_generic_error(lambda: open_ta_private_key(blob, WRAPPING_KEY))


@pytest.mark.parametrize(
    "operation",
    [
        lambda: TaBlob(ELECTION_ID, BLOB_TA_CONTEXT, b"short", b"x" * 16, b"m" * 32, 3, 5),
        lambda: TaBlob(ELECTION_ID, BLOB_TA_CONTEXT, b"i" * 16, b"short", b"m" * 32, 3, 5),
        lambda: TaBlob(
            ELECTION_ID,
            BLOB_TA_CONTEXT,
            b"i" * 16,
            b"x" * 16,
            b"m" * (HMAC_SHA256_TAG_SIZE - 1),
            3,
            5,
        ),
        lambda: open_ta_private_key(object(), WRAPPING_KEY),
        lambda: ta_blob_hkdf_context(ELECTION_ID, "unknown-purpose"),
    ],
)
def test_malformed_ta_blob_inputs_use_generic_error(operation: object) -> None:
    _assert_generic_error(operation)


def test_ta_blob_does_not_use_fernet_or_aes_gcm() -> None:
    source = inspect.getsource(ta_blob_module)

    assert "Fernet" not in source
    assert "AESGCM" not in source
    assert "encrypt_aead" not in source
    assert "decrypt_aead" not in source
