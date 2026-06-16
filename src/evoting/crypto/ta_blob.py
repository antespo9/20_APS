"""Protection for the Tallying Authority private-key blob."""

from __future__ import annotations

from dataclasses import dataclass
import os

from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from evoting.crypto.shamir import WRAPPING_KEY_SIZE
from evoting.errors import CRYPTOGRAPHIC_ERROR_MESSAGE, CryptographicError
from evoting.serialization import canonical_bytes


BLOB_TA_CONTEXT = "evoting.blobTA.cbc-hmac.v1"
BLOB_TA_AAD_CONTEXT = BLOB_TA_CONTEXT
AES256_CBC_KEY_SIZE = 32
AES_CBC_IV_SIZE = 16
HMAC_SHA256_KEY_SIZE = 32
HMAC_SHA256_TAG_SIZE = 32
PKCS7_BLOCK_SIZE_BITS = 128

_HKDF_NAME = "HKDF-SHA256"
_PURPOSE_ENCRYPTION = "encryption"
_PURPOSE_AUTHENTICATION = "authentication"


@dataclass(frozen=True, slots=True, repr=False)
class TaBlobKeys:
    """Independent keys derived from ``Kwrap`` for ``blobTA`` protection."""

    kenc: bytes
    kmac: bytes

    def __post_init__(self) -> None:
        _require_derived_key(self.kenc)
        _require_derived_key(self.kmac)
        if self.kenc == self.kmac:
            raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)


@dataclass(frozen=True, slots=True)
class TaBlob:
    election_id: str
    context: str
    iv: bytes
    ciphertext: bytes
    mac: bytes
    threshold_t: int
    threshold_n: int

    def __post_init__(self) -> None:
        _require_identifier(self.election_id)
        _require_context(self.context)
        _require_iv(self.iv)
        _require_ciphertext(self.ciphertext)
        _require_mac(self.mac)
        _require_threshold(self.threshold_t, self.threshold_n)


def derive_ta_blob_keys(
    wrapping_key: bytes,
    election_id: str,
    context: str = BLOB_TA_CONTEXT,
) -> TaBlobKeys:
    """Derive independent AES-CBC and HMAC-SHA256 keys from a 32-byte ``Kwrap``."""

    _require_wrapping_key(wrapping_key)
    _require_identifier(election_id)
    _require_context(context)
    return TaBlobKeys(
        kenc=_hkdf_key(wrapping_key, election_id, _PURPOSE_ENCRYPTION, context),
        kmac=_hkdf_key(wrapping_key, election_id, _PURPOSE_AUTHENTICATION, context),
    )


def ta_blob_hkdf_context(
    election_id: str,
    purpose: str,
    context: str = BLOB_TA_CONTEXT,
) -> bytes:
    """Build the canonical HKDF context for a ``blobTA`` subkey."""

    _require_identifier(election_id)
    _require_context(context)
    if purpose not in {_PURPOSE_ENCRYPTION, _PURPOSE_AUTHENTICATION}:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
    return canonical_bytes(
        {
            "context": context,
            "election_id": election_id,
            "kdf": _HKDF_NAME,
            "purpose": purpose,
        }
    )


def ta_blob_authenticated_bytes(blob: TaBlob) -> bytes:
    """Return the canonical bytes authenticated by the ``blobTA`` MAC."""

    if not isinstance(blob, TaBlob):
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
    return _authenticated_bytes(
        context=blob.context,
        election_id=blob.election_id,
        iv=blob.iv,
        ciphertext=blob.ciphertext,
        threshold_t=blob.threshold_t,
        threshold_n=blob.threshold_n,
    )


def blob_ta_aad(election_id: str, aad_context: str = BLOB_TA_CONTEXT) -> bytes:
    """Compatibility helper for the previous public API name."""

    _require_identifier(election_id)
    _require_context(aad_context)
    return canonical_bytes({"context": aad_context, "election_id": election_id})


def protect_ta_private_key(
    *,
    election_id: str,
    private_key_pem: bytes,
    wrapping_key: bytes,
    threshold_t: int,
    threshold_n: int,
    context: str = BLOB_TA_CONTEXT,
) -> TaBlob:
    """Encrypt and authenticate a serialized TA private key."""

    try:
        _require_identifier(election_id)
        _require_context(context)
        _require_private_key_bytes(private_key_pem)
        _require_wrapping_key(wrapping_key)
        _require_threshold(threshold_t, threshold_n)

        keys = derive_ta_blob_keys(wrapping_key, election_id, context)
        iv = os.urandom(AES_CBC_IV_SIZE)
        padded = _apply_pkcs7_padding(private_key_pem)
        ciphertext = _encrypt_cbc(keys.kenc, iv, padded)
        authenticated = _authenticated_bytes(
            context=context,
            election_id=election_id,
            iv=iv,
            ciphertext=ciphertext,
            threshold_t=threshold_t,
            threshold_n=threshold_n,
        )
        mac_value = _compute_hmac(keys.kmac, authenticated)
        return TaBlob(
            election_id=election_id,
            context=context,
            iv=iv,
            ciphertext=ciphertext,
            mac=mac_value,
            threshold_t=threshold_t,
            threshold_n=threshold_n,
        )
    except CryptographicError:
        raise
    except Exception as exc:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE) from exc


def open_ta_private_key(blob: TaBlob, wrapping_key: bytes) -> bytes:
    """Authenticate and open ``blobTA`` with a reconstructed ``Kwrap``."""

    try:
        if not isinstance(blob, TaBlob):
            raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
        keys = derive_ta_blob_keys(wrapping_key, blob.election_id, blob.context)
        _verify_hmac(keys.kmac, ta_blob_authenticated_bytes(blob), blob.mac)
        padded_plaintext = _decrypt_cbc(keys.kenc, blob.iv, blob.ciphertext)
        return _remove_pkcs7_padding(padded_plaintext)
    except CryptographicError:
        raise
    except Exception as exc:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE) from exc


def _hkdf_key(wrapping_key: bytes, election_id: str, purpose: str, context: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=AES256_CBC_KEY_SIZE,
        salt=None,
        info=ta_blob_hkdf_context(election_id, purpose, context),
    ).derive(wrapping_key)


def _authenticated_bytes(
    *,
    context: str,
    election_id: str,
    iv: bytes,
    ciphertext: bytes,
    threshold_t: int,
    threshold_n: int,
) -> bytes:
    _require_context(context)
    _require_identifier(election_id)
    _require_iv(iv)
    _require_ciphertext(ciphertext)
    _require_threshold(threshold_t, threshold_n)
    return canonical_bytes(
        {
            "ciphertext": ciphertext,
            "context": context,
            "election_id": election_id,
            "iv": iv,
            "threshold_n": threshold_n,
            "threshold_t": threshold_t,
        }
    )


def _apply_pkcs7_padding(value: bytes) -> bytes:
    try:
        padder = padding.PKCS7(PKCS7_BLOCK_SIZE_BITS).padder()
        return padder.update(value) + padder.finalize()
    except Exception as exc:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE) from exc


def _remove_pkcs7_padding(value: bytes) -> bytes:
    try:
        unpadder = padding.PKCS7(PKCS7_BLOCK_SIZE_BITS).unpadder()
        return unpadder.update(value) + unpadder.finalize()
    except Exception as exc:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE) from exc


def _encrypt_cbc(key: bytes, iv: bytes, padded_plaintext: bytes) -> bytes:
    try:
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        return encryptor.update(padded_plaintext) + encryptor.finalize()
    except Exception as exc:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE) from exc


def _decrypt_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    try:
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as exc:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE) from exc


def _compute_hmac(key: bytes, authenticated: bytes) -> bytes:
    try:
        mac = hmac.HMAC(key, hashes.SHA256())
        mac.update(authenticated)
        return mac.finalize()
    except Exception as exc:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE) from exc


def _verify_hmac(key: bytes, authenticated: bytes, expected: bytes) -> None:
    try:
        mac = hmac.HMAC(key, hashes.SHA256())
        mac.update(authenticated)
        mac.verify(expected)
    except Exception as exc:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE) from exc


def _require_identifier(value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)


def _require_context(value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)


def _require_private_key_bytes(value: bytes) -> None:
    if not isinstance(value, bytes) or len(value) == 0:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)


def _require_wrapping_key(value: bytes) -> None:
    if not isinstance(value, bytes) or len(value) != WRAPPING_KEY_SIZE:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)


def _require_derived_key(value: bytes) -> None:
    if not isinstance(value, bytes) or len(value) != AES256_CBC_KEY_SIZE:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)


def _require_iv(value: bytes) -> None:
    if not isinstance(value, bytes) or len(value) != AES_CBC_IV_SIZE:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)


def _require_ciphertext(value: bytes) -> None:
    if (
        not isinstance(value, bytes)
        or len(value) == 0
        or len(value) % AES_CBC_IV_SIZE != 0
    ):
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)


def _require_mac(value: bytes) -> None:
    if not isinstance(value, bytes) or len(value) != HMAC_SHA256_TAG_SIZE:
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)


def _require_threshold(threshold_t: int, threshold_n: int) -> None:
    if (
        not isinstance(threshold_t, int)
        or isinstance(threshold_t, bool)
        or not isinstance(threshold_n, int)
        or isinstance(threshold_n, bool)
        or threshold_t < 2
        or threshold_t > threshold_n
    ):
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)


__all__ = [
    "AES256_CBC_KEY_SIZE",
    "AES_CBC_IV_SIZE",
    "BLOB_TA_AAD_CONTEXT",
    "BLOB_TA_CONTEXT",
    "HMAC_SHA256_KEY_SIZE",
    "HMAC_SHA256_TAG_SIZE",
    "PKCS7_BLOCK_SIZE_BITS",
    "TaBlob",
    "TaBlobKeys",
    "blob_ta_aad",
    "derive_ta_blob_keys",
    "open_ta_private_key",
    "protect_ta_private_key",
    "ta_blob_authenticated_bytes",
    "ta_blob_hkdf_context",
]
