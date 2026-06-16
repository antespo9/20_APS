"""Tallying Authority blob protection for Milestone 3."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
import os

from evoting.actors.commissioners import CommissionerSet, CommissionerShare
from evoting.crypto.ta_blob import (
    BLOB_TA_AAD_CONTEXT,
    BLOB_TA_CONTEXT,
    TaBlob,
    blob_ta_aad,
    open_ta_private_key,
    protect_ta_private_key,
)
from evoting.crypto.shamir import WRAPPING_KEY_SIZE, ShamirShare, reconstruct_secret, split_secret
from evoting.errors import CRYPTOGRAPHIC_ERROR_MESSAGE, CryptographicError


@dataclass(frozen=True, slots=True)
class TallyingAuthority:
    election_id: str
    threshold_t: int
    threshold_n: int
    commissioner_ids: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        _require_identifier(self.election_id)
        _require_threshold(self.threshold_t, self.threshold_n)
        if self.commissioner_ids is not None:
            ids = tuple(self.commissioner_ids)
            if len(ids) != self.threshold_n or len(set(ids)) != len(ids):
                raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
            object.__setattr__(self, "commissioner_ids", ids)

    def create_blob(self, private_key_pem: bytes) -> tuple[TaBlob, CommissionerSet]:
        return create_protected_blob(
            election_id=self.election_id,
            private_key_pem=private_key_pem,
            threshold_t=self.threshold_t,
            threshold_n=self.threshold_n,
            commissioner_ids=self.commissioner_ids,
        )

    def open_blob(self, blob: TaBlob, shares: Sequence[CommissionerShare]) -> bytes:
        if not isinstance(blob, TaBlob) or blob.election_id != self.election_id:
            raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
        return open_protected_blob(blob, shares)


def create_protected_blob(
    *,
    election_id: str,
    private_key_pem: bytes,
    threshold_t: int,
    threshold_n: int,
    commissioner_ids: Sequence[str] | None = None,
) -> tuple[TaBlob, CommissionerSet]:
    """Protect the TA private key and distribute the wrapping key as Shamir shares."""

    _require_identifier(election_id)
    _require_private_key_bytes(private_key_pem)
    _require_threshold(threshold_t, threshold_n)

    wrapping_key = os.urandom(WRAPPING_KEY_SIZE)
    blob = protect_ta_private_key(
        election_id=election_id,
        private_key_pem=private_key_pem,
        wrapping_key=wrapping_key,
        threshold_t=threshold_t,
        threshold_n=threshold_n,
        context=BLOB_TA_CONTEXT,
    )
    shamir_shares = split_secret(wrapping_key, threshold_t, threshold_n)
    commissioner_set = CommissionerSet.from_shares(election_id, shamir_shares, commissioner_ids)
    return blob, commissioner_set


def open_protected_blob(blob: TaBlob, shares: Sequence[CommissionerShare]) -> bytes:
    """Open ``blobTA`` after reconstructing ``Kwrap`` from at least ``t`` valid shares."""

    if not isinstance(blob, TaBlob):
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
    shamir_shares = _extract_shamir_shares(blob, shares)
    wrapping_key = reconstruct_secret(shamir_shares, blob.threshold_t)
    return open_ta_private_key(blob, wrapping_key)


def _extract_shamir_shares(blob: TaBlob, shares: Sequence[CommissionerShare]) -> tuple[ShamirShare, ...]:
    if not isinstance(shares, Sequence) or isinstance(shares, (bytes, bytearray, str)):
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)

    extracted: list[ShamirShare] = []
    commissioner_ids: set[str] = set()
    share_x_values: set[int] = set()
    for item in shares:
        if not isinstance(item, CommissionerShare):
            raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
        if (
            item.election_id != blob.election_id
            or item.commissioner_id in commissioner_ids
            or item.share.x in share_x_values
        ):
            raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
        commissioner_ids.add(item.commissioner_id)
        share_x_values.add(item.share.x)
        extracted.append(item.share)
    return tuple(extracted)


def _require_identifier(value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)


def _require_private_key_bytes(value: bytes) -> None:
    if not isinstance(value, bytes) or len(value) == 0:
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
    "BLOB_TA_AAD_CONTEXT",
    "BLOB_TA_CONTEXT",
    "TaBlob",
    "TallyingAuthority",
    "blob_ta_aad",
    "create_protected_blob",
    "open_protected_blob",
]
