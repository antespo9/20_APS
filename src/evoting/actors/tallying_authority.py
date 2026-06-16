"""Tallying Authority blob protection for Milestone 3."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
import os
import re

from evoting.actors.commissioners import CommissionerSet, CommissionerShare
from evoting.actors.verifier import (
    PublicVerificationError,
    tally_result_message,
    validate_public_log,
    verify_tally_result_signature,
)
from evoting.actors.bulletin_board import BoardLogRecord
from evoting.crypto.encryption import decrypt_vote, load_encryption_private_key
from evoting.crypto.ta_blob import (
    BLOB_TA_AAD_CONTEXT,
    BLOB_TA_CONTEXT,
    TaBlob,
    blob_ta_aad,
    open_ta_private_key,
    protect_ta_private_key,
)
from evoting.crypto.shamir import WRAPPING_KEY_SIZE, ShamirShare, reconstruct_secret, split_secret
from evoting.crypto.signatures import load_signature_private_key, sign_message
from evoting.errors import CRYPTOGRAPHIC_ERROR_MESSAGE, CryptographicError, EvotingError
from evoting.models import BoardEntry, CloseState, ElectionParams, TallyResult


TALLY_ERROR_MESSAGE = "tallying authority operation failed"
_LIST_CODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")


class TallyingAuthorityError(EvotingError):
    """Raised when tallying cannot proceed because global preconditions failed."""


class BallotAnomalyCode(StrEnum):
    MALFORMED_CIPHERTEXT = "MALFORMED_CIPHERTEXT"
    DECRYPTION_FAILED = "DECRYPTION_FAILED"
    UNDECODABLE_PLAINTEXT = "UNDECODABLE_PLAINTEXT"
    INVALID_PLAINTEXT_FORMAT = "INVALID_PLAINTEXT_FORMAT"
    LIST_CODE_OUT_OF_DOMAIN = "LIST_CODE_OUT_OF_DOMAIN"


@dataclass(frozen=True, slots=True)
class AnomalousBallot:
    rid: bytes
    code: BallotAnomalyCode


@dataclass(frozen=True, slots=True)
class TallyReport:
    result: TallyResult
    anomalies: tuple[AnomalousBallot, ...]


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

    def tally(
        self,
        *,
        params: ElectionParams,
        records: Sequence[BoardLogRecord],
        close_state: CloseState,
        blob: TaBlob,
        shares: Sequence[CommissionerShare],
        signing_private_key: object,
    ) -> TallyReport:
        if not isinstance(params, ElectionParams):
            raise TallyingAuthorityError(TALLY_ERROR_MESSAGE)
        if params.election_id != self.election_id:
            raise TallyingAuthorityError(TALLY_ERROR_MESSAGE)
        if params.threshold.t != self.threshold_t or params.threshold.n != self.threshold_n:
            raise TallyingAuthorityError(TALLY_ERROR_MESSAGE)
        return tally_election(
            params=params,
            records=records,
            close_state=close_state,
            blob=blob,
            shares=shares,
            signing_private_key=signing_private_key,
        )


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


def tally_election(
    *,
    params: ElectionParams,
    records: Sequence[BoardLogRecord],
    close_state: CloseState,
    blob: TaBlob,
    shares: Sequence[CommissionerShare],
    signing_private_key: object,
) -> TallyReport:
    """Perform tallying after public log validation and authenticated ``blobTA`` opening."""

    try:
        if not isinstance(params, ElectionParams) or not isinstance(blob, TaBlob):
            raise TallyingAuthorityError(TALLY_ERROR_MESSAGE)
        if blob.election_id != params.election_id:
            raise TallyingAuthorityError(TALLY_ERROR_MESSAGE)
        if blob.threshold_t != params.threshold.t or blob.threshold_n != params.threshold.n:
            raise TallyingAuthorityError(TALLY_ERROR_MESSAGE)
        log_state = validate_public_log(params, records, close_state)
        if not isinstance(shares, Sequence) or isinstance(shares, (bytes, bytearray, str)):
            raise TallyingAuthorityError(TALLY_ERROR_MESSAGE)
        if len(shares) < blob.threshold_t:
            raise TallyingAuthorityError(TALLY_ERROR_MESSAGE)
        private_key_pem = open_protected_blob(blob, shares)
        decryption_key = load_encryption_private_key(private_key_pem)
        signing_key = (
            load_signature_private_key(signing_private_key)
            if isinstance(signing_private_key, bytes)
            else signing_private_key
        )
    except (PublicVerificationError, CryptographicError, TallyingAuthorityError) as exc:
        raise TallyingAuthorityError(TALLY_ERROR_MESSAGE) from exc
    except Exception as exc:
        raise TallyingAuthorityError(TALLY_ERROR_MESSAGE) from exc

    allowed_codes = tuple(item.code for item in params.lists)
    totals = {code: 0 for code in allowed_codes}
    anomalies: list[AnomalousBallot] = []

    for entry in log_state.final_ballot_entries:
        classification = _decrypt_and_classify(entry, decryption_key, allowed_codes)
        if isinstance(classification, BallotAnomalyCode):
            anomalies.append(AnomalousBallot(rid=entry.rid, code=classification))
        else:
            totals[classification] += 1

    final_ballot_count = len(log_state.final_ballot_entries)
    valid_ballot_count = sum(totals.values())
    anomalous_count = len(anomalies)
    try:
        signature = sign_message(
            signing_key,
            tally_result_message(
                election_id=params.election_id,
                h_close=log_state.h_close,
                totals_by_list=totals,
                final_ballot_count=final_ballot_count,
                valid_ballot_count=valid_ballot_count,
                anomalous_count=anomalous_count,
            ),
        )
        result = TallyResult(
            election_id=params.election_id,
            h_close=log_state.h_close,
            totals_by_list=totals,
            anomalous_count=anomalous_count,
            signature_ta=signature,
            final_ballot_count=final_ballot_count,
            valid_ballot_count=valid_ballot_count,
        )
    except Exception as exc:
        raise TallyingAuthorityError(TALLY_ERROR_MESSAGE) from exc
    return TallyReport(result=result, anomalies=tuple(anomalies))


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


def _decrypt_and_classify(entry: BoardEntry, private_key: object, allowed_codes: Sequence[str]) -> str | BallotAnomalyCode:
    expected_ciphertext_size = private_key.key_size // 8
    if not isinstance(entry.c, bytes) or len(entry.c) != expected_ciphertext_size:
        return BallotAnomalyCode.MALFORMED_CIPHERTEXT
    try:
        plaintext = decrypt_vote(private_key, entry.c)
    except CryptographicError:
        return BallotAnomalyCode.DECRYPTION_FAILED
    try:
        decoded = plaintext.decode("utf-8")
    except UnicodeDecodeError:
        return BallotAnomalyCode.UNDECODABLE_PLAINTEXT
    if not _LIST_CODE_RE.fullmatch(decoded):
        return BallotAnomalyCode.INVALID_PLAINTEXT_FORMAT
    if decoded not in allowed_codes:
        return BallotAnomalyCode.LIST_CODE_OUT_OF_DOMAIN
    return decoded


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
    "AnomalousBallot",
    "BallotAnomalyCode",
    "BLOB_TA_AAD_CONTEXT",
    "BLOB_TA_CONTEXT",
    "TaBlob",
    "TALLY_ERROR_MESSAGE",
    "TallyReport",
    "TallyingAuthority",
    "TallyingAuthorityError",
    "blob_ta_aad",
    "create_protected_blob",
    "open_protected_blob",
    "tally_election",
    "verify_tally_result_signature",
]
