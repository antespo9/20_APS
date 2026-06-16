"""Public verification utilities for logs, receipts and tally results."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from evoting.actors.bulletin_board import (
    BoardLogRecord,
    ballot_rid,
    chain_link_hash,
    entry_hash,
    genesis_hash,
    verify_ballot_signature,
    verify_close_state,
    verify_receipt,
)
from evoting.actors.registration_authority import verify_authorization
from evoting.crypto.hashes import SHA256_DIGEST_SIZE
from evoting.crypto.signatures import load_signature_public_key, verify_signature
from evoting.errors import EvotingError
from evoting.models import (
    Ack,
    AuthorizationRequest,
    BoardEntry,
    BoardEntryType,
    CloseEntry,
    CloseState,
    ElectionParams,
    TallyResult,
    VotePackage,
)
from evoting.serialization import canonical_bytes


PUBLIC_VERIFICATION_ERROR_MESSAGE = "public verification failed"


class PublicVerificationError(EvotingError):
    """Raised when a public verification input is not a valid protocol state."""


@dataclass(frozen=True, slots=True)
class PublicLogState:
    genesis_hash: bytes
    h_close: bytes
    close_index: int
    final_ballot_entries: tuple[BoardEntry, ...]
    final_record_indices: tuple[int, ...]


def validate_public_log(
    params: ElectionParams,
    records: Sequence[BoardLogRecord],
    close_state: CloseState,
    *,
    genesis_hash_value: bytes | None = None,
) -> PublicLogState:
    """Validate the public Bulletin Board log and reconstruct final ballots."""

    try:
        if not isinstance(params, ElectionParams) or not isinstance(close_state, CloseState):
            raise PublicVerificationError(PUBLIC_VERIFICATION_ERROR_MESSAGE)
        if close_state.election_id != params.election_id:
            raise PublicVerificationError(PUBLIC_VERIFICATION_ERROR_MESSAGE)
        if not verify_close_state(params.pk_bb, close_state):
            raise PublicVerificationError(PUBLIC_VERIFICATION_ERROR_MESSAGE)
        if not isinstance(records, Sequence) or isinstance(records, (bytes, bytearray, str)):
            raise PublicVerificationError(PUBLIC_VERIFICATION_ERROR_MESSAGE)

        expected_genesis_hash = genesis_hash(params) if genesis_hash_value is None else genesis_hash_value
        _require_hash(expected_genesis_hash)
        previous_hash = expected_genesis_hash
        close_record: BoardLogRecord | None = None
        final_by_pseudonym: dict[bytes, tuple[int, BoardEntry]] = {}
        next_version_by_pseudonym: dict[bytes, int] = {}
        pk_by_pseudonym: dict[bytes, bytes] = {}
        seen_rids: set[bytes] = set()

        for expected_index, record in enumerate(records, start=1):
            if not isinstance(record, BoardLogRecord):
                raise PublicVerificationError(PUBLIC_VERIFICATION_ERROR_MESSAGE)
            if close_record is not None:
                raise PublicVerificationError(PUBLIC_VERIFICATION_ERROR_MESSAGE)
            if record.index != expected_index or record.previous_hash != previous_hash:
                raise PublicVerificationError(PUBLIC_VERIFICATION_ERROR_MESSAGE)

            current_entry_hash = entry_hash(record.entry)
            if record.entry_hash != current_entry_hash:
                raise PublicVerificationError(PUBLIC_VERIFICATION_ERROR_MESSAGE)
            current_chain_hash = chain_link_hash(
                previous_hash=previous_hash,
                index=record.index,
                entry_hash_value=current_entry_hash,
            )
            if record.chain_hash != current_chain_hash:
                raise PublicVerificationError(PUBLIC_VERIFICATION_ERROR_MESSAGE)

            if isinstance(record.entry, BoardEntry):
                _validate_ballot_record(
                    params=params,
                    record=record,
                    seen_rids=seen_rids,
                    next_version_by_pseudonym=next_version_by_pseudonym,
                    pk_by_pseudonym=pk_by_pseudonym,
                )
                final_by_pseudonym[record.entry.p_i] = (record.index, record.entry)
            elif isinstance(record.entry, CloseEntry):
                if record.entry.type != BoardEntryType.CLOSE or record.entry.election_id != params.election_id:
                    raise PublicVerificationError(PUBLIC_VERIFICATION_ERROR_MESSAGE)
                close_record = record
            else:
                raise PublicVerificationError(PUBLIC_VERIFICATION_ERROR_MESSAGE)

            previous_hash = current_chain_hash

        if close_record is None:
            raise PublicVerificationError(PUBLIC_VERIFICATION_ERROR_MESSAGE)
        if previous_hash != close_state.h_close or close_record.chain_hash != close_state.h_close:
            raise PublicVerificationError(PUBLIC_VERIFICATION_ERROR_MESSAGE)

        ordered_final = tuple(sorted(final_by_pseudonym.values(), key=lambda item: item[0]))
        if len(ordered_final) > params.eligible_count:
            raise PublicVerificationError(PUBLIC_VERIFICATION_ERROR_MESSAGE)
        return PublicLogState(
            genesis_hash=expected_genesis_hash,
            h_close=close_state.h_close,
            close_index=close_record.index,
            final_ballot_entries=tuple(entry for _, entry in ordered_final),
            final_record_indices=tuple(index for index, _ in ordered_final),
        )
    except PublicVerificationError:
        raise
    except Exception as exc:
        raise PublicVerificationError(PUBLIC_VERIFICATION_ERROR_MESSAGE) from exc


def verify_public_log(
    params: ElectionParams,
    records: Sequence[BoardLogRecord],
    close_state: CloseState,
    *,
    genesis_hash_value: bytes | None = None,
) -> bool:
    try:
        validate_public_log(
            params,
            records,
            close_state,
            genesis_hash_value=genesis_hash_value,
        )
    except Exception:
        return False
    return True


def select_final_ballot_entries(
    params: ElectionParams,
    records: Sequence[BoardLogRecord],
    close_state: CloseState,
    *,
    genesis_hash_value: bytes | None = None,
) -> tuple[BoardEntry, ...]:
    """Return the highest valid version per pseudonym from verified public records."""

    return validate_public_log(
        params,
        records,
        close_state,
        genesis_hash_value=genesis_hash_value,
    ).final_ballot_entries


def verify_individual_receipt(
    params: ElectionParams,
    records: Sequence[BoardLogRecord],
    close_state: CloseState,
    receipt: Ack,
    *,
    expected_p_i: bytes | None = None,
    genesis_hash_value: bytes | None = None,
) -> bool:
    """Verify a BB receipt and its inclusion in a verified public log."""

    try:
        validate_public_log(
            params,
            records,
            close_state,
            genesis_hash_value=genesis_hash_value,
        )
        if not isinstance(receipt, Ack):
            return False
        if receipt.election_id != params.election_id or receipt.index < 1 or receipt.index > len(records):
            return False
        record = records[receipt.index - 1]
        if not isinstance(record.entry, BoardEntry):
            return False
        if expected_p_i is not None and record.entry.p_i != expected_p_i:
            return False
        if record.entry.rid != receipt.rid or record.chain_hash != receipt.chain_hash:
            return False
        return verify_receipt(
            params.pk_bb,
            receipt,
            expected_election_id=params.election_id,
            expected_index=record.index,
            expected_rid=record.entry.rid,
            expected_chain_hash=record.chain_hash,
        )
    except Exception:
        return False


def tally_result_message(
    *,
    election_id: str,
    h_close: bytes,
    totals_by_list: Mapping[str, int],
    final_ballot_count: int,
    valid_ballot_count: int,
    anomalous_count: int,
) -> bytes:
    _require_hash(h_close)
    return canonical_bytes(
        {
            "anomalous_count": anomalous_count,
            "election_id": election_id,
            "final_ballot_count": final_ballot_count,
            "h_close": h_close,
            "totals_by_list": dict(totals_by_list),
            "valid_ballot_count": valid_ballot_count,
        }
    )


def tally_result_message_from_result(result: TallyResult) -> bytes:
    if not isinstance(result, TallyResult):
        raise PublicVerificationError(PUBLIC_VERIFICATION_ERROR_MESSAGE)
    return tally_result_message(
        election_id=result.election_id,
        h_close=result.h_close,
        totals_by_list=result.totals_by_list,
        final_ballot_count=result.final_ballot_count,
        valid_ballot_count=result.valid_ballot_count,
        anomalous_count=result.anomalous_count,
    )


def verify_tally_result_signature(public_key_pem: bytes, result: TallyResult) -> bool:
    """Verify the TA RSA-PSS signature over the unsigned tally result."""

    try:
        public_key = load_signature_public_key(public_key_pem)
        return verify_signature(public_key, tally_result_message_from_result(result), result.signature_ta)
    except Exception:
        return False


def verify_tally_result(
    params: ElectionParams,
    records: Sequence[BoardLogRecord],
    close_state: CloseState,
    result: TallyResult,
    *,
    genesis_hash_value: bytes | None = None,
) -> bool:
    """Verify the public consistency of a signed tally result."""

    try:
        log_state = validate_public_log(
            params,
            records,
            close_state,
            genesis_hash_value=genesis_hash_value,
        )
        if not isinstance(result, TallyResult):
            return False
        allowed_codes = tuple(item.code for item in params.lists)
        if result.election_id != params.election_id or result.h_close != log_state.h_close:
            return False
        if set(result.totals_by_list) != set(allowed_codes):
            return False
        if result.final_ballot_count != len(log_state.final_ballot_entries):
            return False
        if result.final_ballot_count > params.eligible_count:
            return False
        if result.valid_ballot_count + result.anomalous_count != result.final_ballot_count:
            return False
        if sum(result.totals_by_list.values()) != result.valid_ballot_count:
            return False
        return verify_tally_result_signature(params.pk_ta_sig, result)
    except Exception:
        return False


def verify_public_election(
    params: ElectionParams,
    records: Sequence[BoardLogRecord],
    close_state: CloseState,
    result: TallyResult,
    *,
    genesis_hash_value: bytes | None = None,
) -> bool:
    """Verify public log state and signed tally-result consistency."""

    return verify_tally_result(
        params,
        records,
        close_state,
        result,
        genesis_hash_value=genesis_hash_value,
    )


def _validate_ballot_record(
    *,
    params: ElectionParams,
    record: BoardLogRecord,
    seen_rids: set[bytes],
    next_version_by_pseudonym: dict[bytes, int],
    pk_by_pseudonym: dict[bytes, bytes],
) -> None:
    entry = record.entry
    if not isinstance(entry, BoardEntry) or entry.type != BoardEntryType.BALLOT:
        raise PublicVerificationError(PUBLIC_VERIFICATION_ERROR_MESSAGE)
    if entry.election_id != params.election_id or entry.v_i > params.vmax:
        raise PublicVerificationError(PUBLIC_VERIFICATION_ERROR_MESSAGE)
    if entry.rid in seen_rids:
        raise PublicVerificationError(PUBLIC_VERIFICATION_ERROR_MESSAGE)

    package = VotePackage(
        c=entry.c,
        p_i=entry.p_i,
        pk_vote_i=entry.pk_vote_i,
        tau_i=entry.tau_i,
        v_i=entry.v_i,
        sigma_i=entry.sigma_i,
    )
    if ballot_rid(params.election_id, package) != entry.rid:
        raise PublicVerificationError(PUBLIC_VERIFICATION_ERROR_MESSAGE)
    request = AuthorizationRequest(
        election_id=params.election_id,
        p_i=entry.p_i,
        pk_vote_i=entry.pk_vote_i,
    )
    if not verify_authorization(params.pk_ra, request, entry.tau_i):
        raise PublicVerificationError(PUBLIC_VERIFICATION_ERROR_MESSAGE)
    if not verify_ballot_signature(params.election_id, package):
        raise PublicVerificationError(PUBLIC_VERIFICATION_ERROR_MESSAGE)

    expected_version = next_version_by_pseudonym.get(entry.p_i)
    if expected_version is None:
        if entry.v_i != 1:
            raise PublicVerificationError(PUBLIC_VERIFICATION_ERROR_MESSAGE)
        pk_by_pseudonym[entry.p_i] = entry.pk_vote_i
    else:
        if entry.pk_vote_i != pk_by_pseudonym[entry.p_i] or entry.v_i != expected_version:
            raise PublicVerificationError(PUBLIC_VERIFICATION_ERROR_MESSAGE)
    next_version_by_pseudonym[entry.p_i] = entry.v_i + 1
    seen_rids.add(entry.rid)


def _require_hash(value: bytes) -> None:
    if not isinstance(value, bytes) or len(value) != SHA256_DIGEST_SIZE:
        raise PublicVerificationError(PUBLIC_VERIFICATION_ERROR_MESSAGE)


__all__ = [
    "PUBLIC_VERIFICATION_ERROR_MESSAGE",
    "PublicLogState",
    "PublicVerificationError",
    "select_final_ballot_entries",
    "tally_result_message",
    "tally_result_message_from_result",
    "validate_public_log",
    "verify_individual_receipt",
    "verify_public_election",
    "verify_public_log",
    "verify_tally_result",
    "verify_tally_result_signature",
]
