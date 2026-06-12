"""Data models for the protocol messages."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import re
from typing import Mapping

from evoting.errors import ModelValidationError


HASH_SIZE_BYTES = 32

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
_LIST_CODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")


class BoardEntryType(StrEnum):
    BALLOT = "BALLOT"
    CLOSE = "CLOSE"


def _validate_identifier(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not _IDENTIFIER_RE.fullmatch(value):
        raise ModelValidationError(f"{field_name} must be a non-empty protocol identifier")


def _validate_list_code(value: str, field_name: str = "code") -> None:
    if not isinstance(value, str) or not _LIST_CODE_RE.fullmatch(value):
        raise ModelValidationError(f"{field_name} must be a non-empty list code")


def _validate_text(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ModelValidationError(f"{field_name} must be non-empty text")


def _validate_positive_int(value: int, field_name: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ModelValidationError(f"{field_name} must be a positive integer")


def _validate_non_negative_int(value: int, field_name: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ModelValidationError(f"{field_name} must be a non-negative integer")


def _validate_timestamp_ms(value: int, field_name: str) -> None:
    _validate_non_negative_int(value, field_name)


def _validate_bytes(value: bytes, field_name: str) -> None:
    if not isinstance(value, bytes) or len(value) == 0:
        raise ModelValidationError(f"{field_name} must be non-empty bytes")


def _validate_hash_bytes(value: bytes, field_name: str) -> None:
    if not isinstance(value, bytes) or len(value) != HASH_SIZE_BYTES:
        raise ModelValidationError(f"{field_name} must be {HASH_SIZE_BYTES} bytes")


def _as_tuple(values: tuple | list, field_name: str) -> tuple:
    if not isinstance(values, (tuple, list)) or len(values) == 0:
        raise ModelValidationError(f"{field_name} must be a non-empty sequence")
    return tuple(values)


@dataclass(frozen=True, slots=True)
class ElectionList:
    code: str
    label: str

    def __post_init__(self) -> None:
        _validate_list_code(self.code)
        _validate_text(self.label, "label")


@dataclass(frozen=True, slots=True)
class ThresholdParams:
    t: int
    n: int

    def __post_init__(self) -> None:
        _validate_positive_int(self.t, "t")
        _validate_positive_int(self.n, "n")
        if self.t > self.n:
            raise ModelValidationError("t must not be greater than n")


@dataclass(frozen=True, slots=True)
class ElectionParams:
    election_id: str
    lists: tuple[ElectionList, ...]
    opens_at_ms: int
    closes_at_ms: int
    eligible_count: int
    pk_ta_enc: bytes
    pk_ta_sig: bytes
    pk_ra: bytes
    pk_bb: bytes
    threshold: ThresholdParams
    vmax: int
    params_hash: bytes | None = None

    def __post_init__(self) -> None:
        _validate_identifier(self.election_id, "election_id")
        lists = _as_tuple(self.lists, "lists")
        if not all(isinstance(item, ElectionList) for item in lists):
            raise ModelValidationError("lists must contain ElectionList values")
        codes = [item.code for item in lists]
        if len(set(codes)) != len(codes):
            raise ModelValidationError("list codes must be unique")
        object.__setattr__(self, "lists", lists)

        _validate_timestamp_ms(self.opens_at_ms, "opens_at_ms")
        _validate_timestamp_ms(self.closes_at_ms, "closes_at_ms")
        if self.opens_at_ms >= self.closes_at_ms:
            raise ModelValidationError("opens_at_ms must be before closes_at_ms")
        _validate_positive_int(self.eligible_count, "eligible_count")
        _validate_bytes(self.pk_ta_enc, "pk_ta_enc")
        _validate_bytes(self.pk_ta_sig, "pk_ta_sig")
        _validate_bytes(self.pk_ra, "pk_ra")
        _validate_bytes(self.pk_bb, "pk_bb")
        if not isinstance(self.threshold, ThresholdParams):
            raise ModelValidationError("threshold must be ThresholdParams")
        _validate_positive_int(self.vmax, "vmax")
        if self.params_hash is not None:
            _validate_hash_bytes(self.params_hash, "params_hash")


@dataclass(frozen=True, slots=True)
class AuthorizationRequest:
    election_id: str
    p_i: bytes
    pk_vote_i: bytes

    def __post_init__(self) -> None:
        _validate_identifier(self.election_id, "election_id")
        _validate_hash_bytes(self.p_i, "p_i")
        _validate_bytes(self.pk_vote_i, "pk_vote_i")


@dataclass(frozen=True, slots=True)
class VoteMessage:
    election_id: str
    p_i: bytes
    c: bytes
    pk_vote_i: bytes
    v_i: int

    def __post_init__(self) -> None:
        _validate_identifier(self.election_id, "election_id")
        _validate_hash_bytes(self.p_i, "p_i")
        _validate_bytes(self.c, "c")
        _validate_bytes(self.pk_vote_i, "pk_vote_i")
        _validate_positive_int(self.v_i, "v_i")


@dataclass(frozen=True, slots=True)
class VotePackage:
    c: bytes
    p_i: bytes
    pk_vote_i: bytes
    tau_i: bytes
    v_i: int
    sigma_i: bytes

    def __post_init__(self) -> None:
        _validate_bytes(self.c, "c")
        _validate_hash_bytes(self.p_i, "p_i")
        _validate_bytes(self.pk_vote_i, "pk_vote_i")
        _validate_bytes(self.tau_i, "tau_i")
        _validate_positive_int(self.v_i, "v_i")
        _validate_bytes(self.sigma_i, "sigma_i")


@dataclass(frozen=True, slots=True)
class BoardEntry:
    type: BoardEntryType
    election_id: str
    c: bytes
    p_i: bytes
    pk_vote_i: bytes
    tau_i: bytes
    v_i: int
    sigma_i: bytes
    rid: bytes
    timestamp_ms: int

    def __post_init__(self) -> None:
        if not isinstance(self.type, BoardEntryType) or self.type != BoardEntryType.BALLOT:
            raise ModelValidationError("BoardEntry type must be BALLOT")
        _validate_identifier(self.election_id, "election_id")
        _validate_bytes(self.c, "c")
        _validate_hash_bytes(self.p_i, "p_i")
        _validate_bytes(self.pk_vote_i, "pk_vote_i")
        _validate_bytes(self.tau_i, "tau_i")
        _validate_positive_int(self.v_i, "v_i")
        _validate_bytes(self.sigma_i, "sigma_i")
        _validate_hash_bytes(self.rid, "rid")
        _validate_timestamp_ms(self.timestamp_ms, "timestamp_ms")


@dataclass(frozen=True, slots=True)
class CloseEntry:
    type: BoardEntryType
    election_id: str
    timestamp_ms: int

    def __post_init__(self) -> None:
        if not isinstance(self.type, BoardEntryType) or self.type != BoardEntryType.CLOSE:
            raise ModelValidationError("CloseEntry type must be CLOSE")
        _validate_identifier(self.election_id, "election_id")
        _validate_timestamp_ms(self.timestamp_ms, "timestamp_ms")


@dataclass(frozen=True, slots=True)
class Ack:
    election_id: str
    index: int
    rid: bytes
    chain_hash: bytes
    signature_bb: bytes

    def __post_init__(self) -> None:
        _validate_identifier(self.election_id, "election_id")
        _validate_non_negative_int(self.index, "index")
        _validate_hash_bytes(self.rid, "rid")
        _validate_hash_bytes(self.chain_hash, "chain_hash")
        _validate_bytes(self.signature_bb, "signature_bb")


@dataclass(frozen=True, slots=True)
class CloseState:
    election_id: str
    h_close: bytes
    signature_bb: bytes

    def __post_init__(self) -> None:
        _validate_identifier(self.election_id, "election_id")
        _validate_hash_bytes(self.h_close, "h_close")
        _validate_bytes(self.signature_bb, "signature_bb")


@dataclass(frozen=True, slots=True)
class TallyResult:
    election_id: str
    h_close: bytes
    totals_by_list: Mapping[str, int]
    anomalous_count: int
    signature_ta: bytes

    def __post_init__(self) -> None:
        _validate_identifier(self.election_id, "election_id")
        _validate_hash_bytes(self.h_close, "h_close")
        if not isinstance(self.totals_by_list, Mapping) or not self.totals_by_list:
            raise ModelValidationError("totals_by_list must be a non-empty mapping")
        normalized_totals: dict[str, int] = {}
        for code, total in self.totals_by_list.items():
            _validate_list_code(code, "totals_by_list key")
            _validate_non_negative_int(total, f"total for {code}")
            normalized_totals[code] = total
        object.__setattr__(self, "totals_by_list", normalized_totals)
        _validate_non_negative_int(self.anomalous_count, "anomalous_count")
        _validate_bytes(self.signature_ta, "signature_ta")
