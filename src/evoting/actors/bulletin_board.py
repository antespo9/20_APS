"""Bulletin Board validation, append-only log and receipts."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
import time

from cryptography.hazmat.primitives.asymmetric import rsa

from evoting.actors.registration_authority import verify_authorization
from evoting.crypto.hashes import SHA256_DIGEST_SIZE, sha256_digest
from evoting.crypto.signatures import (
    load_signature_private_key,
    load_signature_public_key,
    sign_message,
    verify_signature,
)
from evoting.errors import EvotingError
from evoting.models import (
    Ack,
    AuthorizationRequest,
    BoardEntry,
    BoardEntryType,
    CloseEntry,
    CloseState,
    ElectionParams,
    VoteMessage,
    VotePackage,
)
from evoting.serialization import canonical_bytes


BULLETIN_BOARD_ERROR_MESSAGE = "bulletin board validation failed"
BB_GENESIS_CONTEXT = "BB-GENESIS"


class BulletinBoardError(EvotingError):
    """Raised when the Bulletin Board refuses a protocol operation."""


@dataclass(frozen=True, slots=True)
class BoardLogRecord:
    index: int
    previous_hash: bytes
    entry: BoardEntry | CloseEntry
    entry_hash: bytes
    chain_hash: bytes

    def __post_init__(self) -> None:
        _require_positive_int(self.index)
        _require_hash(self.previous_hash)
        if not isinstance(self.entry, (BoardEntry, CloseEntry)):
            raise BulletinBoardError(BULLETIN_BOARD_ERROR_MESSAGE)
        _require_hash(self.entry_hash)
        _require_hash(self.chain_hash)


class BulletinBoard:
    """Local simulated append-only Bulletin Board."""

    def __init__(
        self,
        params: ElectionParams,
        private_key: rsa.RSAPrivateKey | bytes,
        *,
        clock_ms: Callable[[], int] | None = None,
    ) -> None:
        if not isinstance(params, ElectionParams):
            raise BulletinBoardError(BULLETIN_BOARD_ERROR_MESSAGE)
        if isinstance(private_key, bytes):
            loaded_private_key = load_signature_private_key(private_key)
        else:
            loaded_private_key = private_key
        if not isinstance(loaded_private_key, rsa.RSAPrivateKey):
            raise BulletinBoardError(BULLETIN_BOARD_ERROR_MESSAGE)
        self.params = params
        self._private_key = loaded_private_key
        self._clock_ms = _utc_now_ms if clock_ms is None else clock_ms
        self._records: list[BoardLogRecord] = []
        self._latest_by_pseudonym: dict[bytes, BoardEntry] = {}
        self._seen_package_digests: set[bytes] = set()
        self._genesis_hash = genesis_hash(params)
        self._current_hash = self._genesis_hash
        self._close_state: CloseState | None = None

    @property
    def genesis_hash(self) -> bytes:
        return self._genesis_hash

    @property
    def current_hash(self) -> bytes:
        return self._current_hash

    @property
    def records(self) -> tuple[BoardLogRecord, ...]:
        return tuple(self._records)

    @property
    def entries(self) -> tuple[BoardEntry | CloseEntry, ...]:
        return tuple(record.entry for record in self._records)

    @property
    def chain_hashes(self) -> tuple[bytes, ...]:
        return tuple(record.chain_hash for record in self._records)

    @property
    def close_state(self) -> CloseState | None:
        return self._close_state

    @property
    def is_closed(self) -> bool:
        return self._close_state is not None

    def submit_vote(self, package: VotePackage, *, now_ms: int | None = None) -> Ack:
        """Validate, append and acknowledge a vote package."""

        timestamp_ms = self._resolve_now_ms(now_ms)
        self._validate_vote_package(package, timestamp_ms)
        rid = ballot_rid(self.params.election_id, package)
        entry = BoardEntry(
            type=BoardEntryType.BALLOT,
            election_id=self.params.election_id,
            c=package.c,
            p_i=package.p_i,
            pk_vote_i=package.pk_vote_i,
            tau_i=package.tau_i,
            v_i=package.v_i,
            sigma_i=package.sigma_i,
            rid=rid,
            timestamp_ms=timestamp_ms,
        )
        record = self._append_entry(entry)
        package_digest = sha256_digest(canonical_bytes(package))
        self._seen_package_digests.add(package_digest)
        self._latest_by_pseudonym[package.p_i] = entry
        signature = sign_message(
            self._private_key,
            receipt_message(
                election_id=self.params.election_id,
                index=record.index,
                rid=rid,
                chain_hash=record.chain_hash,
            ),
        )
        return Ack(
            election_id=self.params.election_id,
            index=record.index,
            rid=rid,
            chain_hash=record.chain_hash,
            signature_bb=signature,
        )

    def verify_receipt(self, receipt: Ack) -> bool:
        if not isinstance(receipt, Ack) or receipt.index < 1 or receipt.index > len(self._records):
            return False
        record = self._records[receipt.index - 1]
        if not isinstance(record.entry, BoardEntry):
            return False
        return verify_receipt(
            self.params.pk_bb,
            receipt,
            expected_election_id=self.params.election_id,
            expected_index=record.index,
            expected_rid=record.entry.rid,
            expected_chain_hash=record.chain_hash,
        )

    def verify_hash_chain(self) -> bool:
        return verify_log_records(
            genesis_hash_value=self._genesis_hash,
            records=self.records,
            expected_final_hash=self._close_state.h_close if self._close_state is not None else self._current_hash,
        )

    def close(self, *, now_ms: int | None = None) -> CloseState:
        """Append the CLOSE event and sign the final chain state exactly once."""

        if self._close_state is not None:
            raise BulletinBoardError(BULLETIN_BOARD_ERROR_MESSAGE)
        timestamp_ms = self._resolve_now_ms(now_ms)
        if timestamp_ms < self.params.closes_at_ms:
            raise BulletinBoardError(BULLETIN_BOARD_ERROR_MESSAGE)
        close_entry = CloseEntry(
            type=BoardEntryType.CLOSE,
            election_id=self.params.election_id,
            timestamp_ms=timestamp_ms,
        )
        record = self._append_entry(close_entry)
        signature = sign_message(
            self._private_key,
            close_state_message(election_id=self.params.election_id, h_close=record.chain_hash),
        )
        self._close_state = CloseState(
            election_id=self.params.election_id,
            h_close=record.chain_hash,
            signature_bb=signature,
        )
        return self._close_state

    def final_ballot_entries(self) -> tuple[BoardEntry, ...]:
        """Return only the highest-version ballot entry for each pseudonym after CLOSE."""

        if self._close_state is None:
            raise BulletinBoardError(BULLETIN_BOARD_ERROR_MESSAGE)
        latest: dict[bytes, tuple[int, BoardEntry]] = {}
        for record in self._records:
            if isinstance(record.entry, CloseEntry):
                break
            entry = record.entry
            current = latest.get(entry.p_i)
            if current is None or entry.v_i > current[1].v_i:
                latest[entry.p_i] = (record.index, entry)
        return tuple(entry for _, entry in sorted(latest.values(), key=lambda item: item[0]))

    def _append_entry(self, entry: BoardEntry | CloseEntry) -> BoardLogRecord:
        index = len(self._records) + 1
        previous_hash = self._current_hash
        digest = entry_hash(entry)
        chain_hash = chain_link_hash(
            previous_hash=previous_hash,
            index=index,
            entry_hash_value=digest,
        )
        record = BoardLogRecord(
            index=index,
            previous_hash=previous_hash,
            entry=entry,
            entry_hash=digest,
            chain_hash=chain_hash,
        )
        self._records.append(record)
        self._current_hash = chain_hash
        return record

    def _validate_vote_package(self, package: VotePackage, now_ms: int) -> None:
        if not isinstance(package, VotePackage):
            raise BulletinBoardError(BULLETIN_BOARD_ERROR_MESSAGE)
        if self._close_state is not None or not _is_open(self.params, now_ms):
            raise BulletinBoardError(BULLETIN_BOARD_ERROR_MESSAGE)
        if package.v_i > self.params.vmax:
            raise BulletinBoardError(BULLETIN_BOARD_ERROR_MESSAGE)

        package_digest = sha256_digest(canonical_bytes(package))
        if package_digest in self._seen_package_digests:
            raise BulletinBoardError(BULLETIN_BOARD_ERROR_MESSAGE)

        authorization = AuthorizationRequest(
            election_id=self.params.election_id,
            p_i=package.p_i,
            pk_vote_i=package.pk_vote_i,
        )
        try:
            authorization_valid = verify_authorization(self.params.pk_ra, authorization, package.tau_i)
            signature_valid = verify_ballot_signature(self.params.election_id, package)
        except Exception as exc:
            raise BulletinBoardError(BULLETIN_BOARD_ERROR_MESSAGE) from exc
        if not authorization_valid or not signature_valid:
            raise BulletinBoardError(BULLETIN_BOARD_ERROR_MESSAGE)

        latest = self._latest_by_pseudonym.get(package.p_i)
        if latest is None:
            if package.v_i != 1:
                raise BulletinBoardError(BULLETIN_BOARD_ERROR_MESSAGE)
            return
        if package.pk_vote_i != latest.pk_vote_i:
            raise BulletinBoardError(BULLETIN_BOARD_ERROR_MESSAGE)
        if package.v_i != latest.v_i + 1:
            raise BulletinBoardError(BULLETIN_BOARD_ERROR_MESSAGE)

    def _resolve_now_ms(self, now_ms: int | None) -> int:
        selected = self._clock_ms() if now_ms is None else now_ms
        if not isinstance(selected, int) or isinstance(selected, bool) or selected < 0:
            raise BulletinBoardError(BULLETIN_BOARD_ERROR_MESSAGE)
        return selected


def ballot_message(election_id: str, package: VotePackage) -> bytes:
    if not isinstance(package, VotePackage):
        raise BulletinBoardError(BULLETIN_BOARD_ERROR_MESSAGE)
    return canonical_bytes(
        VoteMessage(
            election_id=election_id,
            p_i=package.p_i,
            c=package.c,
            pk_vote_i=package.pk_vote_i,
            v_i=package.v_i,
        )
    )


def verify_ballot_signature(election_id: str, package: VotePackage) -> bool:
    if not isinstance(package, VotePackage):
        raise BulletinBoardError(BULLETIN_BOARD_ERROR_MESSAGE)
    public_key = load_signature_public_key(package.pk_vote_i)
    return verify_signature(public_key, ballot_message(election_id, package), package.sigma_i)


def ballot_rid(election_id: str, package: VotePackage) -> bytes:
    if not isinstance(package, VotePackage):
        raise BulletinBoardError(BULLETIN_BOARD_ERROR_MESSAGE)
    return sha256_digest(
        canonical_bytes(
            {
                "c": package.c,
                "election_id": election_id,
                "p_i": package.p_i,
                "pk_vote_i": package.pk_vote_i,
                "sigma_i": package.sigma_i,
                "v_i": package.v_i,
            }
        )
    )


def receipt_message(*, election_id: str, index: int, rid: bytes, chain_hash: bytes) -> bytes:
    _require_positive_int(index)
    _require_hash(rid)
    _require_hash(chain_hash)
    return canonical_bytes(
        {
            "chain_hash": chain_hash,
            "election_id": election_id,
            "index": index,
            "rid": rid,
        }
    )


def verify_receipt(
    public_key_pem: bytes,
    receipt: Ack,
    *,
    expected_election_id: str | None = None,
    expected_index: int | None = None,
    expected_rid: bytes | None = None,
    expected_chain_hash: bytes | None = None,
) -> bool:
    if not isinstance(receipt, Ack):
        raise BulletinBoardError(BULLETIN_BOARD_ERROR_MESSAGE)
    if expected_election_id is not None and receipt.election_id != expected_election_id:
        return False
    if expected_index is not None and receipt.index != expected_index:
        return False
    if expected_rid is not None and receipt.rid != expected_rid:
        return False
    if expected_chain_hash is not None and receipt.chain_hash != expected_chain_hash:
        return False
    public_key = load_signature_public_key(public_key_pem)
    return verify_signature(
        public_key,
        receipt_message(
            election_id=receipt.election_id,
            index=receipt.index,
            rid=receipt.rid,
            chain_hash=receipt.chain_hash,
        ),
        receipt.signature_bb,
    )


def close_state_message(*, election_id: str, h_close: bytes) -> bytes:
    _require_hash(h_close)
    return canonical_bytes({"election_id": election_id, "h_close": h_close})


def verify_close_state(public_key_pem: bytes, close_state: CloseState) -> bool:
    if not isinstance(close_state, CloseState):
        raise BulletinBoardError(BULLETIN_BOARD_ERROR_MESSAGE)
    public_key = load_signature_public_key(public_key_pem)
    return verify_signature(
        public_key,
        close_state_message(election_id=close_state.election_id, h_close=close_state.h_close),
        close_state.signature_bb,
    )


def public_params_hash(params: ElectionParams) -> bytes:
    if not isinstance(params, ElectionParams):
        raise BulletinBoardError(BULLETIN_BOARD_ERROR_MESSAGE)
    return sha256_digest(
        canonical_bytes(
            {
                "closes_at_ms": params.closes_at_ms,
                "election_id": params.election_id,
                "eligible_count": params.eligible_count,
                "lists": params.lists,
                "opens_at_ms": params.opens_at_ms,
                "pk_bb": params.pk_bb,
                "pk_ra": params.pk_ra,
                "pk_ta_enc": params.pk_ta_enc,
                "pk_ta_sig": params.pk_ta_sig,
                "threshold": params.threshold,
                "vmax": params.vmax,
            }
        )
    )


def genesis_hash(params: ElectionParams) -> bytes:
    return sha256_digest(
        canonical_bytes(
            {
                "context": BB_GENESIS_CONTEXT,
                "election_id": params.election_id,
                "params_hash": public_params_hash(params),
            }
        )
    )


def entry_hash(entry: BoardEntry | CloseEntry) -> bytes:
    if not isinstance(entry, (BoardEntry, CloseEntry)):
        raise BulletinBoardError(BULLETIN_BOARD_ERROR_MESSAGE)
    return sha256_digest(canonical_bytes(entry))


def chain_link_hash(*, previous_hash: bytes, index: int, entry_hash_value: bytes) -> bytes:
    _require_hash(previous_hash)
    _require_positive_int(index)
    _require_hash(entry_hash_value)
    return sha256_digest(
        canonical_bytes(
            {
                "entry_hash": entry_hash_value,
                "index": index,
                "previous_hash": previous_hash,
            }
        )
    )


def verify_log_records(
    *,
    genesis_hash_value: bytes,
    records: Sequence[BoardLogRecord],
    expected_final_hash: bytes | None = None,
) -> bool:
    _require_hash(genesis_hash_value)
    if not isinstance(records, Sequence) or isinstance(records, (bytes, bytearray, str)):
        raise BulletinBoardError(BULLETIN_BOARD_ERROR_MESSAGE)

    previous_hash = genesis_hash_value
    close_seen = False
    for expected_index, record in enumerate(records, start=1):
        if not isinstance(record, BoardLogRecord):
            return False
        if close_seen:
            return False
        if record.index != expected_index or record.previous_hash != previous_hash:
            return False
        recalculated_entry_hash = entry_hash(record.entry)
        if record.entry_hash != recalculated_entry_hash:
            return False
        recalculated_chain_hash = chain_link_hash(
            previous_hash=previous_hash,
            index=record.index,
            entry_hash_value=recalculated_entry_hash,
        )
        if record.chain_hash != recalculated_chain_hash:
            return False
        previous_hash = recalculated_chain_hash
        close_seen = isinstance(record.entry, CloseEntry)

    if expected_final_hash is not None and previous_hash != expected_final_hash:
        return False
    return True


def _is_open(params: ElectionParams, now_ms: int) -> bool:
    return params.opens_at_ms <= now_ms < params.closes_at_ms


def _utc_now_ms() -> int:
    return time.time_ns() // 1_000_000


def _require_hash(value: bytes) -> None:
    if not isinstance(value, bytes) or len(value) != SHA256_DIGEST_SIZE:
        raise BulletinBoardError(BULLETIN_BOARD_ERROR_MESSAGE)


def _require_positive_int(value: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise BulletinBoardError(BULLETIN_BOARD_ERROR_MESSAGE)


__all__ = [
    "BB_GENESIS_CONTEXT",
    "BULLETIN_BOARD_ERROR_MESSAGE",
    "BoardLogRecord",
    "BulletinBoard",
    "BulletinBoardError",
    "ballot_message",
    "ballot_rid",
    "chain_link_hash",
    "close_state_message",
    "entry_hash",
    "genesis_hash",
    "public_params_hash",
    "receipt_message",
    "verify_ballot_signature",
    "verify_close_state",
    "verify_log_records",
    "verify_receipt",
]
