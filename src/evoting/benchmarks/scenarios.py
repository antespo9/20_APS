"""Benchmark scenarios for already implemented protocol operations."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
import os
from pathlib import Path
import tempfile
import time

from evoting.actors.bulletin_board import (
    BoardLogRecord,
    BulletinBoard,
    chain_link_hash,
    entry_hash,
    verify_receipt,
)
from evoting.actors.registration_authority import RegistrationAuthority
from evoting.actors.tallying_authority import (
    TaBlob,
    create_protected_blob,
    open_protected_blob,
    tally_election,
)
from evoting.actors.verifier import verify_individual_receipt, verify_public_election
from evoting.actors.voter import (
    PseudonymousVoterState,
    apply_accepted_receipt,
    generate_authorization_material,
    prepare_vote_package,
)
from evoting.benchmarks.models import BenchmarkResult
from evoting.crypto.encryption import (
    encrypt_vote,
    encryption_private_key_to_pem,
    encryption_public_key_to_pem,
    generate_encryption_private_key,
    load_encryption_public_key,
)
from evoting.crypto.password import ScryptParameters
from evoting.crypto.shamir import WRAPPING_KEY_SIZE, reconstruct_secret, split_secret
from evoting.crypto.signatures import (
    generate_signature_private_key,
    load_signature_private_key,
    sign_message,
    signature_public_key_to_pem,
)
from evoting.models import Ack, ElectionList, ElectionParams, ThresholdParams, VoteMessage, VotePackage
from evoting.serialization import canonical_bytes


ELECTION_ID = "benchmark-election-2026"
OPEN_MS = 1_800_000_000_000
LISTS = (
    ElectionList(code="LIST-001", label="Lista Alfa"),
    ElectionList(code="LIST-002", label="Lista Beta"),
    ElectionList(code="LIST-003", label="Lista Gamma"),
)
LIST_CODES = tuple(item.code for item in LISTS)
PASSWORD = b"benchmark-password"
FAST_SCRYPT = ScryptParameters(n=2**4, r=1, p=1, length=32)


@dataclass(frozen=True, slots=True)
class BenchmarkProfile:
    name: str
    warmups: int
    repetitions: int
    public_verification_scales: tuple[int, ...]
    tally_scale: int
    scrypt_parameters: ScryptParameters


@dataclass(frozen=True, slots=True)
class AuthorizedFixture:
    params: ElectionParams
    state: PseudonymousVoterState
    board_key: object
    ta_encryption_key: object
    ta_signature_key: object
    blob: TaBlob
    commissioner_shares: tuple[object, ...]


@dataclass(frozen=True, slots=True)
class ClosedElectionFixture:
    params: ElectionParams
    records: tuple[BoardLogRecord, ...]
    close_state: object
    report: object
    receipt: Ack
    blob: TaBlob
    commissioner_shares: tuple[object, ...]
    ta_signature_key: object


PROFILES = {
    "smoke": BenchmarkProfile(
        name="smoke",
        warmups=0,
        repetitions=1,
        public_verification_scales=(1, 3),
        tally_scale=2,
        scrypt_parameters=FAST_SCRYPT,
    ),
    "full": BenchmarkProfile(
        name="full",
        warmups=1,
        repetitions=5,
        public_verification_scales=(1, 3, 10, 25),
        tally_scale=10,
        scrypt_parameters=ScryptParameters(),
    ),
}


def run_benchmark_profile(profile_name: str) -> list[BenchmarkResult]:
    """Run one benchmark profile and return structured aggregate results."""

    try:
        profile = PROFILES[profile_name]
    except KeyError as exc:
        raise ValueError(f"unknown benchmark profile: {profile_name}") from exc

    with tempfile.TemporaryDirectory(prefix="evoting-benchmark-") as temp_dir:
        temp_path = Path(temp_dir)
        results = [
            _measure_key_generation("rsa_signature_key_generation", generate_signature_private_key, profile),
            _measure_key_generation("rsa_encryption_key_generation", generate_encryption_private_key, profile),
            _measure_ra_authorization(profile, temp_path),
            _measure_vote_encryption(profile, temp_path),
            _measure_package_signature(profile, temp_path),
            _measure_vote_package_preparation(profile, temp_path),
            _measure_board_acceptance(profile, temp_path),
            _measure_hash_chain_update(profile, temp_path),
            _measure_receipt_verification(profile, temp_path),
            _measure_shamir_split(profile),
            _measure_shamir_reconstruction(profile),
            _measure_blob_create(profile, temp_path),
            _measure_blob_open(profile, temp_path),
            _measure_tally(profile, temp_path, profile.tally_scale),
            _measure_vote_package_size(profile, temp_path),
            _measure_receipt_size(profile, temp_path),
        ]
        for scale in profile.public_verification_scales:
            results.append(_measure_public_verification(profile, temp_path, scale))
        return results


def _measure(
    *,
    operation: str,
    profile: BenchmarkProfile,
    input_size: str,
    input_scale: int,
    measured: Callable[[], object],
    message_size: Callable[[], int] | int = 0,
    notes: str = "",
) -> BenchmarkResult:
    for _ in range(profile.warmups):
        measured()
    samples_ns: list[int] = []
    for _ in range(profile.repetitions):
        started = time.perf_counter_ns()
        measured()
        samples_ns.append(time.perf_counter_ns() - started)
    size = message_size() if callable(message_size) else message_size
    return BenchmarkResult.from_samples(
        operation=operation,
        profile=profile.name,
        input_size=input_size,
        input_scale=input_scale,
        warmups=profile.warmups,
        repetitions=profile.repetitions,
        samples_ns=samples_ns,
        message_size_bytes=size,
        notes=notes,
    )


def _measure_prepared(
    *,
    operation: str,
    profile: BenchmarkProfile,
    input_size: str,
    input_scale: int,
    prepare: Callable[[], Callable[[], object]],
    message_size: Callable[[], int] | int = 0,
    notes: str = "",
) -> BenchmarkResult:
    for _ in range(profile.warmups):
        prepared = prepare()
        prepared()
    samples_ns: list[int] = []
    for _ in range(profile.repetitions):
        prepared = prepare()
        started = time.perf_counter_ns()
        prepared()
        samples_ns.append(time.perf_counter_ns() - started)
    size = message_size() if callable(message_size) else message_size
    return BenchmarkResult.from_samples(
        operation=operation,
        profile=profile.name,
        input_size=input_size,
        input_scale=input_scale,
        warmups=profile.warmups,
        repetitions=profile.repetitions,
        samples_ns=samples_ns,
        message_size_bytes=size,
        notes=notes,
    )


def _measure_key_generation(
    operation: str,
    generator: Callable[[], object],
    profile: BenchmarkProfile,
) -> BenchmarkResult:
    return _measure(
        operation=operation,
        profile=profile,
        input_size="rsa_bits=2048",
        input_scale=2048,
        measured=generator,
        notes="key generation measured separately from voting operations",
    )


def _measure_ra_authorization(profile: BenchmarkProfile, temp_path: Path) -> BenchmarkResult:
    counter = _Counter()

    def prepare() -> Callable[[], bytes]:
        index = counter.next()
        prepared = _prepare_ra_authorization(
            temp_path / f"ra-authorization-{index}",
            scrypt_parameters=profile.scrypt_parameters,
            voter_index=index,
        )
        return prepared

    return _measure_prepared(
        operation="ra_authentication_and_authorization_issue",
        profile=profile,
        input_size=f"scrypt_n={profile.scrypt_parameters.n}",
        input_scale=profile.scrypt_parameters.n,
        prepare=prepare,
        message_size=lambda: len(
            _prepare_ra_authorization(
                temp_path / "ra-authorization-size",
                scrypt_parameters=profile.scrypt_parameters,
                voter_index=999_999,
            )()
        ),
        notes="includes credential verification, authorization signature and RA registry update",
    )


def _measure_vote_encryption(profile: BenchmarkProfile, temp_path: Path) -> BenchmarkResult:
    fixture = _fresh_authorization_fixture(temp_path / "encrypt")
    public_key = load_encryption_public_key(fixture.params.pk_ta_enc)
    plaintext = LIST_CODES[0].encode("utf-8")

    return _measure(
        operation="rsa_oaep_vote_encryption",
        profile=profile,
        input_size=f"plaintext_bytes={len(plaintext)}",
        input_scale=len(plaintext),
        measured=lambda: encrypt_vote(public_key, plaintext),
        message_size=lambda: len(encrypt_vote(public_key, plaintext)),
    )


def _measure_package_signature(profile: BenchmarkProfile, temp_path: Path) -> BenchmarkResult:
    fixture = _fresh_authorization_fixture(temp_path / "signature")
    private_key = load_signature_private_key(fixture.state.sk_vote_i)
    message = canonical_bytes(
        VoteMessage(
            election_id=fixture.state.election_id,
            p_i=fixture.state.p_i,
            c=b"x" * 256,
            pk_vote_i=fixture.state.pk_vote_i,
            v_i=1,
        )
    )

    return _measure(
        operation="rsa_pss_package_signature",
        profile=profile,
        input_size=f"message_bytes={len(message)}",
        input_scale=len(message),
        measured=lambda: sign_message(private_key, message),
        message_size=lambda: len(sign_message(private_key, message)),
    )


def _measure_vote_package_preparation(profile: BenchmarkProfile, temp_path: Path) -> BenchmarkResult:
    fixture = _fresh_authorization_fixture(temp_path / "package-prepare")

    return _measure(
        operation="voter_prepare_vote_package_complete",
        profile=profile,
        input_size="single_vote_package",
        input_scale=1,
        measured=lambda: prepare_vote_package(
            fixture.state,
            LIST_CODES[0],
            allowed_list_codes=LIST_CODES,
            ta_public_key_pem=fixture.params.pk_ta_enc,
        ),
        message_size=lambda: len(
            canonical_bytes(
                prepare_vote_package(
                    fixture.state,
                    LIST_CODES[0],
                    allowed_list_codes=LIST_CODES,
                    ta_public_key_pem=fixture.params.pk_ta_enc,
                )
            )
        ),
        notes="includes public-key loading, RSA-OAEP encryption, private-key loading and RSA-PSS signature",
    )


def _measure_board_acceptance(profile: BenchmarkProfile, temp_path: Path) -> BenchmarkResult:
    counter = _Counter()

    def prepare() -> Callable[[], Ack]:
        fixture = _fresh_authorization_fixture(temp_path / f"bb-accept-{counter.next()}")
        board = BulletinBoard(fixture.params, fixture.board_key)
        package = _package(fixture.state, fixture.params, LIST_CODES[0])
        return lambda: board.submit_vote(package, now_ms=OPEN_MS + 1)

    return _measure_prepared(
        operation="bb_validate_and_accept_vote_package",
        profile=profile,
        input_size="single_vote_package",
        input_scale=1,
        prepare=prepare,
        message_size=lambda: _single_package_size(temp_path / "bb-accept-size"),
        notes="includes BB validation, append-only record creation and receipt signature",
    )


def _measure_hash_chain_update(profile: BenchmarkProfile, temp_path: Path) -> BenchmarkResult:
    closed = _closed_election_fixture(temp_path / "hash-update", voters=1)
    record = closed.records[0]

    return _measure(
        operation="bb_hash_chain_update_only",
        profile=profile,
        input_size="single_entry_hash_link",
        input_scale=1,
        measured=lambda: chain_link_hash(
            previous_hash=record.previous_hash,
            index=record.index,
            entry_hash_value=entry_hash(record.entry),
        ),
        message_size=len(canonical_bytes(record.entry)),
        notes="isolates canonical entry hash and one hash-chain link computation",
    )


def _measure_receipt_verification(profile: BenchmarkProfile, temp_path: Path) -> BenchmarkResult:
    closed = _closed_election_fixture(temp_path / "receipt", voters=1)

    return _measure(
        operation="bb_receipt_verification",
        profile=profile,
        input_size="single_receipt",
        input_scale=1,
        measured=lambda: verify_receipt(
            closed.params.pk_bb,
            closed.receipt,
            expected_election_id=closed.params.election_id,
            expected_index=closed.records[0].index,
            expected_rid=closed.records[0].entry.rid,
            expected_chain_hash=closed.records[0].chain_hash,
        ),
        message_size=len(canonical_bytes(closed.receipt)),
    )


def _measure_shamir_split(profile: BenchmarkProfile) -> BenchmarkResult:
    return _measure(
        operation="shamir_split",
        profile=profile,
        input_size="threshold=3,shares=5,secret_bytes=32",
        input_scale=5,
        measured=lambda: split_secret(os.urandom(WRAPPING_KEY_SIZE), 3, 5),
        message_size=0,
    )


def _measure_shamir_reconstruction(profile: BenchmarkProfile) -> BenchmarkResult:
    secret = os.urandom(WRAPPING_KEY_SIZE)
    shares = split_secret(secret, 3, 5)

    return _measure(
        operation="shamir_reconstruction",
        profile=profile,
        input_size="threshold=3,provided_shares=3",
        input_scale=3,
        measured=lambda: reconstruct_secret(shares[:3], 3),
        message_size=0,
    )


def _measure_blob_create(profile: BenchmarkProfile, temp_path: Path) -> BenchmarkResult:
    fixture = _fresh_authorization_fixture(temp_path / "blob-create")
    private_key_pem = encryption_private_key_to_pem(fixture.ta_encryption_key)

    return _measure(
        operation="blob_ta_create",
        profile=profile,
        input_size=f"private_key_pem_bytes={len(private_key_pem)}",
        input_scale=len(private_key_pem),
        measured=lambda: create_protected_blob(
            election_id=ELECTION_ID,
            private_key_pem=private_key_pem,
            threshold_t=3,
            threshold_n=5,
        ),
        message_size=lambda: _blob_public_size(
            create_protected_blob(
                election_id=ELECTION_ID,
                private_key_pem=private_key_pem,
                threshold_t=3,
                threshold_n=5,
            )[0]
        ),
        notes="protects a pre-generated TA private key and distributes threshold material",
    )


def _measure_blob_open(profile: BenchmarkProfile, temp_path: Path) -> BenchmarkResult:
    fixture = _fresh_authorization_fixture(temp_path / "blob-open")

    return _measure(
        operation="blob_ta_open",
        profile=profile,
        input_size="threshold=3,provided_shares=3",
        input_scale=3,
        measured=lambda: open_protected_blob(fixture.blob, fixture.commissioner_shares[:3]),
        message_size=_blob_public_size(fixture.blob),
        notes="includes threshold reconstruction and authenticated blob opening",
    )


def _measure_tally(profile: BenchmarkProfile, temp_path: Path, voters: int) -> BenchmarkResult:
    closed = _closed_election_fixture(temp_path / f"tally-{voters}", voters=voters)

    return _measure(
        operation="tally",
        profile=profile,
        input_size=f"final_ballots={voters}",
        input_scale=voters,
        measured=lambda: tally_election(
            params=closed.params,
            records=closed.records,
            close_state=closed.close_state,
            blob=closed.blob,
            shares=closed.commissioner_shares[:3],
            signing_private_key=closed.ta_signature_key,
        ),
        message_size=lambda: len(canonical_bytes(closed.report.result)),
    )


def _measure_vote_package_size(profile: BenchmarkProfile, temp_path: Path) -> BenchmarkResult:
    fixture = _fresh_authorization_fixture(temp_path / "vote-package-size")
    package = _package(fixture.state, fixture.params, LIST_CODES[0])
    size = len(canonical_bytes(package))

    return _constant_size_result(
        operation="vote_package_size",
        profile=profile,
        input_size="single_vote_package",
        input_scale=1,
        message_size=size,
    )


def _measure_receipt_size(profile: BenchmarkProfile, temp_path: Path) -> BenchmarkResult:
    closed = _closed_election_fixture(temp_path / "receipt-size", voters=1)
    size = len(canonical_bytes(closed.receipt))

    return _constant_size_result(
        operation="receipt_size",
        profile=profile,
        input_size="single_receipt",
        input_scale=1,
        message_size=size,
    )


def _measure_public_verification(
    profile: BenchmarkProfile,
    temp_path: Path,
    voters: int,
) -> BenchmarkResult:
    closed = _closed_election_fixture(temp_path / f"public-{voters}", voters=voters)

    return _measure(
        operation="public_verification",
        profile=profile,
        input_size=f"events={len(closed.records)}",
        input_scale=len(closed.records),
        measured=lambda: verify_public_election(
            closed.params,
            closed.records,
            closed.close_state,
            closed.report.result,
        ),
        message_size=lambda: len(canonical_bytes(closed.report.result)),
        notes="scale records growth including final CLOSE event",
    )


def _constant_size_result(
    *,
    operation: str,
    profile: BenchmarkProfile,
    input_size: str,
    input_scale: int,
    message_size: int,
) -> BenchmarkResult:
    return BenchmarkResult.from_samples(
        operation=operation,
        profile=profile.name,
        input_size=input_size,
        input_scale=input_scale,
        warmups=0,
        repetitions=1,
        samples_ns=[0],
        message_size_bytes=message_size,
        notes="size measurement only",
    )


def _fresh_authorization_fixture(
    work_dir: Path,
    *,
    scrypt_parameters: ScryptParameters = FAST_SCRYPT,
    voter_index: int = 1,
    eligible_count: int = 1,
) -> AuthorizedFixture:
    work_dir.mkdir(parents=True, exist_ok=True)
    ra_key = generate_signature_private_key()
    bb_key = generate_signature_private_key()
    ta_encryption_key = generate_encryption_private_key()
    ta_signature_key = generate_signature_private_key()
    voter_id = f"voter-{voter_index:03d}"
    ra = RegistrationAuthority(
        election_id=ELECTION_ID,
        private_key=ra_key,
        store_path=work_dir / "ra.json",
        scrypt_parameters=scrypt_parameters,
    )
    ra.register_voter(voter_id, PASSWORD)
    material = generate_authorization_material(ELECTION_ID)
    tau_i = ra.issue_authorization(voter_id, PASSWORD, material.authorization_request)
    blob, commissioners = create_protected_blob(
        election_id=ELECTION_ID,
        private_key_pem=encryption_private_key_to_pem(ta_encryption_key),
        threshold_t=3,
        threshold_n=5,
    )
    params = ElectionParams(
        election_id=ELECTION_ID,
        lists=LISTS,
        opens_at_ms=OPEN_MS,
        closes_at_ms=OPEN_MS + 10_000,
        eligible_count=eligible_count,
        pk_ta_enc=encryption_public_key_to_pem(ta_encryption_key.public_key()),
        pk_ta_sig=signature_public_key_to_pem(ta_signature_key.public_key()),
        pk_ra=ra.public_key_pem,
        pk_bb=signature_public_key_to_pem(bb_key.public_key()),
        threshold=ThresholdParams(t=3, n=5),
        vmax=3,
    )
    return AuthorizedFixture(
        params=params,
        state=material.complete(tau_i),
        board_key=bb_key,
        ta_encryption_key=ta_encryption_key,
        ta_signature_key=ta_signature_key,
        blob=blob,
        commissioner_shares=commissioners.shares,
    )


def _prepare_ra_authorization(
    work_dir: Path,
    *,
    scrypt_parameters: ScryptParameters,
    voter_index: int,
) -> Callable[[], bytes]:
    work_dir.mkdir(parents=True, exist_ok=True)
    voter_id = f"voter-{voter_index:06d}"
    ra = RegistrationAuthority(
        election_id=ELECTION_ID,
        private_key=generate_signature_private_key(),
        store_path=work_dir / "ra.json",
        scrypt_parameters=scrypt_parameters,
    )
    ra.register_voter(voter_id, PASSWORD)
    material = generate_authorization_material(ELECTION_ID)
    return lambda: ra.issue_authorization(voter_id, PASSWORD, material.authorization_request)


def _closed_election_fixture(work_dir: Path, *, voters: int) -> ClosedElectionFixture:
    first, states = _multi_voter_authorization_fixture(work_dir, voters=voters)
    board = BulletinBoard(first.params, first.board_key)
    receipt: Ack | None = None
    for index, state in enumerate(states, start=1):
        package = _package(state, first.params, LIST_CODES[(index - 1) % len(LIST_CODES)])
        receipt = board.submit_vote(package, now_ms=OPEN_MS + index)
    close_state = board.close(now_ms=first.params.closes_at_ms)
    report = tally_election(
        params=first.params,
        records=board.records,
        close_state=close_state,
        blob=first.blob,
        shares=first.commissioner_shares[:3],
        signing_private_key=first.ta_signature_key,
    )
    if receipt is None:
        raise RuntimeError("closed election fixture requires at least one voter")
    return ClosedElectionFixture(
        params=first.params,
        records=board.records,
        close_state=close_state,
        report=report,
        receipt=receipt,
        blob=first.blob,
        commissioner_shares=first.commissioner_shares,
        ta_signature_key=first.ta_signature_key,
    )


def _multi_voter_authorization_fixture(
    work_dir: Path,
    *,
    voters: int,
) -> tuple[AuthorizedFixture, tuple[PseudonymousVoterState, ...]]:
    work_dir.mkdir(parents=True, exist_ok=True)
    ra_key = generate_signature_private_key()
    bb_key = generate_signature_private_key()
    ta_encryption_key = generate_encryption_private_key()
    ta_signature_key = generate_signature_private_key()
    ra = RegistrationAuthority(
        election_id=ELECTION_ID,
        private_key=ra_key,
        store_path=work_dir / "ra.json",
        scrypt_parameters=FAST_SCRYPT,
    )
    states: list[PseudonymousVoterState] = []
    for index in range(1, voters + 1):
        voter_id = f"voter-{index:03d}"
        ra.register_voter(voter_id, PASSWORD)
        material = generate_authorization_material(ELECTION_ID)
        tau_i = ra.issue_authorization(voter_id, PASSWORD, material.authorization_request)
        states.append(material.complete(tau_i))
    blob, commissioners = create_protected_blob(
        election_id=ELECTION_ID,
        private_key_pem=encryption_private_key_to_pem(ta_encryption_key),
        threshold_t=3,
        threshold_n=5,
    )
    params = ElectionParams(
        election_id=ELECTION_ID,
        lists=LISTS,
        opens_at_ms=OPEN_MS,
        closes_at_ms=OPEN_MS + 10_000,
        eligible_count=voters,
        pk_ta_enc=encryption_public_key_to_pem(ta_encryption_key.public_key()),
        pk_ta_sig=signature_public_key_to_pem(ta_signature_key.public_key()),
        pk_ra=ra.public_key_pem,
        pk_bb=signature_public_key_to_pem(bb_key.public_key()),
        threshold=ThresholdParams(t=3, n=5),
        vmax=3,
    )
    fixture = AuthorizedFixture(
        params=params,
        state=states[0],
        board_key=bb_key,
        ta_encryption_key=ta_encryption_key,
        ta_signature_key=ta_signature_key,
        blob=blob,
        commissioner_shares=commissioners.shares,
    )
    return fixture, tuple(states)


def _package(state: PseudonymousVoterState, params: ElectionParams, code: str) -> VotePackage:
    return prepare_vote_package(
        state,
        code,
        allowed_list_codes=LIST_CODES,
        ta_public_key_pem=params.pk_ta_enc,
    )


def _single_package_size(work_dir: Path) -> int:
    fixture = _fresh_authorization_fixture(work_dir)
    return len(canonical_bytes(_package(fixture.state, fixture.params, LIST_CODES[0])))


def _blob_public_size(blob: TaBlob) -> int:
    return len(
        canonical_bytes(
            {
                "context": blob.context,
                "election_id": blob.election_id,
                "iv_size": len(blob.iv),
                "ciphertext_size": len(blob.ciphertext),
                "mac_size": len(blob.mac),
                "threshold_t": blob.threshold_t,
                "threshold_n": blob.threshold_n,
            }
        )
    )


class _Counter:
    def __init__(self) -> None:
        self._value = 0

    def next(self) -> int:
        self._value += 1
        return self._value


__all__ = ["PROFILES", "run_benchmark_profile"]
