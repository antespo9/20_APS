"""End-to-end local workflows for the stand-alone prototype."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa

from evoting.actors.bulletin_board import (
    BoardLogRecord,
    BulletinBoard,
    public_params_hash,
)
from evoting.actors.commissioners import CommissionerSet
from evoting.actors.registration_authority import AuthorizationError, RegistrationAuthority
from evoting.actors.tallying_authority import TaBlob, TallyReport, TallyingAuthority
from evoting.actors.verifier import (
    select_final_ballot_entries,
    verify_individual_receipt,
    verify_public_election,
    verify_public_log,
    verify_tally_result_signature,
)
from evoting.actors.voter import (
    PseudonymousVoterState,
    apply_accepted_receipt,
    generate_authorization_material,
    prepare_vote_package,
)
from evoting.config import DemoProfile, DemoVoter, default_demo_profile
from evoting.crypto.encryption import (
    encryption_private_key_to_pem,
    encryption_public_key_to_pem,
    generate_encryption_private_key,
)
from evoting.crypto.signatures import generate_signature_private_key, signature_public_key_to_pem
from evoting.errors import EvotingError, ModelValidationError
from evoting.models import Ack, BoardEntry, ElectionParams
from evoting.persistence.stores import default_ra_store_path, default_voter_state_path
from evoting.persistence.voter_state import VoterStateError, VoterStateFileStore


WORKFLOW_ERROR_MESSAGE = "workflow execution failed"


class WorkflowError(EvotingError):
    """Raised when a complete local workflow cannot be executed."""


@dataclass(frozen=True, slots=True)
class ElectionSetup:
    """Coordinated in-memory setup for all logical actors."""

    profile: DemoProfile
    params: ElectionParams
    registration_authority: RegistrationAuthority = field(repr=False)
    bulletin_board: BulletinBoard = field(repr=False)
    tallying_authority: TallyingAuthority = field(repr=False)
    blob_ta: TaBlob = field(repr=False)
    commissioner_set: CommissionerSet = field(repr=False)
    ta_signing_private_key: rsa.RSAPrivateKey = field(repr=False)
    runtime_dir: Path = field(repr=False)


@dataclass(frozen=True, slots=True)
class ReceiptSummary:
    sequence: int
    version: int
    rid: str
    receipt_valid: bool
    stored_state_version: int


@dataclass(frozen=True, slots=True)
class BallotRecordSummary:
    index: int
    version: int
    rid: str
    final: bool


@dataclass(frozen=True, slots=True)
class WorkflowVerifications:
    receipts_valid: bool
    hash_chain_valid: bool
    public_log_valid: bool
    tally_signature_valid: bool
    public_election_valid: bool

    @property
    def all_passed(self) -> bool:
        return (
            self.receipts_valid
            and self.hash_chain_valid
            and self.public_log_valid
            and self.tally_signature_valid
            and self.public_election_valid
        )


@dataclass(frozen=True, slots=True)
class CompleteWorkflowSummary:
    election_id: str
    lists: tuple[tuple[str, str], ...]
    voter_count: int
    vmax: int
    threshold: tuple[int, int]
    params_hash: str
    blob_ta_present: bool
    commissioner_share_count: int
    accepted_ballot_count: int
    ballot_records: tuple[BallotRecordSummary, ...]
    receipts: tuple[ReceiptSummary, ...]
    replacement_performed: bool
    old_versions_preserved: bool
    close_index: int
    h_close: str
    totals_by_list: Mapping[str, int]
    final_ballot_count: int
    valid_ballot_count: int
    anomalous_count: int
    verifications: WorkflowVerifications


@dataclass(frozen=True, slots=True)
class StateLossWorkflowSummary:
    election_id: str
    state_loss_mode: str
    accepted_rid: str
    receipt_valid: bool
    state_file_unavailable: bool
    state_reopen_failed: bool
    second_authorization_refused: bool
    replacement_without_state_refused: bool
    accepted_vote_still_on_board: bool
    accepted_vote_tallied: bool
    final_ballot_count: int
    totals_by_list: Mapping[str, int]
    public_election_valid: bool


@dataclass(frozen=True, slots=True, repr=False)
class _WorkflowCredentials:
    ra_passwords: Mapping[str, bytes]
    state_passwords: Mapping[str, bytes]


def setup_demo_election(
    profile: DemoProfile | None = None,
    *,
    runtime_dir: str | Path | None = None,
) -> ElectionSetup:
    """Generate coordinated parameters, actors, keys, ``blobTA`` and shares."""

    selected_profile = default_demo_profile() if profile is None else profile
    if not isinstance(selected_profile, DemoProfile):
        raise WorkflowError(WORKFLOW_ERROR_MESSAGE)
    selected_runtime_dir = Path(runtime_dir) if runtime_dir is not None else selected_profile.runtime_dir

    ra_key = generate_signature_private_key()
    bb_key = generate_signature_private_key()
    ta_encryption_key = generate_encryption_private_key()
    ta_signing_key = generate_signature_private_key()

    registration_authority = RegistrationAuthority(
        election_id=selected_profile.election_id,
        private_key=ra_key,
        store_path=default_ra_store_path(selected_runtime_dir),
        scrypt_parameters=selected_profile.scrypt_parameters,
    )
    tallying_authority = TallyingAuthority(
        election_id=selected_profile.election_id,
        threshold_t=selected_profile.threshold.t,
        threshold_n=selected_profile.threshold.n,
        commissioner_ids=selected_profile.commissioner_ids,
    )
    blob_ta, commissioner_set = tallying_authority.create_blob(
        encryption_private_key_to_pem(ta_encryption_key)
    )

    params_without_hash = ElectionParams(
        election_id=selected_profile.election_id,
        lists=selected_profile.lists,
        opens_at_ms=selected_profile.opens_at_ms,
        closes_at_ms=selected_profile.closes_at_ms,
        eligible_count=selected_profile.voter_count,
        pk_ta_enc=encryption_public_key_to_pem(ta_encryption_key.public_key()),
        pk_ta_sig=signature_public_key_to_pem(ta_signing_key.public_key()),
        pk_ra=registration_authority.public_key_pem,
        pk_bb=signature_public_key_to_pem(bb_key.public_key()),
        threshold=selected_profile.threshold,
        vmax=selected_profile.vmax,
        params_hash=None,
    )
    params = replace(params_without_hash, params_hash=public_params_hash(params_without_hash))
    bulletin_board = BulletinBoard(params, bb_key)

    return ElectionSetup(
        profile=selected_profile,
        params=params,
        registration_authority=registration_authority,
        bulletin_board=bulletin_board,
        tallying_authority=tallying_authority,
        blob_ta=blob_ta,
        commissioner_set=commissioner_set,
        ta_signing_private_key=ta_signing_key,
        runtime_dir=selected_runtime_dir,
    )


def run_complete_election_workflow(
    profile: DemoProfile | None = None,
    *,
    runtime_dir: str | Path | None = None,
) -> CompleteWorkflowSummary:
    """Execute the full demonstration election and return a public summary."""

    setup = setup_demo_election(profile, runtime_dir=runtime_dir)
    credentials = _new_workflow_credentials(setup.profile)
    _register_demo_voters(setup, credentials)
    states = _authorize_and_persist_initial_states(setup, credentials)

    receipts: list[ReceiptSummary] = []
    live_receipts: list[Ack] = []
    accepted_packages = []

    for index, (state, code) in enumerate(
        zip(states, setup.profile.vote_plan.initial_vote_codes, strict=True),
        start=1,
    ):
        updated, receipt, package = _submit_and_store_state(
            setup,
            credentials,
            setup.profile.voters[index - 1],
            state,
            code,
            now_ms=setup.params.opens_at_ms + index,
        )
        states[index - 1] = updated
        live_receipts.append(receipt)
        accepted_packages.append(package)
        receipts.append(_receipt_summary(len(receipts) + 1, receipt, updated, setup))

    replacement_performed = False
    replacement_index = setup.profile.vote_plan.replacement_voter_index
    replacement_code = setup.profile.vote_plan.replacement_vote_code
    if replacement_index is not None and replacement_code is not None:
        replacement_voter = setup.profile.voters[replacement_index]
        replacement_state = _load_voter_state(setup, credentials, replacement_voter)
        updated, receipt, package = _submit_and_store_state(
            setup,
            credentials,
            replacement_voter,
            replacement_state,
            replacement_code,
            now_ms=setup.params.opens_at_ms + len(setup.profile.voters) + 1,
        )
        states[replacement_index] = updated
        live_receipts.append(receipt)
        accepted_packages.append(package)
        receipts.append(_receipt_summary(len(receipts) + 1, receipt, updated, setup))
        replacement_performed = True

    close_state = setup.bulletin_board.close(now_ms=setup.params.closes_at_ms)
    report = setup.tallying_authority.tally(
        params=setup.params,
        records=setup.bulletin_board.records,
        close_state=close_state,
        blob=setup.blob_ta,
        shares=setup.commissioner_set.shares[: setup.params.threshold.t],
        signing_private_key=setup.ta_signing_private_key,
    )
    verifications = _workflow_verifications(setup, report, live_receipts)
    final_entries = select_final_ballot_entries(setup.params, setup.bulletin_board.records, close_state)
    final_rids = {entry.rid for entry in final_entries}
    ballot_records = _ballot_record_summaries(setup.bulletin_board.records, final_rids)

    return CompleteWorkflowSummary(
        election_id=setup.params.election_id,
        lists=tuple((item.code, item.label) for item in setup.params.lists),
        voter_count=setup.params.eligible_count,
        vmax=setup.params.vmax,
        threshold=(setup.params.threshold.t, setup.params.threshold.n),
        params_hash=_short_hex(setup.params.params_hash),
        blob_ta_present=isinstance(setup.blob_ta, TaBlob),
        commissioner_share_count=len(setup.commissioner_set.shares),
        accepted_ballot_count=sum(1 for record in setup.bulletin_board.records if isinstance(record.entry, BoardEntry)),
        ballot_records=ballot_records,
        receipts=tuple(receipts),
        replacement_performed=replacement_performed,
        old_versions_preserved=_old_versions_preserved(setup.bulletin_board.records),
        close_index=len(setup.bulletin_board.records),
        h_close=_short_hex(close_state.h_close),
        totals_by_list=dict(report.result.totals_by_list),
        final_ballot_count=report.result.final_ballot_count,
        valid_ballot_count=report.result.valid_ballot_count,
        anomalous_count=report.result.anomalous_count,
        verifications=verifications,
    )


def run_state_loss_workflow(
    profile: DemoProfile | None = None,
    *,
    runtime_dir: str | Path | None = None,
    corrupt_state: bool = False,
) -> StateLossWorkflowSummary:
    """Execute the accepted-vote state-loss scenario without recovery."""

    setup = setup_demo_election(profile, runtime_dir=runtime_dir)
    credentials = _new_workflow_credentials(setup.profile)
    first_voter = setup.profile.voters[0]
    _register_one_voter(setup, credentials, first_voter)
    state = _authorize_one_voter(setup, credentials, first_voter)
    _save_voter_state(setup, credentials, first_voter, state)
    reopened_state = _load_voter_state(setup, credentials, first_voter)
    updated_state, receipt, _ = _submit_and_store_state(
        setup,
        credentials,
        first_voter,
        reopened_state,
        setup.profile.vote_plan.initial_vote_codes[0],
        now_ms=setup.params.opens_at_ms + 1,
    )
    receipt_valid = setup.bulletin_board.verify_receipt(receipt)
    _save_voter_state(setup, credentials, first_voter, updated_state)

    state_path = _state_path(setup, first_voter)
    if corrupt_state:
        state_path.write_text("{not valid encrypted state", encoding="utf-8")
        state_loss_mode = "corrupted"
    else:
        state_path.unlink()
        state_loss_mode = "deleted"
    state_file_unavailable = not state_path.exists() or corrupt_state

    second_authorization_refused = _second_authorization_refused(setup, credentials, first_voter)
    state_reopen_failed = False
    replacement_without_state_refused = False
    try:
        lost_state = _load_voter_state(setup, credentials, first_voter)
    except VoterStateError:
        state_reopen_failed = True
        replacement_without_state_refused = True
    else:
        try:
            package = prepare_vote_package(
                lost_state,
                setup.profile.vote_plan.replacement_vote_code or setup.profile.allowed_list_codes[0],
                allowed_list_codes=setup.profile.allowed_list_codes,
                ta_public_key_pem=setup.params.pk_ta_enc,
            )
            setup.bulletin_board.submit_vote(package, now_ms=setup.params.opens_at_ms + 2)
        except Exception:
            replacement_without_state_refused = True

    accepted_vote_still_on_board = any(
        isinstance(record.entry, BoardEntry) and record.entry.rid == receipt.rid
        for record in setup.bulletin_board.records
    )
    close_state = setup.bulletin_board.close(now_ms=setup.params.closes_at_ms)
    report = setup.tallying_authority.tally(
        params=setup.params,
        records=setup.bulletin_board.records,
        close_state=close_state,
        blob=setup.blob_ta,
        shares=setup.commissioner_set.shares[: setup.params.threshold.t],
        signing_private_key=setup.ta_signing_private_key,
    )
    final_entries = select_final_ballot_entries(setup.params, setup.bulletin_board.records, close_state)
    accepted_vote_tallied = any(entry.rid == receipt.rid for entry in final_entries)

    return StateLossWorkflowSummary(
        election_id=setup.params.election_id,
        state_loss_mode=state_loss_mode,
        accepted_rid=_short_hex(receipt.rid),
        receipt_valid=receipt_valid,
        state_file_unavailable=state_file_unavailable,
        state_reopen_failed=state_reopen_failed,
        second_authorization_refused=second_authorization_refused,
        replacement_without_state_refused=replacement_without_state_refused,
        accepted_vote_still_on_board=accepted_vote_still_on_board,
        accepted_vote_tallied=accepted_vote_tallied,
        final_ballot_count=report.result.final_ballot_count,
        totals_by_list=dict(report.result.totals_by_list),
        public_election_valid=verify_public_election(
            setup.params,
            setup.bulletin_board.records,
            close_state,
            report.result,
        ),
    )


def _new_workflow_credentials(profile: DemoProfile) -> _WorkflowCredentials:
    return _WorkflowCredentials(
        ra_passwords={voter.local_voter_id: os.urandom(32) for voter in profile.voters},
        state_passwords={voter.local_voter_id: os.urandom(32) for voter in profile.voters},
    )


def _register_demo_voters(setup: ElectionSetup, credentials: _WorkflowCredentials) -> None:
    for voter in setup.profile.voters:
        _register_one_voter(setup, credentials, voter)


def _register_one_voter(
    setup: ElectionSetup,
    credentials: _WorkflowCredentials,
    voter: DemoVoter,
) -> None:
    setup.registration_authority.register_voter(
        voter.institutional_id,
        credentials.ra_passwords[voter.local_voter_id],
    )


def _authorize_and_persist_initial_states(
    setup: ElectionSetup,
    credentials: _WorkflowCredentials,
) -> list[PseudonymousVoterState]:
    states = []
    for voter in setup.profile.voters:
        state = _authorize_one_voter(setup, credentials, voter)
        _save_voter_state(setup, credentials, voter, state)
        states.append(_load_voter_state(setup, credentials, voter))
    return states


def _authorize_one_voter(
    setup: ElectionSetup,
    credentials: _WorkflowCredentials,
    voter: DemoVoter,
) -> PseudonymousVoterState:
    material = generate_authorization_material(setup.params.election_id)
    tau_i = setup.registration_authority.issue_authorization(
        voter.institutional_id,
        credentials.ra_passwords[voter.local_voter_id],
        material.authorization_request,
    )
    return material.complete(tau_i)


def _second_authorization_refused(
    setup: ElectionSetup,
    credentials: _WorkflowCredentials,
    voter: DemoVoter,
) -> bool:
    try:
        material = generate_authorization_material(setup.params.election_id)
        setup.registration_authority.issue_authorization(
            voter.institutional_id,
            credentials.ra_passwords[voter.local_voter_id],
            material.authorization_request,
        )
    except AuthorizationError:
        return True
    return False


def _submit_and_store_state(
    setup: ElectionSetup,
    credentials: _WorkflowCredentials,
    voter: DemoVoter,
    state: PseudonymousVoterState,
    list_code: str,
    *,
    now_ms: int,
) -> tuple[PseudonymousVoterState, Ack, object]:
    package = prepare_vote_package(
        state,
        list_code,
        allowed_list_codes=setup.profile.allowed_list_codes,
        ta_public_key_pem=setup.params.pk_ta_enc,
    )
    receipt = setup.bulletin_board.submit_vote(package, now_ms=now_ms)
    updated = apply_accepted_receipt(
        state,
        package,
        receipt,
        bb_public_key_pem=setup.params.pk_bb,
    )
    _save_voter_state(setup, credentials, voter, updated)
    return updated, receipt, package


def _save_voter_state(
    setup: ElectionSetup,
    credentials: _WorkflowCredentials,
    voter: DemoVoter,
    state: PseudonymousVoterState,
) -> None:
    VoterStateFileStore(_state_path(setup, voter)).save(
        state,
        credentials.state_passwords[voter.local_voter_id],
        scrypt_parameters=setup.profile.scrypt_parameters,
    )


def _load_voter_state(
    setup: ElectionSetup,
    credentials: _WorkflowCredentials,
    voter: DemoVoter,
) -> PseudonymousVoterState:
    return VoterStateFileStore(_state_path(setup, voter)).load(
        credentials.state_passwords[voter.local_voter_id],
        election_id=setup.params.election_id,
    )


def _state_path(setup: ElectionSetup, voter: DemoVoter) -> Path:
    return default_voter_state_path(voter.local_voter_id, setup.runtime_dir)


def _workflow_verifications(
    setup: ElectionSetup,
    report: TallyReport,
    receipts: list[Ack],
) -> WorkflowVerifications:
    close_state = setup.bulletin_board.close_state
    if close_state is None:
        raise WorkflowError(WORKFLOW_ERROR_MESSAGE)
    receipts_valid = all(
        verify_individual_receipt(setup.params, setup.bulletin_board.records, close_state, receipt)
        for receipt in receipts
    )
    return WorkflowVerifications(
        receipts_valid=receipts_valid,
        hash_chain_valid=setup.bulletin_board.verify_hash_chain(),
        public_log_valid=verify_public_log(setup.params, setup.bulletin_board.records, close_state),
        tally_signature_valid=verify_tally_result_signature(setup.params.pk_ta_sig, report.result),
        public_election_valid=verify_public_election(
            setup.params,
            setup.bulletin_board.records,
            close_state,
            report.result,
        ),
    )


def _receipt_summary(
    sequence: int,
    receipt: Ack,
    state: PseudonymousVoterState,
    setup: ElectionSetup,
) -> ReceiptSummary:
    if not setup.bulletin_board.verify_receipt(receipt):
        receipt_valid = False
    else:
        receipt_valid = True
    return ReceiptSummary(
        sequence=sequence,
        version=state.current_vote_version,
        rid=_short_hex(receipt.rid),
        receipt_valid=receipt_valid,
        stored_state_version=state.current_vote_version,
    )


def _ballot_record_summaries(
    records: tuple[BoardLogRecord, ...],
    final_rids: set[bytes],
) -> tuple[BallotRecordSummary, ...]:
    summaries = []
    for record in records:
        if isinstance(record.entry, BoardEntry):
            summaries.append(
                BallotRecordSummary(
                    index=record.index,
                    version=record.entry.v_i,
                    rid=_short_hex(record.entry.rid),
                    final=record.entry.rid in final_rids,
                )
            )
    return tuple(summaries)


def _old_versions_preserved(records: tuple[BoardLogRecord, ...]) -> bool:
    versions_by_pseudonym: dict[bytes, set[int]] = {}
    for record in records:
        if isinstance(record.entry, BoardEntry):
            versions_by_pseudonym.setdefault(record.entry.p_i, set()).add(record.entry.v_i)
    return any(len(versions) > 1 for versions in versions_by_pseudonym.values())


def _short_hex(value: bytes | None, length: int = 12) -> str:
    if value is None:
        raise ModelValidationError("missing value for public summary")
    if not isinstance(value, bytes) or not value:
        raise ModelValidationError("public summary value must be bytes")
    return value.hex()[:length]


__all__ = [
    "CompleteWorkflowSummary",
    "ElectionSetup",
    "ReceiptSummary",
    "StateLossWorkflowSummary",
    "WorkflowError",
    "WorkflowVerifications",
    "WORKFLOW_ERROR_MESSAGE",
    "setup_demo_election",
    "run_complete_election_workflow",
    "run_state_loss_workflow",
]
