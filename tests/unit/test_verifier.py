from dataclasses import dataclass, replace

from evoting.actors.bulletin_board import BulletinBoard
from evoting.actors.registration_authority import RegistrationAuthority
from evoting.actors.verifier import (
    select_final_ballot_entries,
    validate_public_log,
    verify_individual_receipt,
    verify_public_log,
)
from evoting.actors.voter import apply_accepted_receipt, generate_authorization_material, prepare_vote_package
from evoting.crypto.encryption import encryption_public_key_to_pem, generate_encryption_private_key
from evoting.crypto.password import ScryptParameters
from evoting.crypto.signatures import generate_signature_private_key, signature_public_key_to_pem
from evoting.models import Ack, ElectionList, ElectionParams, ThresholdParams


ELECTION_ID = "election-2026"
OPEN_MS = 1_800_000_000_000
FAST_SCRYPT = ScryptParameters(n=2**4, r=1, p=1, length=32)
LIST_CODES = ("LIST-001", "LIST-002")


@dataclass(frozen=True, slots=True)
class VerifierFixture:
    params: ElectionParams
    board: BulletinBoard
    first_receipt: Ack
    second_receipt: Ack
    final_pseudonym: bytes


def _fixture(tmp_path) -> VerifierFixture:
    ra_key = generate_signature_private_key()
    bb_key = generate_signature_private_key()
    ta_key = generate_encryption_private_key()
    ra = RegistrationAuthority(
        election_id=ELECTION_ID,
        private_key=ra_key,
        store_path=tmp_path / "ra.json",
        scrypt_parameters=FAST_SCRYPT,
    )
    ra.register_voter("voter-001", b"institutional-password")
    material = generate_authorization_material(ELECTION_ID)
    tau_i = ra.issue_authorization("voter-001", b"institutional-password", material.authorization_request)
    state = material.complete(tau_i)
    params = ElectionParams(
        election_id=ELECTION_ID,
        lists=(
            ElectionList(code="LIST-001", label="Lista Alfa"),
            ElectionList(code="LIST-002", label="Lista Beta"),
        ),
        opens_at_ms=OPEN_MS,
        closes_at_ms=OPEN_MS + 10_000,
        eligible_count=1,
        pk_ta_enc=encryption_public_key_to_pem(ta_key.public_key()),
        pk_ta_sig=b"ta signature public key",
        pk_ra=ra.public_key_pem,
        pk_bb=signature_public_key_to_pem(bb_key.public_key()),
        threshold=ThresholdParams(t=3, n=5),
        vmax=3,
    )
    board = BulletinBoard(params, bb_key)
    first_package = prepare_vote_package(
        state,
        "LIST-001",
        allowed_list_codes=LIST_CODES,
        ta_public_key_pem=params.pk_ta_enc,
    )
    first_receipt = board.submit_vote(first_package, now_ms=OPEN_MS + 1)
    state = apply_accepted_receipt(state, first_package, first_receipt, bb_public_key_pem=params.pk_bb)
    second_package = prepare_vote_package(
        state,
        "LIST-002",
        allowed_list_codes=LIST_CODES,
        ta_public_key_pem=params.pk_ta_enc,
    )
    second_receipt = board.submit_vote(second_package, now_ms=OPEN_MS + 2)
    board.close(now_ms=params.closes_at_ms)
    return VerifierFixture(params, board, first_receipt, second_receipt, state.p_i)


def test_public_log_validation_reconstructs_only_latest_versions(tmp_path) -> None:
    fixture = _fixture(tmp_path)
    close_state = fixture.board.close_state
    assert close_state is not None

    state = validate_public_log(fixture.params, fixture.board.records, close_state)
    final_entries = select_final_ballot_entries(fixture.params, fixture.board.records, close_state)

    assert state.h_close == close_state.h_close
    assert state.close_index == 3
    assert len(final_entries) == 1
    assert final_entries[0].v_i == 2
    assert state.final_record_indices == (2,)


def test_individual_receipt_verifies_signature_and_inclusion_without_vote(tmp_path) -> None:
    fixture = _fixture(tmp_path)
    close_state = fixture.board.close_state
    assert close_state is not None

    assert (
        verify_individual_receipt(
            fixture.params,
            fixture.board.records,
            close_state,
            fixture.second_receipt,
            expected_p_i=fixture.final_pseudonym,
        )
        is True
    )
    altered = replace(fixture.second_receipt, rid=b"x" * 32)
    assert verify_individual_receipt(fixture.params, fixture.board.records, close_state, altered) is False


def test_public_log_rejects_wrong_genesis_hash(tmp_path) -> None:
    fixture = _fixture(tmp_path)
    close_state = fixture.board.close_state
    assert close_state is not None

    assert verify_public_log(fixture.params, fixture.board.records, close_state) is True
    assert (
        verify_public_log(
            fixture.params,
            fixture.board.records,
            close_state,
            genesis_hash_value=b"x" * 32,
        )
        is False
    )
