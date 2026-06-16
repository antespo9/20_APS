from dataclasses import replace

import pytest

from evoting.actors.bulletin_board import BulletinBoard, verify_ballot_signature
from evoting.actors.registration_authority import RegistrationAuthority, verify_authorization
from evoting.actors.voter import (
    apply_accepted_receipt,
    generate_authorization_material,
    prepare_vote_package,
)
from evoting.crypto.encryption import encryption_public_key_to_pem, generate_encryption_private_key
from evoting.crypto.password import ScryptParameters
from evoting.crypto.signatures import generate_signature_private_key, signature_public_key_to_pem
from evoting.errors import ModelValidationError
from evoting.models import ElectionList, ElectionParams, ThresholdParams


ELECTION_ID = "election-2026"
OPEN_MS = 1_800_000_000_000
FAST_SCRYPT = ScryptParameters(n=2**4, r=1, p=1, length=32)
LIST_CODES = ("LIST-001", "LIST-002")


def _authorized_state(tmp_path):
    ra_key = generate_signature_private_key()
    bb_key = generate_signature_private_key()
    ta_key = generate_encryption_private_key()
    ra = RegistrationAuthority(
        election_id=ELECTION_ID,
        private_key=ra_key,
        store_path=tmp_path / "ra.json",
        scrypt_parameters=FAST_SCRYPT,
    )
    ra.register_voter("engineer-001", b"institutional-password")
    material = generate_authorization_material(ELECTION_ID)
    tau_i = ra.issue_authorization("engineer-001", b"institutional-password", material.authorization_request)
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
    return material.complete(tau_i), params, bb_key


def test_voter_prepares_first_vote_with_version_one_and_valid_signatures(tmp_path) -> None:
    state, params, _ = _authorized_state(tmp_path)

    package = prepare_vote_package(
        state,
        "LIST-001",
        allowed_list_codes=LIST_CODES,
        ta_public_key_pem=params.pk_ta_enc,
    )

    assert package.v_i == 1
    assert package.p_i == state.p_i
    assert package.pk_vote_i == state.pk_vote_i
    assert package.tau_i == state.tau_i
    assert verify_authorization(params.pk_ra, state.authorization_request, state.tau_i) is True
    assert verify_ballot_signature(ELECTION_ID, package) is True


def test_same_list_code_encrypts_to_different_ciphertexts(tmp_path) -> None:
    state, params, _ = _authorized_state(tmp_path)

    first = prepare_vote_package(
        state,
        "LIST-001",
        allowed_list_codes=LIST_CODES,
        ta_public_key_pem=params.pk_ta_enc,
    )
    second = prepare_vote_package(
        state,
        "LIST-001",
        allowed_list_codes=LIST_CODES,
        ta_public_key_pem=params.pk_ta_enc,
    )

    assert first.c != second.c
    assert first.sigma_i != second.sigma_i
    assert first.v_i == second.v_i == 1


def test_voter_rejects_list_code_outside_public_domain(tmp_path) -> None:
    state, params, _ = _authorized_state(tmp_path)

    with pytest.raises(ModelValidationError):
        prepare_vote_package(
            state,
            "LIST-999",
            allowed_list_codes=LIST_CODES,
            ta_public_key_pem=params.pk_ta_enc,
        )


def test_voter_state_changes_only_after_valid_bb_receipt(tmp_path) -> None:
    state, params, bb_key = _authorized_state(tmp_path)
    board = BulletinBoard(params, bb_key)
    package = prepare_vote_package(
        state,
        "LIST-001",
        allowed_list_codes=LIST_CODES,
        ta_public_key_pem=params.pk_ta_enc,
    )

    assert state.current_vote_version == 0
    assert state.receipts == ()

    receipt = board.submit_vote(package, now_ms=OPEN_MS + 1)
    updated = apply_accepted_receipt(state, package, receipt, bb_public_key_pem=params.pk_bb)

    assert state.current_vote_version == 0
    assert state.receipts == ()
    assert updated.current_vote_version == 1
    assert len(updated.receipts) == 1


def test_voter_rejects_altered_receipt_without_advancing_state(tmp_path) -> None:
    state, params, bb_key = _authorized_state(tmp_path)
    board = BulletinBoard(params, bb_key)
    package = prepare_vote_package(
        state,
        "LIST-001",
        allowed_list_codes=LIST_CODES,
        ta_public_key_pem=params.pk_ta_enc,
    )
    receipt = board.submit_vote(package, now_ms=OPEN_MS + 1)
    altered = replace(receipt, rid=b"x" * 32)

    with pytest.raises(ModelValidationError):
        apply_accepted_receipt(state, package, altered, bb_public_key_pem=params.pk_bb)

    assert state.current_vote_version == 0
    assert state.receipts == ()
