from dataclasses import dataclass, replace

import pytest

from evoting.actors.bulletin_board import (
    BulletinBoard,
    BulletinBoardError,
    verify_close_state,
    verify_receipt,
)
from evoting.actors.registration_authority import (
    RegistrationAuthority,
    authorization_message,
)
from evoting.actors.voter import (
    PseudonymousVoterState,
    apply_accepted_receipt,
    generate_authorization_material,
    prepare_vote_package,
)
from evoting.crypto.encryption import encryption_public_key_to_pem, generate_encryption_private_key
from evoting.crypto.password import ScryptParameters
from evoting.crypto.signatures import (
    generate_signature_private_key,
    sign_message,
    signature_private_key_to_pem,
    signature_public_key_to_pem,
)
from evoting.models import AuthorizationRequest, BoardEntry, BoardEntryType, ElectionList, ElectionParams, ThresholdParams


ELECTION_ID = "election-2026"
OPEN_MS = 1_800_000_000_000
FAST_SCRYPT = ScryptParameters(n=2**4, r=1, p=1, length=32)
LIST_CODES = ("LIST-001", "LIST-002")


@dataclass(frozen=True, slots=True)
class ElectionFixture:
    state: PseudonymousVoterState
    params: ElectionParams
    board: BulletinBoard
    ra_key: object
    bb_key: object


def _fixture(tmp_path, *, vmax: int = 3) -> ElectionFixture:
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
        pk_ra=signature_public_key_to_pem(ra_key.public_key()),
        pk_bb=signature_public_key_to_pem(bb_key.public_key()),
        threshold=ThresholdParams(t=3, n=5),
        vmax=vmax,
    )
    return ElectionFixture(
        state=material.complete(tau_i),
        params=params,
        board=BulletinBoard(params, bb_key),
        ra_key=ra_key,
        bb_key=bb_key,
    )


def _package(state: PseudonymousVoterState, params: ElectionParams, code: str = "LIST-001"):
    return prepare_vote_package(
        state,
        code,
        allowed_list_codes=LIST_CODES,
        ta_public_key_pem=params.pk_ta_enc,
    )


def test_first_valid_vote_is_accepted_with_version_one_receipt_and_chain(tmp_path) -> None:
    fixture = _fixture(tmp_path)
    package = _package(fixture.state, fixture.params)

    receipt = fixture.board.submit_vote(package, now_ms=OPEN_MS + 1)

    assert receipt.index == 1
    assert receipt.election_id == ELECTION_ID
    assert verify_receipt(fixture.params.pk_bb, receipt, expected_rid=fixture.board.records[0].entry.rid)
    assert fixture.board.verify_receipt(receipt) is True
    assert fixture.board.verify_hash_chain() is True
    assert len(fixture.board.records) == 1
    entry = fixture.board.records[0].entry
    assert isinstance(entry, BoardEntry)
    assert entry.type == BoardEntryType.BALLOT
    assert entry.v_i == 1
    assert "engineer-001" not in repr(fixture.board.records)


def test_board_rejects_vote_for_wrong_election_id(tmp_path) -> None:
    fixture = _fixture(tmp_path)
    package = _package(fixture.state, fixture.params)
    other_params = replace(fixture.params, election_id="election-2027")
    other_board = BulletinBoard(other_params, fixture.bb_key)

    with pytest.raises(BulletinBoardError):
        other_board.submit_vote(package, now_ms=OPEN_MS + 1)


def test_board_rejects_vote_outside_open_period(tmp_path) -> None:
    fixture = _fixture(tmp_path)
    package = _package(fixture.state, fixture.params)

    with pytest.raises(BulletinBoardError):
        fixture.board.submit_vote(package, now_ms=OPEN_MS - 1)

    with pytest.raises(BulletinBoardError):
        fixture.board.submit_vote(package, now_ms=fixture.params.closes_at_ms)


def test_board_rejects_duplicate_or_non_consecutive_versions(tmp_path) -> None:
    fixture = _fixture(tmp_path)
    first = _package(fixture.state, fixture.params)
    first_receipt = fixture.board.submit_vote(first, now_ms=OPEN_MS + 1)
    accepted_state = apply_accepted_receipt(
        fixture.state,
        first,
        first_receipt,
        bb_public_key_pem=fixture.params.pk_bb,
    )
    duplicate_version = _package(fixture.state, fixture.params, "LIST-002")
    skipped_state = replace(accepted_state, current_vote_version=2)
    skipped_version = _package(skipped_state, fixture.params, "LIST-002")

    with pytest.raises(BulletinBoardError):
        fixture.board.submit_vote(duplicate_version, now_ms=OPEN_MS + 2)

    with pytest.raises(BulletinBoardError):
        fixture.board.submit_vote(skipped_version, now_ms=OPEN_MS + 3)

    assert len(fixture.board.records) == 1


def test_board_rejects_replacement_with_changed_pseudonymous_key(tmp_path) -> None:
    fixture = _fixture(tmp_path)
    first = _package(fixture.state, fixture.params)
    first_receipt = fixture.board.submit_vote(first, now_ms=OPEN_MS + 1)
    accepted_state = apply_accepted_receipt(
        fixture.state,
        first,
        first_receipt,
        bb_public_key_pem=fixture.params.pk_bb,
    )
    replacement_key = generate_signature_private_key()
    replacement_pk = signature_public_key_to_pem(replacement_key.public_key())
    request = AuthorizationRequest(
        election_id=ELECTION_ID,
        p_i=accepted_state.p_i,
        pk_vote_i=replacement_pk,
    )
    changed_key_state = PseudonymousVoterState(
        election_id=accepted_state.election_id,
        t_i=accepted_state.t_i,
        p_i=accepted_state.p_i,
        pk_vote_i=replacement_pk,
        sk_vote_i=signature_private_key_to_pem(replacement_key),
        tau_i=sign_message(fixture.ra_key, authorization_message(request)),
        current_vote_version=accepted_state.current_vote_version,
        receipts=accepted_state.receipts,
    )
    changed_key_package = _package(changed_key_state, fixture.params, "LIST-002")

    with pytest.raises(BulletinBoardError):
        fixture.board.submit_vote(changed_key_package, now_ms=OPEN_MS + 2)

    assert len(fixture.board.records) == 1


def test_board_rejects_versions_above_vmax(tmp_path) -> None:
    fixture = _fixture(tmp_path, vmax=1)
    first = _package(fixture.state, fixture.params)
    first_receipt = fixture.board.submit_vote(first, now_ms=OPEN_MS + 1)
    accepted_state = apply_accepted_receipt(
        fixture.state,
        first,
        first_receipt,
        bb_public_key_pem=fixture.params.pk_bb,
    )
    replacement = _package(accepted_state, fixture.params, "LIST-002")

    with pytest.raises(BulletinBoardError):
        fixture.board.submit_vote(replacement, now_ms=OPEN_MS + 2)

    assert len(fixture.board.records) == 1


def test_close_appends_event_signs_final_state_and_refuses_second_close(tmp_path) -> None:
    fixture = _fixture(tmp_path)
    package = _package(fixture.state, fixture.params)
    fixture.board.submit_vote(package, now_ms=OPEN_MS + 1)

    close_state = fixture.board.close(now_ms=fixture.params.closes_at_ms)

    assert fixture.board.is_closed is True
    assert close_state.h_close == fixture.board.current_hash
    assert verify_close_state(fixture.params.pk_bb, close_state) is True
    assert fixture.board.records[-1].entry.type == BoardEntryType.CLOSE
    assert fixture.board.verify_hash_chain() is True
    with pytest.raises(BulletinBoardError):
        fixture.board.close(now_ms=fixture.params.closes_at_ms + 1)


def test_close_before_scheduled_end_is_rejected(tmp_path) -> None:
    fixture = _fixture(tmp_path)

    with pytest.raises(BulletinBoardError):
        fixture.board.close(now_ms=fixture.params.closes_at_ms - 1)

    assert fixture.board.is_closed is False
    assert fixture.board.records == ()
    receipt = fixture.board.submit_vote(_package(fixture.state, fixture.params), now_ms=OPEN_MS + 1)
    assert fixture.board.verify_receipt(receipt) is True


def test_vote_after_close_is_rejected(tmp_path) -> None:
    fixture = _fixture(tmp_path)
    fixture.board.close(now_ms=fixture.params.closes_at_ms)
    package = _package(fixture.state, fixture.params)

    with pytest.raises(BulletinBoardError):
        fixture.board.submit_vote(package, now_ms=fixture.params.closes_at_ms + 1)
