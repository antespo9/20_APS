from dataclasses import dataclass, replace
import inspect

import pytest

import evoting.actors.bulletin_board as bulletin_board_module
from evoting.actors.bulletin_board import (
    BoardLogRecord,
    BulletinBoard,
    BulletinBoardError,
    verify_log_records,
    verify_receipt,
)
from evoting.actors.registration_authority import RegistrationAuthority
from evoting.actors.voter import (
    PseudonymousVoterState,
    apply_accepted_receipt,
    generate_authorization_material,
    prepare_vote_package,
)
from evoting.crypto.encryption import encryption_public_key_to_pem, generate_encryption_private_key
from evoting.crypto.password import ScryptParameters
from evoting.crypto.signatures import generate_signature_private_key, signature_public_key_to_pem
from evoting.models import BoardEntry, ElectionList, ElectionParams, ThresholdParams


ELECTION_ID = "election-2026"
OPEN_MS = 1_800_000_000_000
FAST_SCRYPT = ScryptParameters(n=2**4, r=1, p=1, length=32)
LIST_CODES = ("LIST-001", "LIST-002")


@dataclass(frozen=True, slots=True)
class ElectionFixture:
    state: PseudonymousVoterState
    params: ElectionParams
    board: BulletinBoard


def _fixture(tmp_path) -> ElectionFixture:
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
        vmax=3,
    )
    return ElectionFixture(
        state=material.complete(tau_i),
        params=params,
        board=BulletinBoard(params, bb_key),
    )


def _package(state: PseudonymousVoterState, params: ElectionParams, code: str = "LIST-001"):
    return prepare_vote_package(
        state,
        code,
        allowed_list_codes=LIST_CODES,
        ta_public_key_pem=params.pk_ta_enc,
    )


def _closed_board_with_replacement(tmp_path) -> ElectionFixture:
    fixture = _fixture(tmp_path)
    first = _package(fixture.state, fixture.params)
    first_receipt = fixture.board.submit_vote(first, now_ms=OPEN_MS + 1)
    accepted = apply_accepted_receipt(
        fixture.state,
        first,
        first_receipt,
        bb_public_key_pem=fixture.params.pk_bb,
    )
    second = _package(accepted, fixture.params, "LIST-002")
    fixture.board.submit_vote(second, now_ms=OPEN_MS + 2)
    fixture.board.close(now_ms=fixture.params.closes_at_ms)
    return fixture


def test_altered_authorization_is_rejected(tmp_path) -> None:
    fixture = _fixture(tmp_path)
    package = _package(fixture.state, fixture.params)
    altered_tau = package.tau_i[:-1] + bytes([package.tau_i[-1] ^ 1])
    altered = replace(package, tau_i=altered_tau)

    with pytest.raises(BulletinBoardError):
        fixture.board.submit_vote(altered, now_ms=OPEN_MS + 1)

    assert fixture.board.records == ()


def test_altered_signed_message_or_signature_is_rejected(tmp_path) -> None:
    fixture = _fixture(tmp_path)
    package = _package(fixture.state, fixture.params)
    altered_message = replace(package, c=package.c[:-1] + bytes([package.c[-1] ^ 1]))
    altered_signature = replace(package, sigma_i=package.sigma_i[:-1] + bytes([package.sigma_i[-1] ^ 1]))

    with pytest.raises(BulletinBoardError):
        fixture.board.submit_vote(altered_message, now_ms=OPEN_MS + 1)

    with pytest.raises(BulletinBoardError):
        fixture.board.submit_vote(altered_signature, now_ms=OPEN_MS + 1)

    assert fixture.board.records == ()


def test_identical_replay_is_rejected_without_second_entry(tmp_path) -> None:
    fixture = _fixture(tmp_path)
    package = _package(fixture.state, fixture.params)

    fixture.board.submit_vote(package, now_ms=OPEN_MS + 1)

    with pytest.raises(BulletinBoardError):
        fixture.board.submit_vote(package, now_ms=OPEN_MS + 2)

    assert len(fixture.board.records) == 1


def test_altered_receipt_does_not_verify(tmp_path) -> None:
    fixture = _fixture(tmp_path)
    package = _package(fixture.state, fixture.params)
    receipt = fixture.board.submit_vote(package, now_ms=OPEN_MS + 1)
    altered_rid = replace(receipt, rid=b"x" * 32)
    altered_signature = replace(
        receipt,
        signature_bb=receipt.signature_bb[:-1] + bytes([receipt.signature_bb[-1] ^ 1]),
    )

    assert verify_receipt(fixture.params.pk_bb, receipt, expected_rid=receipt.rid) is True
    assert verify_receipt(fixture.params.pk_bb, altered_rid, expected_rid=receipt.rid) is False
    assert verify_receipt(fixture.params.pk_bb, altered_signature, expected_rid=receipt.rid) is False
    assert fixture.board.verify_receipt(altered_rid) is False


def test_hash_chain_detects_entry_deletion_duplication_reordering_and_field_changes(tmp_path) -> None:
    fixture = _closed_board_with_replacement(tmp_path)
    records = fixture.board.records
    close_state = fixture.board.close_state
    assert close_state is not None
    assert verify_log_records(
        genesis_hash_value=fixture.board.genesis_hash,
        records=records,
        expected_final_hash=close_state.h_close,
    )

    first_entry = records[0].entry
    assert isinstance(first_entry, BoardEntry)
    altered_entry = replace(first_entry, c=first_entry.c[:-1] + bytes([first_entry.c[-1] ^ 1]))
    cases = [
        (replace(records[0], entry=altered_entry),) + records[1:],
        records[:1] + records[2:],
        (records[0], records[0]) + records[1:],
        (records[1], records[0], records[2]),
        (replace(records[0], index=2),) + records[1:],
        (replace(records[0], previous_hash=b"x" * 32),) + records[1:],
        (replace(records[0], entry_hash=b"y" * 32),) + records[1:],
        (replace(records[0], chain_hash=b"z" * 32),) + records[1:],
    ]

    for tampered_records in cases:
        assert (
            verify_log_records(
                genesis_hash_value=fixture.board.genesis_hash,
                records=tampered_records,
                expected_final_hash=close_state.h_close,
            )
            is False
        )


def test_public_log_record_rejects_malformed_hash_fields(tmp_path) -> None:
    fixture = _fixture(tmp_path)
    package = _package(fixture.state, fixture.params)
    fixture.board.submit_vote(package, now_ms=OPEN_MS + 1)
    record = fixture.board.records[0]

    with pytest.raises(BulletinBoardError):
        BoardLogRecord(
            index=record.index,
            previous_hash=b"short",
            entry=record.entry,
            entry_hash=record.entry_hash,
            chain_hash=record.chain_hash,
        )


def test_bulletin_board_does_not_decrypt_votes() -> None:
    source = inspect.getsource(bulletin_board_module)

    assert "decrypt_vote" not in source
