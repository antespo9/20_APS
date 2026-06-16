from dataclasses import dataclass

import pytest

from evoting.actors.bulletin_board import BulletinBoard, BulletinBoardError
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
from evoting.models import BoardEntry, CloseEntry, ElectionList, ElectionParams, ThresholdParams


ELECTION_ID = "election-2026"
OPEN_MS = 1_800_000_000_000
FAST_SCRYPT = ScryptParameters(n=2**4, r=1, p=1, length=32)
LIST_CODES = ("LIST-001", "LIST-002", "LIST-003")


@dataclass(frozen=True, slots=True)
class ElectionFixture:
    states: tuple[PseudonymousVoterState, ...]
    params: ElectionParams
    board: BulletinBoard


def _fixture(tmp_path, *, voters: int = 1, vmax: int = 3) -> ElectionFixture:
    ra_key = generate_signature_private_key()
    bb_key = generate_signature_private_key()
    ta_key = generate_encryption_private_key()
    ra = RegistrationAuthority(
        election_id=ELECTION_ID,
        private_key=ra_key,
        store_path=tmp_path / "ra.json",
        scrypt_parameters=FAST_SCRYPT,
    )
    states: list[PseudonymousVoterState] = []
    for index in range(1, voters + 1):
        institutional_id = f"engineer-{index:03d}"
        ra.register_voter(institutional_id, b"institutional-password")
        material = generate_authorization_material(ELECTION_ID)
        tau_i = ra.issue_authorization(institutional_id, b"institutional-password", material.authorization_request)
        states.append(material.complete(tau_i))

    params = ElectionParams(
        election_id=ELECTION_ID,
        lists=(
            ElectionList(code="LIST-001", label="Lista Alfa"),
            ElectionList(code="LIST-002", label="Lista Beta"),
            ElectionList(code="LIST-003", label="Lista Gamma"),
        ),
        opens_at_ms=OPEN_MS,
        closes_at_ms=OPEN_MS + 10_000,
        eligible_count=voters,
        pk_ta_enc=encryption_public_key_to_pem(ta_key.public_key()),
        pk_ta_sig=b"ta signature public key",
        pk_ra=ra.public_key_pem,
        pk_bb=signature_public_key_to_pem(bb_key.public_key()),
        threshold=ThresholdParams(t=3, n=5),
        vmax=vmax,
    )
    return ElectionFixture(states=tuple(states), params=params, board=BulletinBoard(params, bb_key))


def _package(state: PseudonymousVoterState, params: ElectionParams, code: str):
    return prepare_vote_package(
        state,
        code,
        allowed_list_codes=LIST_CODES,
        ta_public_key_pem=params.pk_ta_enc,
    )


def _submit_and_apply(
    board: BulletinBoard,
    state: PseudonymousVoterState,
    params: ElectionParams,
    code: str,
    *,
    now_ms: int,
) -> PseudonymousVoterState:
    package = _package(state, params, code)
    receipt = board.submit_vote(package, now_ms=now_ms)
    return apply_accepted_receipt(state, package, receipt, bb_public_key_pem=params.pk_bb)


def test_valid_replacement_preserves_old_entries_and_selects_latest_after_close(tmp_path) -> None:
    fixture = _fixture(tmp_path, voters=2)
    first_voter = _submit_and_apply(
        fixture.board,
        fixture.states[0],
        fixture.params,
        "LIST-001",
        now_ms=OPEN_MS + 1,
    )
    second_voter = _submit_and_apply(
        fixture.board,
        fixture.states[1],
        fixture.params,
        "LIST-003",
        now_ms=OPEN_MS + 2,
    )
    first_voter = _submit_and_apply(
        fixture.board,
        first_voter,
        fixture.params,
        "LIST-002",
        now_ms=OPEN_MS + 3,
    )

    close_state = fixture.board.close(now_ms=fixture.params.closes_at_ms)
    final_entries = fixture.board.final_ballot_entries()
    public_entries = fixture.board.entries

    assert close_state.h_close == fixture.board.current_hash
    assert len(public_entries) == 4
    assert sum(1 for entry in public_entries if isinstance(entry, BoardEntry)) == 3
    assert isinstance(public_entries[-1], CloseEntry)
    first_voter_entries = [
        entry
        for entry in public_entries
        if isinstance(entry, BoardEntry) and entry.p_i == first_voter.p_i
    ]
    assert [entry.v_i for entry in first_voter_entries] == [1, 2]
    assert len(final_entries) == 2
    assert {entry.p_i: entry.v_i for entry in final_entries} == {
        first_voter.p_i: 2,
        second_voter.p_i: 1,
    }


def test_replacement_above_vmax_is_rejected_and_previous_versions_remain(tmp_path) -> None:
    fixture = _fixture(tmp_path, voters=1, vmax=2)
    state = _submit_and_apply(
        fixture.board,
        fixture.states[0],
        fixture.params,
        "LIST-001",
        now_ms=OPEN_MS + 1,
    )
    state = _submit_and_apply(
        fixture.board,
        state,
        fixture.params,
        "LIST-002",
        now_ms=OPEN_MS + 2,
    )
    third = _package(state, fixture.params, "LIST-003")

    with pytest.raises(BulletinBoardError):
        fixture.board.submit_vote(third, now_ms=OPEN_MS + 3)

    assert len(fixture.board.records) == 2
    assert [record.entry.v_i for record in fixture.board.records if isinstance(record.entry, BoardEntry)] == [1, 2]


def test_replacement_after_close_is_rejected(tmp_path) -> None:
    fixture = _fixture(tmp_path, voters=1)
    state = _submit_and_apply(
        fixture.board,
        fixture.states[0],
        fixture.params,
        "LIST-001",
        now_ms=OPEN_MS + 1,
    )
    fixture.board.close(now_ms=fixture.params.closes_at_ms)
    replacement = _package(state, fixture.params, "LIST-002")

    with pytest.raises(BulletinBoardError):
        fixture.board.submit_vote(replacement, now_ms=fixture.params.closes_at_ms + 1)

    final_entries = fixture.board.final_ballot_entries()
    assert len(final_entries) == 1
    assert final_entries[0].v_i == 1
