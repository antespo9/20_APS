from dataclasses import dataclass, replace

import pytest

from evoting.actors.bulletin_board import (
    BoardLogRecord,
    BulletinBoard,
    chain_link_hash,
    close_state_message,
    entry_hash,
)
from evoting.actors.commissioners import CommissionerShare
from evoting.actors.registration_authority import RegistrationAuthority
from evoting.actors.tallying_authority import (
    BallotAnomalyCode,
    TaBlob,
    TALLY_ERROR_MESSAGE,
    TallyingAuthorityError,
    create_protected_blob,
    tally_election,
)
from evoting.actors.voter import generate_authorization_material
from evoting.crypto.encryption import (
    encrypt_vote,
    encryption_private_key_to_pem,
    encryption_public_key_to_pem,
    generate_encryption_private_key,
    load_encryption_public_key,
)
from evoting.crypto.password import ScryptParameters
from evoting.crypto.shamir import FIELD_PRIME, ShamirShare
from evoting.crypto.signatures import (
    generate_signature_private_key,
    load_signature_private_key,
    sign_message,
    signature_public_key_to_pem,
)
from evoting.models import CloseState, ElectionList, ElectionParams, ThresholdParams, VoteMessage, VotePackage
from evoting.serialization import canonical_bytes


ELECTION_ID = "election-2026"
OPEN_MS = 1_800_000_000_000
FAST_SCRYPT = ScryptParameters(n=2**4, r=1, p=1, length=32)
LIST_CODES = ("LIST-001", "LIST-002", "LIST-003")


@dataclass(frozen=True, slots=True)
class NegativeFixture:
    params: ElectionParams
    board: BulletinBoard
    states: tuple[object, ...]
    blob: TaBlob
    shares: tuple[CommissionerShare, ...]
    bb_key: object
    ta_signature_key: object


def _fixture(tmp_path, voters: int = 1) -> NegativeFixture:
    ra_key = generate_signature_private_key()
    bb_key = generate_signature_private_key()
    ta_enc_key = generate_encryption_private_key()
    ta_sig_key = generate_signature_private_key()
    ra = RegistrationAuthority(
        election_id=ELECTION_ID,
        private_key=ra_key,
        store_path=tmp_path / "ra.json",
        scrypt_parameters=FAST_SCRYPT,
    )
    states = []
    for index in range(1, voters + 1):
        institutional_id = f"voter-{index:03d}"
        ra.register_voter(institutional_id, b"institutional-password")
        material = generate_authorization_material(ELECTION_ID)
        tau_i = ra.issue_authorization(institutional_id, b"institutional-password", material.authorization_request)
        states.append(material.complete(tau_i))
    blob, commissioners = create_protected_blob(
        election_id=ELECTION_ID,
        private_key_pem=encryption_private_key_to_pem(ta_enc_key),
        threshold_t=3,
        threshold_n=5,
    )
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
        pk_ta_enc=encryption_public_key_to_pem(ta_enc_key.public_key()),
        pk_ta_sig=signature_public_key_to_pem(ta_sig_key.public_key()),
        pk_ra=ra.public_key_pem,
        pk_bb=signature_public_key_to_pem(bb_key.public_key()),
        threshold=ThresholdParams(t=3, n=5),
        vmax=3,
    )
    return NegativeFixture(params, BulletinBoard(params, bb_key), tuple(states), blob, commissioners.shares, bb_key, ta_sig_key)


def _signed_package(state, params: ElectionParams, ciphertext: bytes) -> VotePackage:
    version = state.current_vote_version + 1
    message = VoteMessage(
        election_id=state.election_id,
        p_i=state.p_i,
        c=ciphertext,
        pk_vote_i=state.pk_vote_i,
        v_i=version,
    )
    signature = sign_message(load_signature_private_key(state.sk_vote_i), canonical_bytes(message))
    return VotePackage(
        c=ciphertext,
        p_i=state.p_i,
        pk_vote_i=state.pk_vote_i,
        tau_i=state.tau_i,
        v_i=version,
        sigma_i=signature,
    )


def _submit_plaintext(board: BulletinBoard, state, params: ElectionParams, plaintext: bytes, *, now_ms: int) -> None:
    public_key = load_encryption_public_key(params.pk_ta_enc)
    board.submit_vote(_signed_package(state, params, encrypt_vote(public_key, plaintext)), now_ms=now_ms)


def _closed_with_one_vote(tmp_path) -> NegativeFixture:
    fixture = _fixture(tmp_path)
    _submit_plaintext(fixture.board, fixture.states[0], fixture.params, b"LIST-001", now_ms=OPEN_MS + 1)
    fixture.board.close(now_ms=fixture.params.closes_at_ms)
    return fixture


def _assert_tally_global_error(fixture: NegativeFixture, *, records=None, close_state=None, blob=None, shares=None) -> None:
    selected_close_state = fixture.board.close_state if close_state is None else close_state
    assert selected_close_state is not None
    with pytest.raises(TallyingAuthorityError) as exc_info:
        tally_election(
            params=fixture.params,
            records=fixture.board.records if records is None else records,
            close_state=selected_close_state,
            blob=fixture.blob if blob is None else blob,
            shares=fixture.shares[:3] if shares is None else shares,
            signing_private_key=fixture.ta_signature_key,
        )
    assert str(exc_info.value) == TALLY_ERROR_MESSAGE


def test_tally_before_close_is_rejected(tmp_path, monkeypatch) -> None:
    fixture = _fixture(tmp_path)
    _submit_plaintext(fixture.board, fixture.states[0], fixture.params, b"LIST-001", now_ms=OPEN_MS + 1)

    def fail_if_opened(*args, **kwargs):
        raise AssertionError("blobTA opened before CLOSE")

    monkeypatch.setattr("evoting.actors.tallying_authority.open_protected_blob", fail_if_opened)
    with pytest.raises(TallyingAuthorityError):
        tally_election(
            params=fixture.params,
            records=fixture.board.records,
            close_state=None,
            blob=fixture.blob,
            shares=fixture.shares[:3],
            signing_private_key=fixture.ta_signature_key,
        )


def test_tally_rejects_altered_close_signature(tmp_path) -> None:
    fixture = _closed_with_one_vote(tmp_path)
    close_state = fixture.board.close_state
    assert close_state is not None
    altered = replace(
        close_state,
        signature_bb=close_state.signature_bb[:-1] + bytes([close_state.signature_bb[-1] ^ 1]),
    )

    _assert_tally_global_error(fixture, close_state=altered)


def test_tally_rejects_altered_hash_chain(tmp_path) -> None:
    fixture = _closed_with_one_vote(tmp_path)
    first = fixture.board.records[0]
    tampered = replace(first, entry_hash=b"x" * 32)

    _assert_tally_global_error(fixture, records=(tampered,) + fixture.board.records[1:])


def test_tally_rejects_validly_signed_wrong_h_close(tmp_path) -> None:
    fixture = _closed_with_one_vote(tmp_path)
    wrong_h_close = b"x" * 32
    close_state = CloseState(
        election_id=fixture.params.election_id,
        h_close=wrong_h_close,
        signature_bb=sign_message(
            fixture.bb_key,
            close_state_message(election_id=fixture.params.election_id, h_close=wrong_h_close),
        ),
    )

    _assert_tally_global_error(fixture, close_state=close_state)


def test_tally_rejects_entries_after_close(tmp_path) -> None:
    fixture = _closed_with_one_vote(tmp_path)

    _assert_tally_global_error(fixture, records=fixture.board.records + (fixture.board.records[0],))


def test_tally_rejects_less_than_threshold_shares(tmp_path) -> None:
    fixture = _closed_with_one_vote(tmp_path)

    _assert_tally_global_error(fixture, shares=fixture.shares[:2])


def test_tally_rejects_altered_share_or_blob(tmp_path) -> None:
    fixture = _closed_with_one_vote(tmp_path)
    altered_inner = ShamirShare(
        x=fixture.shares[1].share.x,
        y=(fixture.shares[1].share.y + 1) % FIELD_PRIME,
    )
    altered_share = CommissionerShare(
        commissioner_id=fixture.shares[1].commissioner_id,
        election_id=fixture.shares[1].election_id,
        share=altered_inner,
    )
    altered_blob = replace(
        fixture.blob,
        mac=fixture.blob.mac[:-1] + bytes([fixture.blob.mac[-1] ^ 1]),
    )

    _assert_tally_global_error(fixture, shares=(fixture.shares[0], altered_share, fixture.shares[2]))
    _assert_tally_global_error(fixture, blob=altered_blob)


def test_tally_classifies_ciphertext_and_plaintext_anomalies(tmp_path) -> None:
    fixture = _fixture(tmp_path, voters=5)
    public_key = load_encryption_public_key(fixture.params.pk_ta_enc)
    fixture.board.submit_vote(_signed_package(fixture.states[0], fixture.params, b"malformed"), now_ms=OPEN_MS + 1)
    _submit_plaintext(fixture.board, fixture.states[1], fixture.params, b"\xff\xfe", now_ms=OPEN_MS + 2)
    _submit_plaintext(fixture.board, fixture.states[2], fixture.params, b"bad code", now_ms=OPEN_MS + 3)
    _submit_plaintext(fixture.board, fixture.states[3], fixture.params, b"LIST-999", now_ms=OPEN_MS + 4)
    fixture.board.submit_vote(
        _signed_package(fixture.states[4], fixture.params, encrypt_vote(public_key, b"LIST-001")),
        now_ms=OPEN_MS + 5,
    )
    close_state = fixture.board.close(now_ms=fixture.params.closes_at_ms)

    report = tally_election(
        params=fixture.params,
        records=fixture.board.records,
        close_state=close_state,
        blob=fixture.blob,
        shares=fixture.shares[:3],
        signing_private_key=fixture.ta_signature_key,
    )

    assert [item.code for item in report.anomalies] == [
        BallotAnomalyCode.MALFORMED_CIPHERTEXT,
        BallotAnomalyCode.UNDECODABLE_PLAINTEXT,
        BallotAnomalyCode.INVALID_PLAINTEXT_FORMAT,
        BallotAnomalyCode.LIST_CODE_OUT_OF_DOMAIN,
    ]
    assert report.result.totals_by_list == {"LIST-001": 1, "LIST-002": 0, "LIST-003": 0}
    assert report.result.final_ballot_count == 5
    assert report.result.valid_ballot_count == 1
    assert report.result.anomalous_count == 4


def test_tally_rejects_close_record_with_broken_chain_link(tmp_path) -> None:
    fixture = _closed_with_one_vote(tmp_path)
    close_record = fixture.board.records[-1]
    broken_close = BoardLogRecord(
        index=close_record.index,
        previous_hash=close_record.previous_hash,
        entry=close_record.entry,
        entry_hash=entry_hash(close_record.entry),
        chain_hash=chain_link_hash(
            previous_hash=close_record.previous_hash,
            index=close_record.index,
            entry_hash_value=entry_hash(close_record.entry),
        )[:-1]
        + b"x",
    )

    _assert_tally_global_error(fixture, records=fixture.board.records[:-1] + (broken_close,))
