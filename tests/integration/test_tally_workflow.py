from dataclasses import dataclass

from evoting.actors.bulletin_board import BulletinBoard
from evoting.actors.commissioners import CommissionerShare
from evoting.actors.registration_authority import RegistrationAuthority
from evoting.actors import tallying_authority as tallying_authority_module
from evoting.actors.tallying_authority import TaBlob, create_protected_blob, tally_election
from evoting.actors.verifier import verify_public_election
from evoting.actors.voter import apply_accepted_receipt, generate_authorization_material, prepare_vote_package
from evoting.crypto.encryption import (
    encryption_private_key_to_pem,
    encryption_public_key_to_pem,
    generate_encryption_private_key,
)
from evoting.crypto.password import ScryptParameters
from evoting.crypto.signatures import generate_signature_private_key, signature_public_key_to_pem
from evoting.models import ElectionList, ElectionParams, ThresholdParams


ELECTION_ID = "election-2026"
OPEN_MS = 1_800_000_000_000
FAST_SCRYPT = ScryptParameters(n=2**4, r=1, p=1, length=32)
LIST_CODES = ("LIST-001", "LIST-002", "LIST-003")


@dataclass(frozen=True, slots=True)
class WorkflowFixture:
    params: ElectionParams
    board: BulletinBoard
    states: tuple[object, ...]
    blob: TaBlob
    shares: tuple[CommissionerShare, ...]
    ta_signature_key: object


def _fixture(tmp_path, voters: int) -> WorkflowFixture:
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
    return WorkflowFixture(params, BulletinBoard(params, bb_key), tuple(states), blob, commissioners.shares, ta_sig_key)


def _submit(board: BulletinBoard, state, params: ElectionParams, code: str, *, now_ms: int):
    package = prepare_vote_package(
        state,
        code,
        allowed_list_codes=LIST_CODES,
        ta_public_key_pem=params.pk_ta_enc,
    )
    receipt = board.submit_vote(package, now_ms=now_ms)
    return apply_accepted_receipt(state, package, receipt, bb_public_key_pem=params.pk_bb), package


def test_tally_counts_multiple_voters_and_includes_zero_vote_lists(tmp_path) -> None:
    fixture = _fixture(tmp_path, voters=4)
    _submit(fixture.board, fixture.states[0], fixture.params, "LIST-001", now_ms=OPEN_MS + 1)
    _submit(fixture.board, fixture.states[1], fixture.params, "LIST-002", now_ms=OPEN_MS + 2)
    _submit(fixture.board, fixture.states[2], fixture.params, "LIST-001", now_ms=OPEN_MS + 3)
    _submit(fixture.board, fixture.states[3], fixture.params, "LIST-002", now_ms=OPEN_MS + 4)
    close_state = fixture.board.close(now_ms=fixture.params.closes_at_ms)

    report = tally_election(
        params=fixture.params,
        records=fixture.board.records,
        close_state=close_state,
        blob=fixture.blob,
        shares=fixture.shares[:3],
        signing_private_key=fixture.ta_signature_key,
    )

    assert report.result.totals_by_list == {"LIST-001": 2, "LIST-002": 2, "LIST-003": 0}
    assert report.result.final_ballot_count == 4
    assert report.result.valid_ballot_count == 4
    assert report.result.anomalous_count == 0
    assert verify_public_election(fixture.params, fixture.board.records, close_state, report.result) is True


def test_tally_decrypts_only_final_versions(tmp_path, monkeypatch) -> None:
    fixture = _fixture(tmp_path, voters=1)
    state, first_package = _submit(fixture.board, fixture.states[0], fixture.params, "LIST-001", now_ms=OPEN_MS + 1)
    _, second_package = _submit(fixture.board, state, fixture.params, "LIST-002", now_ms=OPEN_MS + 2)
    close_state = fixture.board.close(now_ms=fixture.params.closes_at_ms)
    seen_ciphertexts = []
    original_decrypt = tallying_authority_module.decrypt_vote

    def recording_decrypt(private_key, ciphertext):
        seen_ciphertexts.append(ciphertext)
        return original_decrypt(private_key, ciphertext)

    monkeypatch.setattr(tallying_authority_module, "decrypt_vote", recording_decrypt)

    report = tally_election(
        params=fixture.params,
        records=fixture.board.records,
        close_state=close_state,
        blob=fixture.blob,
        shares=fixture.shares[:3],
        signing_private_key=fixture.ta_signature_key,
    )

    assert first_package.c not in seen_ciphertexts
    assert second_package.c in seen_ciphertexts
    assert report.result.totals_by_list == {"LIST-001": 0, "LIST-002": 1, "LIST-003": 0}
    assert report.result.final_ballot_count == 1
