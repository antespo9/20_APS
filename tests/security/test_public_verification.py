from dataclasses import dataclass, replace
import base64
import inspect

from evoting.actors.bulletin_board import BulletinBoard
from evoting.actors.commissioners import CommissionerShare
from evoting.actors.registration_authority import RegistrationAuthority
from evoting.actors.tallying_authority import TaBlob, create_protected_blob, tally_election
from evoting.actors import verifier as verifier_module
from evoting.actors.verifier import (
    verify_individual_receipt,
    verify_public_election,
    verify_tally_result,
    verify_tally_result_signature,
)
from evoting.actors.voter import generate_authorization_material, prepare_vote_package
from evoting.crypto.encryption import (
    encryption_private_key_to_pem,
    encryption_public_key_to_pem,
    generate_encryption_private_key,
)
from evoting.crypto.password import ScryptParameters
from evoting.crypto.signatures import generate_signature_private_key, signature_public_key_to_pem
from evoting.models import ElectionList, ElectionParams, TallyResult, ThresholdParams
from evoting.serialization import canonical_bytes


ELECTION_ID = "election-2026"
OPEN_MS = 1_800_000_000_000
FAST_SCRYPT = ScryptParameters(n=2**4, r=1, p=1, length=32)
LIST_CODES = ("LIST-001", "LIST-002")


@dataclass(frozen=True, slots=True)
class PublicFixture:
    params: ElectionParams
    board: BulletinBoard
    blob: TaBlob
    shares: tuple[CommissionerShare, ...]
    ta_signature_key: object
    receipts: tuple[object, ...]


def _fixture(tmp_path) -> PublicFixture:
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
    for index in range(1, 3):
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
        ),
        opens_at_ms=OPEN_MS,
        closes_at_ms=OPEN_MS + 10_000,
        eligible_count=2,
        pk_ta_enc=encryption_public_key_to_pem(ta_enc_key.public_key()),
        pk_ta_sig=signature_public_key_to_pem(ta_sig_key.public_key()),
        pk_ra=ra.public_key_pem,
        pk_bb=signature_public_key_to_pem(bb_key.public_key()),
        threshold=ThresholdParams(t=3, n=5),
        vmax=3,
    )
    board = BulletinBoard(params, bb_key)
    receipts = []
    for index, code in enumerate(("LIST-001", "LIST-002"), start=1):
        package = prepare_vote_package(
            states[index - 1],
            code,
            allowed_list_codes=LIST_CODES,
            ta_public_key_pem=params.pk_ta_enc,
        )
        receipts.append(board.submit_vote(package, now_ms=OPEN_MS + index))
    board.close(now_ms=params.closes_at_ms)
    return PublicFixture(params, board, blob, commissioners.shares, ta_sig_key, tuple(receipts))


def _result(fixture: PublicFixture):
    close_state = fixture.board.close_state
    assert close_state is not None
    return tally_election(
        params=fixture.params,
        records=fixture.board.records,
        close_state=close_state,
        blob=fixture.blob,
        shares=fixture.shares[:3],
        signing_private_key=fixture.ta_signature_key,
    ).result


def test_public_verification_accepts_complete_log_and_result(tmp_path) -> None:
    fixture = _fixture(tmp_path)
    close_state = fixture.board.close_state
    assert close_state is not None
    result = _result(fixture)

    assert verify_tally_result_signature(fixture.params.pk_ta_sig, result) is True
    assert verify_tally_result(fixture.params, fixture.board.records, close_state, result) is True
    assert verify_public_election(fixture.params, fixture.board.records, close_state, result) is True


def test_public_verification_rejects_deleted_reordered_duplicated_or_altered_records(tmp_path) -> None:
    fixture = _fixture(tmp_path)
    close_state = fixture.board.close_state
    assert close_state is not None
    result = _result(fixture)
    first_entry = fixture.board.records[0].entry
    altered_entry = replace(first_entry, c=first_entry.c[:-1] + bytes([first_entry.c[-1] ^ 1]))
    cases = [
        fixture.board.records[:1] + fixture.board.records[2:],
        (fixture.board.records[1], fixture.board.records[0], fixture.board.records[2]),
        (fixture.board.records[0], fixture.board.records[0]) + fixture.board.records[1:],
        (replace(fixture.board.records[0], entry=altered_entry),) + fixture.board.records[1:],
    ]

    for records in cases:
        assert verify_public_election(fixture.params, records, close_state, result) is False


def test_public_verification_rejects_altered_ta_signature_and_incoherent_numbers(tmp_path) -> None:
    fixture = _fixture(tmp_path)
    close_state = fixture.board.close_state
    assert close_state is not None
    result = _result(fixture)
    altered_signature = replace(
        result,
        signature_ta=result.signature_ta[:-1] + bytes([result.signature_ta[-1] ^ 1]),
    )
    invalid_counts = TallyResult(
        election_id=result.election_id,
        h_close=result.h_close,
        totals_by_list=result.totals_by_list,
        anomalous_count=1,
        signature_ta=result.signature_ta,
        final_ballot_count=result.final_ballot_count,
        valid_ballot_count=result.valid_ballot_count,
    )

    assert verify_tally_result(fixture.params, fixture.board.records, close_state, result) is True
    assert verify_tally_result(fixture.params, fixture.board.records, close_state, altered_signature) is False
    assert verify_tally_result(fixture.params, fixture.board.records, close_state, invalid_counts) is False


def test_public_verification_rejects_altered_receipt(tmp_path) -> None:
    fixture = _fixture(tmp_path)
    close_state = fixture.board.close_state
    assert close_state is not None
    receipt = fixture.receipts[0]
    altered = replace(receipt, chain_hash=b"x" * 32)

    assert verify_individual_receipt(fixture.params, fixture.board.records, close_state, receipt) is True
    assert verify_individual_receipt(fixture.params, fixture.board.records, close_state, altered) is False


def test_public_verifier_does_not_decrypt_or_load_private_keys() -> None:
    source = inspect.getsource(verifier_module)

    assert "decrypt_vote" not in source
    assert "load_encryption_private_key" not in source
    assert "open_protected_blob" not in source


def test_public_result_contains_no_identity_pseudonym_or_ciphertext(tmp_path) -> None:
    fixture = _fixture(tmp_path)
    result = _result(fixture)
    encoded_result = canonical_bytes(result)
    first_entry = fixture.board.records[0].entry

    assert b"voter-" not in encoded_result
    assert base64.b64encode(first_entry.p_i) not in encoded_result
    assert base64.b64encode(first_entry.c) not in encoded_result
