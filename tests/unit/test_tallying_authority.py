from dataclasses import dataclass, replace

from evoting.actors.bulletin_board import BulletinBoard
from evoting.actors.commissioners import CommissionerShare
from evoting.actors.registration_authority import RegistrationAuthority
from evoting.actors.tallying_authority import (
    BallotAnomalyCode,
    TaBlob,
    TallyingAuthority,
    create_protected_blob,
    tally_election,
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
from evoting.models import ElectionList, ElectionParams, ThresholdParams


ELECTION_ID = "election-2026"
OPEN_MS = 1_800_000_000_000
FAST_SCRYPT = ScryptParameters(n=2**4, r=1, p=1, length=32)
LIST_CODES = ("LIST-001", "LIST-002")


@dataclass(frozen=True, slots=True)
class TallyFixture:
    params: ElectionParams
    board: BulletinBoard
    blob: TaBlob
    shares: tuple[CommissionerShare, ...]
    ta_signature_key: object


def _fixture(tmp_path) -> TallyFixture:
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
    ra.register_voter("voter-001", b"institutional-password")
    material = generate_authorization_material(ELECTION_ID)
    tau_i = ra.issue_authorization("voter-001", b"institutional-password", material.authorization_request)
    state = material.complete(tau_i)
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
        eligible_count=1,
        pk_ta_enc=encryption_public_key_to_pem(ta_enc_key.public_key()),
        pk_ta_sig=signature_public_key_to_pem(ta_sig_key.public_key()),
        pk_ra=ra.public_key_pem,
        pk_bb=signature_public_key_to_pem(bb_key.public_key()),
        threshold=ThresholdParams(t=3, n=5),
        vmax=3,
    )
    board = BulletinBoard(params, bb_key)
    package = prepare_vote_package(
        state,
        "LIST-001",
        allowed_list_codes=LIST_CODES,
        ta_public_key_pem=params.pk_ta_enc,
    )
    board.submit_vote(package, now_ms=OPEN_MS + 1)
    board.close(now_ms=params.closes_at_ms)
    return TallyFixture(params, board, blob, commissioners.shares, ta_sig_key)


def test_tallying_authority_method_counts_and_signs_result(tmp_path) -> None:
    fixture = _fixture(tmp_path)
    authority = TallyingAuthority(ELECTION_ID, threshold_t=3, threshold_n=5)
    close_state = fixture.board.close_state
    assert close_state is not None

    report = authority.tally(
        params=fixture.params,
        records=fixture.board.records,
        close_state=close_state,
        blob=fixture.blob,
        shares=fixture.shares[:3],
        signing_private_key=fixture.ta_signature_key,
    )

    assert report.result.totals_by_list == {"LIST-001": 1, "LIST-002": 0}
    assert report.result.final_ballot_count == 1
    assert report.result.valid_ballot_count == 1
    assert report.result.anomalous_count == 0
    assert report.anomalies == ()
    assert verify_tally_result_signature(fixture.params.pk_ta_sig, report.result) is True


def test_tally_result_signature_rejects_altered_unsigned_fields(tmp_path) -> None:
    fixture = _fixture(tmp_path)
    close_state = fixture.board.close_state
    assert close_state is not None
    report = tally_election(
        params=fixture.params,
        records=fixture.board.records,
        close_state=close_state,
        blob=fixture.blob,
        shares=fixture.shares[:3],
        signing_private_key=fixture.ta_signature_key,
    )
    altered = replace(report.result, totals_by_list={"LIST-001": 0, "LIST-002": 1})

    assert verify_tally_result_signature(fixture.params.pk_ta_sig, report.result) is True
    assert verify_tally_result_signature(fixture.params.pk_ta_sig, altered) is False


def test_tally_result_signature_rejects_altered_signature(tmp_path) -> None:
    fixture = _fixture(tmp_path)
    close_state = fixture.board.close_state
    assert close_state is not None
    report = tally_election(
        params=fixture.params,
        records=fixture.board.records,
        close_state=close_state,
        blob=fixture.blob,
        shares=fixture.shares[:3],
        signing_private_key=fixture.ta_signature_key,
    )
    altered = replace(
        report.result,
        signature_ta=report.result.signature_ta[:-1] + bytes([report.result.signature_ta[-1] ^ 1]),
    )

    assert verify_tally_result_signature(fixture.params.pk_ta_sig, altered) is False


def test_tally_report_classifies_anomalies_without_plaintext_values() -> None:
    anomaly = BallotAnomalyCode.LIST_CODE_OUT_OF_DOMAIN

    assert anomaly.value == "LIST_CODE_OUT_OF_DOMAIN"
