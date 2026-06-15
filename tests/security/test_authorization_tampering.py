from dataclasses import replace

from evoting.actors.registration_authority import RegistrationAuthority, verify_authorization
from evoting.actors.voter import generate_authorization_material
from evoting.crypto.password import ScryptParameters
from evoting.crypto.signatures import generate_signature_private_key, signature_public_key_to_pem


ELECTION_ID = "election-2026"
FAST_SCRYPT = ScryptParameters(n=2**4, r=1, p=1, length=32)


def _issued_authorization(tmp_path):
    ra = RegistrationAuthority(
        election_id=ELECTION_ID,
        private_key=generate_signature_private_key(),
        store_path=tmp_path / "ra.json",
        scrypt_parameters=FAST_SCRYPT,
    )
    ra.register_voter("engineer-001", b"institutional-password")
    material = generate_authorization_material(ELECTION_ID)
    tau_i = ra.issue_authorization("engineer-001", b"institutional-password", material.authorization_request)
    return ra.public_key_pem, material.authorization_request, tau_i


def test_altered_authorization_request_is_rejected(tmp_path) -> None:
    public_key_pem, request, tau_i = _issued_authorization(tmp_path)
    altered_pseudonym = bytes([request.p_i[0] ^ 1]) + request.p_i[1:]
    altered_request = replace(request, p_i=altered_pseudonym)

    assert verify_authorization(public_key_pem, altered_request, tau_i) is False


def test_altered_authorization_public_key_is_rejected(tmp_path) -> None:
    public_key_pem, request, tau_i = _issued_authorization(tmp_path)
    altered_request = replace(request, pk_vote_i=generate_authorization_material(ELECTION_ID).pk_vote_i)

    assert verify_authorization(public_key_pem, altered_request, tau_i) is False


def test_altered_authorization_election_id_is_rejected(tmp_path) -> None:
    public_key_pem, request, tau_i = _issued_authorization(tmp_path)
    altered_request = replace(request, election_id="election-2027")

    assert verify_authorization(public_key_pem, altered_request, tau_i) is False


def test_altered_authorization_signature_is_rejected(tmp_path) -> None:
    public_key_pem, request, tau_i = _issued_authorization(tmp_path)
    altered_signature = bytearray(tau_i)
    altered_signature[-1] ^= 1

    assert verify_authorization(public_key_pem, request, bytes(altered_signature)) is False


def test_wrong_ra_public_key_is_rejected(tmp_path) -> None:
    _, request, tau_i = _issued_authorization(tmp_path)
    wrong_public_key_pem = signature_public_key_to_pem(generate_signature_private_key().public_key())

    assert verify_authorization(wrong_public_key_pem, request, tau_i) is False
