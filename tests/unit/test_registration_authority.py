import pytest

from evoting.actors.registration_authority import (
    AUTHORIZATION_ERROR_MESSAGE,
    AuthorizationError,
    RegistrationAuthority,
    verify_authorization,
)
from evoting.actors.voter import generate_authorization_material
from evoting.crypto.password import ScryptParameters
from evoting.crypto.signatures import generate_signature_private_key


ELECTION_ID = "election-2026"
FAST_SCRYPT = ScryptParameters(n=2**4, r=1, p=1, length=32)


def _ra(store_path, *, election_id: str = ELECTION_ID) -> RegistrationAuthority:
    return RegistrationAuthority(
        election_id=election_id,
        private_key=generate_signature_private_key(),
        store_path=store_path,
        scrypt_parameters=FAST_SCRYPT,
    )


def test_registration_authority_authenticates_correct_credentials(tmp_path) -> None:
    ra = _ra(tmp_path / "ra.json")
    ra.register_voter("engineer-001", b"institutional-password")

    assert ra.authenticate_voter("engineer-001", b"institutional-password") is True


def test_registration_authority_rejects_wrong_password(tmp_path) -> None:
    ra = _ra(tmp_path / "ra.json")
    ra.register_voter("engineer-001", b"institutional-password")
    material = generate_authorization_material(ELECTION_ID)

    assert ra.authenticate_voter("engineer-001", b"wrong-password") is False
    with pytest.raises(AuthorizationError) as exc_info:
        ra.issue_authorization("engineer-001", b"wrong-password", material.authorization_request)

    assert str(exc_info.value) == AUTHORIZATION_ERROR_MESSAGE


def test_registration_authority_rejects_unknown_voter(tmp_path) -> None:
    ra = _ra(tmp_path / "ra.json")
    material = generate_authorization_material(ELECTION_ID)

    assert ra.authenticate_voter("engineer-missing", b"password") is False
    with pytest.raises(AuthorizationError):
        ra.issue_authorization("engineer-missing", b"password", material.authorization_request)


def test_registration_authority_rejects_disabled_voter(tmp_path) -> None:
    ra = _ra(tmp_path / "ra.json")
    ra.register_voter("engineer-disabled", b"institutional-password", enabled=False)
    material = generate_authorization_material(ELECTION_ID)

    assert ra.authenticate_voter("engineer-disabled", b"institutional-password") is False
    with pytest.raises(AuthorizationError):
        ra.issue_authorization("engineer-disabled", b"institutional-password", material.authorization_request)


def test_first_authorization_is_issued_and_signed(tmp_path) -> None:
    ra = _ra(tmp_path / "ra.json")
    ra.register_voter("engineer-001", b"institutional-password")
    material = generate_authorization_material(ELECTION_ID)

    tau_i = ra.issue_authorization("engineer-001", b"institutional-password", material.authorization_request)

    assert isinstance(tau_i, bytes)
    assert verify_authorization(ra.public_key_pem, material.authorization_request, tau_i) is True
    issued = ra.issued_authorization("engineer-001")
    assert issued.election_id == ELECTION_ID
    assert issued.p_i == material.p_i
    assert issued.pk_vote_i == material.pk_vote_i
    assert issued.tau_i == tau_i


def test_second_authorization_is_rejected(tmp_path) -> None:
    ra = _ra(tmp_path / "ra.json")
    ra.register_voter("engineer-001", b"institutional-password")
    first = generate_authorization_material(ELECTION_ID)
    second = generate_authorization_material(ELECTION_ID)

    ra.issue_authorization("engineer-001", b"institutional-password", first.authorization_request)

    with pytest.raises(AuthorizationError):
        ra.issue_authorization("engineer-001", b"institutional-password", second.authorization_request)


def test_second_authorization_is_rejected_after_registry_reopen(tmp_path) -> None:
    store_path = tmp_path / "ra.json"
    private_key = generate_signature_private_key()
    first_ra = RegistrationAuthority(
        election_id=ELECTION_ID,
        private_key=private_key,
        store_path=store_path,
        scrypt_parameters=FAST_SCRYPT,
    )
    first_ra.register_voter("engineer-001", b"institutional-password")
    first_ra.issue_authorization(
        "engineer-001",
        b"institutional-password",
        generate_authorization_material(ELECTION_ID).authorization_request,
    )
    reopened_ra = RegistrationAuthority(
        election_id=ELECTION_ID,
        private_key=private_key,
        store_path=store_path,
        scrypt_parameters=FAST_SCRYPT,
    )

    with pytest.raises(AuthorizationError):
        reopened_ra.issue_authorization(
            "engineer-001",
            b"institutional-password",
            generate_authorization_material(ELECTION_ID).authorization_request,
        )


def test_ra_archive_does_not_store_password_private_key_or_vote(tmp_path) -> None:
    store_path = tmp_path / "ra.json"
    ra = _ra(store_path)
    ra.register_voter("engineer-001", b"institutional-password")
    material = generate_authorization_material(ELECTION_ID)
    ra.issue_authorization("engineer-001", b"institutional-password", material.authorization_request)

    archive_text = store_path.read_text(encoding="utf-8")

    assert "institutional-password" not in archive_text
    assert "BEGIN PRIVATE KEY" not in archive_text
    assert "LIST-001" not in archive_text
