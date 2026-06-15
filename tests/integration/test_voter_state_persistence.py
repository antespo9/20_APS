import base64
import json

import pytest

from evoting.actors.registration_authority import AuthorizationError, RegistrationAuthority
from evoting.actors.voter import generate_authorization_material
from evoting.crypto.password import ScryptParameters
from evoting.crypto.signatures import generate_signature_private_key
from evoting.persistence.voter_state import VoterStateError, VoterStateFileStore


ELECTION_ID = "election-2026"
FAST_SCRYPT = ScryptParameters(n=2**4, r=1, p=1, length=32)
LOCAL_PASSWORD = b"local-state-password"


def _ra(store_path, private_key=None) -> RegistrationAuthority:
    return RegistrationAuthority(
        election_id=ELECTION_ID,
        private_key=private_key or generate_signature_private_key(),
        store_path=store_path,
        scrypt_parameters=FAST_SCRYPT,
    )


def _state_with_ra_authorization(tmp_path):
    ra = _ra(tmp_path / "ra.json")
    ra.register_voter("engineer-001", b"institutional-password")
    material = generate_authorization_material(ELECTION_ID)
    tau_i = ra.issue_authorization("engineer-001", b"institutional-password", material.authorization_request)
    return ra, material.complete(tau_i)


def test_voter_state_is_saved_encrypted_and_loaded(tmp_path) -> None:
    _, state = _state_with_ra_authorization(tmp_path)
    store = VoterStateFileStore(tmp_path / "runtime" / "voters" / "local-voter-001" / "state.enc.json")

    store.save(state, LOCAL_PASSWORD, scrypt_parameters=FAST_SCRYPT)
    loaded = store.load(LOCAL_PASSWORD, election_id=ELECTION_ID)

    assert loaded == state


def test_voter_state_recovers_after_new_application_instance(tmp_path) -> None:
    _, state = _state_with_ra_authorization(tmp_path)
    path = tmp_path / "runtime" / "voters" / "local-voter-001" / "state.enc.json"
    VoterStateFileStore(path).save(state, LOCAL_PASSWORD, scrypt_parameters=FAST_SCRYPT)

    reopened_store = VoterStateFileStore(path)

    assert reopened_store.load(LOCAL_PASSWORD, election_id=ELECTION_ID) == state


def test_wrong_local_password_is_rejected_with_generic_error(tmp_path) -> None:
    _, state = _state_with_ra_authorization(tmp_path)
    store = VoterStateFileStore(tmp_path / "state.enc.json")
    store.save(state, LOCAL_PASSWORD, scrypt_parameters=FAST_SCRYPT)

    with pytest.raises(VoterStateError):
        store.load(b"wrong-local-password", election_id=ELECTION_ID)


def test_altered_encrypted_file_is_rejected(tmp_path) -> None:
    _, state = _state_with_ra_authorization(tmp_path)
    path = tmp_path / "state.enc.json"
    store = VoterStateFileStore(path)
    store.save(state, LOCAL_PASSWORD, scrypt_parameters=FAST_SCRYPT)
    container = json.loads(path.read_text(encoding="utf-8"))
    ciphertext = bytearray(base64.b64decode(container["aead"]["ciphertext"]))
    ciphertext[0] ^= 1
    container["aead"]["ciphertext"] = base64.b64encode(bytes(ciphertext)).decode("ascii")
    path.write_text(json.dumps(container, sort_keys=True), encoding="utf-8")

    with pytest.raises(VoterStateError):
        store.load(LOCAL_PASSWORD, election_id=ELECTION_ID)


def test_altered_aad_context_or_wrong_election_id_is_rejected(tmp_path) -> None:
    _, state = _state_with_ra_authorization(tmp_path)
    path = tmp_path / "state.enc.json"
    store = VoterStateFileStore(path)
    store.save(state, LOCAL_PASSWORD, scrypt_parameters=FAST_SCRYPT)

    with pytest.raises(VoterStateError):
        store.load(LOCAL_PASSWORD, election_id="election-2027")

    container = json.loads(path.read_text(encoding="utf-8"))
    container["aad_context"] = "evoting.voter_state.v1.altered"
    path.write_text(json.dumps(container, sort_keys=True), encoding="utf-8")

    with pytest.raises(VoterStateError):
        store.load(LOCAL_PASSWORD, election_id=ELECTION_ID)


def test_container_does_not_store_voter_secrets_in_clear(tmp_path) -> None:
    _, state = _state_with_ra_authorization(tmp_path)
    path = tmp_path / "state.enc.json"
    VoterStateFileStore(path).save(state, LOCAL_PASSWORD, scrypt_parameters=FAST_SCRYPT)

    container_text = path.read_text(encoding="utf-8")

    assert LOCAL_PASSWORD.decode("ascii") not in container_text
    assert base64.b64encode(state.t_i).decode("ascii") not in container_text
    assert base64.b64encode(state.sk_vote_i).decode("ascii") not in container_text
    assert base64.b64encode(state.tau_i).decode("ascii") not in container_text
    assert "BEGIN PRIVATE KEY" not in container_text


def test_missing_state_does_not_allow_new_authorization(tmp_path) -> None:
    private_key = generate_signature_private_key()
    store_path = tmp_path / "ra.json"
    ra = _ra(store_path, private_key=private_key)
    ra.register_voter("engineer-001", b"institutional-password")
    first = generate_authorization_material(ELECTION_ID)
    ra.issue_authorization("engineer-001", b"institutional-password", first.authorization_request)

    with pytest.raises(VoterStateError):
        VoterStateFileStore(tmp_path / "missing-state.enc.json").load(LOCAL_PASSWORD, election_id=ELECTION_ID)

    reopened_ra = _ra(store_path, private_key=private_key)
    second = generate_authorization_material(ELECTION_ID)
    with pytest.raises(AuthorizationError):
        reopened_ra.issue_authorization("engineer-001", b"institutional-password", second.authorization_request)


def test_archives_do_not_link_identity_and_plaintext_vote(tmp_path) -> None:
    ra, state = _state_with_ra_authorization(tmp_path)
    voter_path = tmp_path / "state.enc.json"
    VoterStateFileStore(voter_path).save(state, LOCAL_PASSWORD, scrypt_parameters=FAST_SCRYPT)
    ra_archive = (tmp_path / "ra.json").read_text(encoding="utf-8")
    voter_archive = voter_path.read_text(encoding="utf-8")

    assert "engineer-001" in ra_archive
    assert "LIST-001" not in ra_archive
    assert "engineer-001" not in voter_archive
    assert "LIST-001" not in voter_archive
    assert base64.b64encode(state.p_i).decode("ascii") not in voter_archive
    assert ra.issued_authorization("engineer-001").p_i == state.p_i
