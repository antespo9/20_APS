from dataclasses import replace

import pytest

from evoting.actors.bulletin_board import public_params_hash
from evoting.actors.verifier import verify_public_params_signature
from evoting.config import DemoProfile, DemoVoter, default_demo_profile
from evoting.crypto.password import ScryptParameters
from evoting.errors import ModelValidationError
from evoting.models import ElectionList, ThresholdParams
from evoting.serialization import canonical_bytes
from evoting.workflow import setup_demo_election


FAST_SCRYPT = ScryptParameters(n=2**4, r=1, p=1, length=32)


def _profile(tmp_path) -> DemoProfile:
    return default_demo_profile(runtime_dir=tmp_path, scrypt_parameters=FAST_SCRYPT)


def test_default_demo_profile_is_valid_and_complete(tmp_path) -> None:
    profile = _profile(tmp_path)

    assert profile.election_id == "demo-election-2026"
    assert profile.vmax == 3
    assert profile.threshold == ThresholdParams(t=3, n=5)
    assert profile.voter_count == 3
    assert len(profile.lists) >= 3
    assert len(profile.voters) >= 3
    assert profile.opens_at_ms < profile.closes_at_ms
    assert profile.allowed_list_codes == ("LIST-001", "LIST-002", "LIST-003")


def test_demo_profile_rejects_invalid_threshold_vmax_duplicates_and_identifiers(tmp_path) -> None:
    profile = _profile(tmp_path)

    with pytest.raises(ModelValidationError):
        ThresholdParams(t=6, n=5)

    with pytest.raises(ModelValidationError):
        replace(profile, vmax=0)

    with pytest.raises(ModelValidationError):
        replace(
            profile,
            lists=(
                ElectionList(code="LIST-001", label="One"),
                ElectionList(code="LIST-001", label="Duplicate"),
            ),
        )

    with pytest.raises(ModelValidationError):
        replace(profile, election_id="bad election id")

    with pytest.raises(ModelValidationError):
        replace(profile, voters=(DemoVoter("bad voter", "local-voter-001"),))


def test_setup_generates_distinct_role_keys_and_coherent_public_params(tmp_path) -> None:
    profile = _profile(tmp_path)
    setup = setup_demo_election(profile)
    params = setup.params

    public_keys = {params.pk_ra, params.pk_bb, params.pk_ta_enc, params.pk_ta_sig}

    assert len(public_keys) == 4
    assert params.election_id == profile.election_id
    assert params.lists == profile.lists
    assert params.threshold == profile.threshold
    assert params.vmax == profile.vmax
    assert params.eligible_count == profile.voter_count
    assert params.params_hash == public_params_hash(params)
    assert params.params_signature is not None
    assert verify_public_params_signature(params) is True


def test_setup_creates_blob_ta_and_expected_number_of_commissioner_shares(tmp_path) -> None:
    setup = setup_demo_election(_profile(tmp_path))

    assert setup.blob_ta.election_id == setup.params.election_id
    assert setup.blob_ta.threshold_t == setup.params.threshold.t
    assert setup.blob_ta.threshold_n == setup.params.threshold.n
    assert len(setup.commissioner_set.shares) == setup.params.threshold.n


def test_public_params_object_contains_no_private_keys_or_secrets(tmp_path) -> None:
    setup = setup_demo_election(_profile(tmp_path))
    rendered = repr(setup.params).encode("utf-8") + canonical_bytes(setup.params)

    forbidden_markers = (
        b"BEGIN PRIVATE KEY",
        b"Kwrap",
        b"ShamirShare",
        b"sk_",
        b"password",
        b"share=",
    )
    for marker in forbidden_markers:
        assert marker not in rendered
