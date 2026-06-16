import pytest

from evoting.config import default_demo_profile
from evoting.crypto.password import ScryptParameters
from evoting.workflow import run_state_loss_workflow


FAST_SCRYPT = ScryptParameters(n=2**4, r=1, p=1, length=32)


def _profile(tmp_path):
    return default_demo_profile(runtime_dir=tmp_path, scrypt_parameters=FAST_SCRYPT)


@pytest.mark.parametrize("corrupt_state", [False, True])
def test_state_loss_or_corruption_after_accepted_vote_does_not_enable_replacement(tmp_path, corrupt_state) -> None:
    summary = run_state_loss_workflow(_profile(tmp_path), corrupt_state=corrupt_state)

    assert summary.receipt_valid is True
    assert summary.state_file_unavailable is True
    assert summary.state_reopen_failed is True
    assert summary.second_authorization_refused is True
    assert summary.replacement_without_state_refused is True
    assert summary.accepted_vote_still_on_board is True
    assert summary.accepted_vote_tallied is True
    assert summary.final_ballot_count == 1
    assert sum(summary.totals_by_list.values()) == 1
    assert summary.public_election_valid is True
