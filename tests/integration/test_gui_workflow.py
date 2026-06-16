from evoting.config import default_demo_profile
from evoting.crypto.password import ScryptParameters
from evoting.gui.controller import DemoGuiController


FAST_SCRYPT = ScryptParameters(n=2**4, r=1, p=1, length=32)


def _controller(tmp_path) -> DemoGuiController:
    profile = default_demo_profile(runtime_dir=tmp_path, scrypt_parameters=FAST_SCRYPT)
    return DemoGuiController(profile)


def test_gui_controller_complete_workflow_close_tally_and_public_verification(tmp_path) -> None:
    controller = _controller(tmp_path)
    controller.initialize_election()
    voters = controller.snapshot().voters

    for row in voters:
        controller.authorize_voter(row.voter_id)

    for row, code in zip(voters, ("LIST-001", "LIST-002", "LIST-003"), strict=True):
        controller.deposit_vote(row.voter_id, code)

    controller.replace_vote(voters[2].voter_id, "LIST-002")
    closed = controller.close_election()

    assert closed.config.election_status == "Chiusa"
    assert closed.actions.can_tally is True
    assert [row.index for row in closed.bulletin_board] == [1, 2, 3, 4, 5]
    assert [row.record_type for row in closed.bulletin_board] == [
        "BALLOT",
        "BALLOT",
        "BALLOT",
        "BALLOT",
        "CLOSE",
    ]
    assert closed.bulletin_board[-1].status == "chiusura"
    assert sum(1 for row in closed.bulletin_board if row.status == "sostituita") == 1
    assert sum(1 for row in closed.bulletin_board if row.status == "finale") == 3

    tallied = controller.run_tally()

    assert tallied.config.election_status == "Scrutinata"
    assert dict(tallied.tally.totals_by_list) == {
        "LIST-001": 1,
        "LIST-002": 2,
        "LIST-003": 0,
    }
    assert tallied.tally.final_ballots == 3
    assert tallied.tally.valid_ballots == 3
    assert tallied.tally.anomalous_ballots == 0
    assert tallied.actions.can_verify is True

    verified = controller.run_public_verification()

    assert verified.config.election_status == "Verificata"
    assert verified.tally.ta_signature_status == "OK"
    assert verified.tally.hash_chain_status == "OK"
    assert verified.tally.public_log_status == "OK"
    assert verified.tally.public_verification_status == "OK"
    assert verified.actions.can_verify is False

    reset = controller.reset()

    assert reset.bulletin_board == ()


def test_gui_public_snapshot_does_not_expose_secrets_or_full_protocol_values(tmp_path) -> None:
    controller = _controller(tmp_path)
    controller.initialize_election()
    voter_id = controller.snapshot().voters[0].voter_id
    controller.authorize_voter(voter_id)
    snapshot = controller.deposit_vote(voter_id, "LIST-001")

    rendered = repr(snapshot)
    forbidden_markers = (
        "BEGIN PRIVATE KEY",
        "Kwrap",
        "Kenc",
        "Kmac",
        "ShamirShare",
        "sk_vote",
        "t_i",
        "tau_i",
        "password",
        "ciphertext",
        "signature_bb",
        "sigma_i",
    )
    for marker in forbidden_markers:
        assert marker not in rendered

    setup = controller._setup
    assert setup is not None
    entry = setup.bulletin_board.records[0].entry
    assert entry.p_i.hex() not in rendered
    assert entry.rid.hex() not in rendered
    assert entry.c.hex() not in rendered
    assert entry.tau_i.hex() not in rendered
    assert entry.sigma_i.hex() not in rendered
