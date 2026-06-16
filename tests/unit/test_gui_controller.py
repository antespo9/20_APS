import importlib
import subprocess
import sys

import pytest

from evoting.config import default_demo_profile
from evoting.crypto.password import ScryptParameters
from evoting.gui.controller import DemoGuiController, GuiControllerError


FAST_SCRYPT = ScryptParameters(n=2**4, r=1, p=1, length=32)


def _controller(tmp_path) -> DemoGuiController:
    profile = default_demo_profile(runtime_dir=tmp_path, scrypt_parameters=FAST_SCRYPT)
    return DemoGuiController(profile)


def test_initial_controller_state_exposes_public_configuration_only(tmp_path) -> None:
    controller = _controller(tmp_path)
    snapshot = controller.snapshot()

    assert snapshot.config.election_id == "demo-election-2026"
    assert snapshot.config.threshold == "3/5"
    assert snapshot.config.voter_count == 3
    assert snapshot.config.election_status == "Non inizializzata"
    assert snapshot.actions.can_initialize is True
    assert snapshot.actions.can_close is False
    assert all(row.authorization_status == "Non autorizzato" for row in snapshot.voters)
    assert snapshot.bulletin_board == ()


def test_initialization_and_authorization_update_controller_state(tmp_path) -> None:
    controller = _controller(tmp_path)

    initialized = controller.initialize_election()
    assert initialized.config.election_status == "Aperta"
    assert initialized.actions.can_initialize is False
    assert initialized.actions.can_authorize is True

    voter_id = initialized.voters[0].voter_id
    authorized = controller.authorize_voter(voter_id)
    row = next(item for item in authorized.voters if item.voter_id == voter_id)

    assert row.authorization_status == "Autorizzato"
    assert row.current_version == 0
    assert row.receipt_count == 0


def test_deposit_and_replacement_publish_only_public_receipt_and_board_data(tmp_path) -> None:
    controller = _controller(tmp_path)
    controller.initialize_election()
    voter_id = controller.snapshot().voters[0].voter_id
    controller.authorize_voter(voter_id)

    first = controller.deposit_vote(voter_id, "LIST-001")
    assert first.last_receipt is not None
    assert first.last_receipt.board_index == 1
    assert first.last_receipt.version == 1
    assert first.last_receipt.receipt_valid == "si"
    assert len(first.last_receipt.rid) == 12
    assert "LIST-001" not in first.log_messages[-1]
    assert voter_id not in first.log_messages[-1]

    second = controller.replace_vote(voter_id, "LIST-002")
    indices = [row.index for row in second.bulletin_board]
    statuses = [row.status for row in second.bulletin_board]
    versions = [row.version for row in second.bulletin_board]

    assert second.last_receipt is not None
    assert second.last_receipt.board_index == 2
    assert second.last_receipt.version == 2
    assert indices == [1, 2]
    assert statuses == ["sostituita", "finale"]
    assert versions == ["1", "2"]
    assert "LIST-002" not in second.log_messages[-1]
    assert voter_id not in second.log_messages[-1]


def test_controller_refuses_actions_out_of_order(tmp_path) -> None:
    controller = _controller(tmp_path)
    voter_id = controller.snapshot().voters[0].voter_id

    with pytest.raises(GuiControllerError):
        controller.deposit_vote(voter_id, "LIST-001")

    controller.initialize_election()

    with pytest.raises(GuiControllerError):
        controller.deposit_vote(voter_id, "LIST-001")

    controller.authorize_voter(voter_id)

    with pytest.raises(GuiControllerError):
        controller.replace_vote(voter_id, "LIST-002")

    with pytest.raises(GuiControllerError):
        controller.run_tally()

    controller.close_election()

    with pytest.raises(GuiControllerError):
        controller.deposit_vote(voter_id, "LIST-001")

    with pytest.raises(GuiControllerError):
        controller.run_public_verification()


def test_reset_clears_session_state(tmp_path) -> None:
    controller = _controller(tmp_path)
    controller.initialize_election()
    voter_id = controller.snapshot().voters[0].voter_id
    controller.authorize_voter(voter_id)
    controller.deposit_vote(voter_id, "LIST-001")

    reset = controller.reset()

    assert reset.config.election_status == "Non inizializzata"
    assert reset.bulletin_board == ()
    assert reset.last_receipt is None
    assert all(row.current_version == 0 for row in reset.voters)
    assert all(row.receipt_count == 0 for row in reset.voters)


def test_gui_app_import_does_not_create_tk_window(monkeypatch) -> None:
    import tkinter as tk

    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("Tk must not be created during import")

    monkeypatch.setattr(tk, "Tk", fail_if_called)
    module = importlib.import_module("evoting.gui.app")
    importlib.reload(module)

    assert hasattr(module, "main")


def test_bulletin_board_gui_columns_include_index_first() -> None:
    from evoting.gui.app import BOARD_COLUMNS

    assert BOARD_COLUMNS[0][:2] == ("index", "Indice")
    assert [column for column, _label, _width, _anchor in BOARD_COLUMNS] == [
        "index",
        "type",
        "pseudonym",
        "version",
        "rid",
        "chain_hash",
        "status",
    ]


def test_gui_check_mode_runs_without_display() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "evoting.gui.app", "--check"],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert completed.returncode == 0
    assert "GUI check OK" in completed.stdout
