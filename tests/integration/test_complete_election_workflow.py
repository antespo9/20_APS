import subprocess
import sys

from evoting.config import default_demo_profile
from evoting.crypto.password import ScryptParameters
from evoting.workflow import run_complete_election_workflow


FAST_SCRYPT = ScryptParameters(n=2**4, r=1, p=1, length=32)


def _profile(tmp_path):
    return default_demo_profile(runtime_dir=tmp_path, scrypt_parameters=FAST_SCRYPT)


def test_complete_workflow_with_multiple_voters_replacement_tally_and_public_verification(tmp_path) -> None:
    summary = run_complete_election_workflow(_profile(tmp_path))

    assert summary.voter_count == 3
    assert summary.replacement_performed is True
    assert summary.accepted_ballot_count == 4
    assert summary.old_versions_preserved is True
    assert len(summary.ballot_records) == 4
    assert sum(1 for record in summary.ballot_records if record.final) == 3
    assert any(record.version == 1 and not record.final for record in summary.ballot_records)
    assert all(receipt.receipt_valid for receipt in summary.receipts)
    assert len(summary.receipts) == 4
    assert summary.totals_by_list == {"LIST-001": 1, "LIST-002": 2, "LIST-003": 0}
    assert summary.final_ballot_count == 3
    assert summary.valid_ballot_count == 3
    assert summary.anomalous_count == 0
    assert summary.verifications.receipts_valid is True
    assert summary.verifications.hash_chain_valid is True
    assert summary.verifications.public_log_valid is True
    assert summary.verifications.tally_signature_valid is True
    assert summary.verifications.public_election_valid is True
    assert summary.verifications.all_passed is True


def test_complete_workflow_public_summary_contains_no_secrets_or_identity_vote_links(tmp_path) -> None:
    summary = run_complete_election_workflow(_profile(tmp_path))
    rendered = repr(summary)

    forbidden_markers = [
        "BEGIN PRIVATE KEY",
        "Kwrap",
        "ShamirShare",
        "sk_vote",
        "tau_i",
        "password",
        "engineer-",
        "local-voter",
    ]

    for marker in forbidden_markers:
        assert marker not in rendered


def test_demo_module_smoke_outputs_public_summary_without_secrets() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "evoting.demo"],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert completed.returncode == 0
    assert "Milestone 7A - demo workflow completo" in completed.stdout
    assert "LIST-003: 0" in completed.stdout
    assert "Verifiche:" in completed.stdout
    assert "Esito finale: OK" in completed.stdout
    for marker in ("BEGIN PRIVATE KEY", "password", "engineer-", "local-voter", "Kwrap", "ShamirShare"):
        assert marker not in completed.stdout
        assert marker not in completed.stderr
