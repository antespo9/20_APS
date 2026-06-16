import json
import subprocess
import sys

from evoting.benchmarks import BenchmarkResult, run_benchmark_profile
from evoting.benchmarks.runner import write_results


REQUIRED_OPERATIONS = {
    "rsa_signature_key_generation",
    "rsa_encryption_key_generation",
    "ra_authentication_and_authorization_issue",
    "rsa_oaep_vote_encryption",
    "rsa_pss_package_signature",
    "voter_prepare_vote_package_complete",
    "bb_validate_and_accept_vote_package",
    "bb_hash_chain_update_only",
    "bb_receipt_verification",
    "shamir_split",
    "shamir_reconstruction",
    "blob_ta_create",
    "blob_ta_open",
    "tally",
    "public_verification",
    "vote_package_size",
    "receipt_size",
}

FORBIDDEN_MARKERS = (
    "BEGIN PRIVATE KEY",
    "password",
    "engineer-",
    "local-voter",
    "t_i",
    "sk_vote_i",
    "Kwrap",
    "Kenc",
    "Kmac",
    "ShamirShare",
    "share=",
    "ciphertext\":",
    "signature\":",
)


def test_benchmark_package_imports() -> None:
    assert BenchmarkResult.__name__ == "BenchmarkResult"
    assert callable(run_benchmark_profile)


def test_smoke_profile_returns_valid_safe_results(tmp_path) -> None:
    results = run_benchmark_profile("smoke")

    assert results
    assert REQUIRED_OPERATIONS <= {result.operation for result in results}
    assert all(result.profile == "smoke" for result in results)
    assert all(result.repetitions >= 1 for result in results)
    assert all(result.warmups >= 0 for result in results)
    assert all(result.min_ms >= 0 for result in results)
    assert all(result.median_ms >= 0 for result in results)
    assert all(result.mean_ms >= 0 for result in results)
    assert all(result.stdev_ms >= 0 for result in results)
    assert all(result.message_size_bytes >= 0 for result in results)
    assert all(result.unit == "ms" for result in results)
    assert len([result for result in results if result.operation == "public_verification"]) >= 2

    json_path, csv_path = write_results(results, tmp_path)
    assert json_path.exists()
    assert csv_path.exists()

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["schema"] == "evoting.benchmark.results.v1"
    assert payload["profile"] == "smoke"
    assert len(payload["results"]) == len(results)

    rendered = json_path.read_text(encoding="utf-8") + csv_path.read_text(encoding="utf-8")
    for marker in FORBIDDEN_MARKERS:
        assert marker not in rendered


def test_benchmark_cli_smoke_exits_zero_and_writes_files(tmp_path) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "evoting.benchmarks.runner",
            "--profile",
            "smoke",
            "--output",
            str(tmp_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert completed.returncode == 0
    assert "rsa_signature_key_generation" in completed.stdout
    assert "public_verification" in completed.stdout
    assert "full" not in completed.stdout.lower()
    assert list(tmp_path.glob("benchmark-smoke-*.json"))
    assert list(tmp_path.glob("benchmark-smoke-*.csv"))


def test_pytest_smoke_does_not_execute_full_profile() -> None:
    results = run_benchmark_profile("smoke")

    assert {result.profile for result in results} == {"smoke"}
