"""Textual local demonstration for the complete election workflow."""

from __future__ import annotations

from pathlib import Path
import sys
import tempfile

from evoting.config import default_demo_profile
from evoting.workflow import CompleteWorkflowSummary, run_complete_election_workflow


def main() -> int:
    runtime_parent = Path("runtime") / "demo"
    runtime_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="milestone-7a-", dir=runtime_parent) as runtime_dir:
        profile = default_demo_profile(runtime_dir=runtime_dir)
        summary = run_complete_election_workflow(profile)

    print(_format_summary(summary))
    return 0 if summary.verifications.all_passed else 1


def _format_summary(summary: CompleteWorkflowSummary) -> str:
    lines = [
        "Milestone 7A - demo workflow completo",
        f"Elezione: {summary.election_id}",
        f"Parametri: Vmax={summary.vmax}, soglia={summary.threshold[0]}/{summary.threshold[1]}, elettori={summary.voter_count}",
        f"Setup: params={summary.params_hash}, blobTA={'presente' if summary.blob_ta_present else 'assente'}, quote={summary.commissioner_share_count}",
        "",
        "Liste pubblicate:",
    ]
    for code, label in summary.lists:
        lines.append(f"  - {code}: {label}")

    lines.extend(["", "Ricevute accettate:"])
    for receipt in summary.receipts:
        status = "valida" if receipt.receipt_valid else "non valida"
        lines.append(
            f"  - #{receipt.sequence}: v{receipt.version}, RID {receipt.rid}, ricevuta {status}, stato v{receipt.stored_state_version}"
        )

    lines.extend(["", "Registro pubblico:"])
    for record in summary.ballot_records:
        final = "finale" if record.final else "sostituita"
        lines.append(f"  - entry {record.index}: v{record.version}, RID {record.rid}, {final}")

    lines.extend(
        [
            "",
            f"Chiusura: entry {summary.close_index}, h_close {summary.h_close}",
            "",
            "Totali pubblici:",
        ]
    )
    for code, _ in summary.lists:
        lines.append(f"  - {code}: {summary.totals_by_list[code]}")
    lines.append(f"  - anomalie: {summary.anomalous_count}")
    lines.append(
        f"  - schede finali: {summary.final_ballot_count}, valide: {summary.valid_ballot_count}"
    )

    checks = (
        ("ricevute", summary.verifications.receipts_valid),
        ("hash chain", summary.verifications.hash_chain_valid),
        ("registro pubblico", summary.verifications.public_log_valid),
        ("firma TA", summary.verifications.tally_signature_valid),
        ("verifica pubblica", summary.verifications.public_election_valid),
    )
    lines.extend(["", "Verifiche:"])
    for label, ok in checks:
        lines.append(f"  - {label}: {'OK' if ok else 'FALLITA'}")
    lines.append(f"Esito finale: {'OK' if summary.verifications.all_passed else 'FALLITO'}")
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
