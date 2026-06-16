"""Command-line runner for WP4 performance benchmarks."""

from __future__ import annotations

import argparse
import csv
from datetime import UTC, datetime
import json
from pathlib import Path
import sys

from evoting.benchmarks.models import CSV_FIELDS, BenchmarkResult
from evoting.benchmarks.scenarios import PROFILES, run_benchmark_profile


DEFAULT_OUTPUT_DIR = Path("runtime") / "benchmarks"


def main(argv: list[str] | None = None) -> int:
    parser = _argument_parser()
    args = parser.parse_args(argv)
    try:
        results = run_benchmark_profile(args.profile)
        output_dir = Path(args.output)
        json_path, csv_path = write_results(results, output_dir)
        print(format_table(results))
        print()
        print(f"JSON: {json_path}")
        print(f"CSV:  {csv_path}")
    except Exception as exc:
        print(f"benchmark failed: {exc}", file=sys.stderr)
        return 1
    return 0


def write_results(results: list[BenchmarkResult], output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    profile = _single_profile(results)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    json_path = output_dir / f"benchmark-{profile}-{timestamp}.json"
    csv_path = output_dir / f"benchmark-{profile}-{timestamp}.csv"

    payload = {
        "schema": "evoting.benchmark.results.v1",
        "profile": profile,
        "generated_at_utc": timestamp,
        "results": [result.to_dict() for result in results],
    }
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for result in results:
            writer.writerow(result.to_dict())
    return json_path, csv_path


def format_table(results: list[BenchmarkResult]) -> str:
    headers = ("operation", "scale", "reps", "min_ms", "median_ms", "mean_ms", "stdev_ms", "bytes")
    rows = [
        (
            result.operation,
            str(result.input_scale),
            str(result.repetitions),
            _fmt(result.min_ms),
            _fmt(result.median_ms),
            _fmt(result.mean_ms),
            _fmt(result.stdev_ms),
            str(result.message_size_bytes),
        )
        for result in results
    ]
    widths = [
        max(len(headers[index]), *(len(row[index]) for row in rows))
        for index in range(len(headers))
    ]
    header_line = "  ".join(headers[index].ljust(widths[index]) for index in range(len(headers)))
    rule = "  ".join("-" * widths[index] for index in range(len(headers)))
    body = [
        "  ".join(row[index].ljust(widths[index]) for index in range(len(headers)))
        for row in rows
    ]
    return "\n".join([header_line, rule, *body])


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run WP4 e-voting performance benchmarks.")
    parser.add_argument(
        "--profile",
        choices=sorted(PROFILES),
        required=True,
        help="benchmark profile to execute",
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT_DIR),
        help="directory for JSON and CSV results",
    )
    return parser


def _single_profile(results: list[BenchmarkResult]) -> str:
    profiles = {result.profile for result in results}
    if len(profiles) != 1:
        raise ValueError("all benchmark results must have one profile")
    return profiles.pop()


def _fmt(value: float) -> str:
    return f"{value:.3f}"


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["DEFAULT_OUTPUT_DIR", "format_table", "main", "write_results"]
