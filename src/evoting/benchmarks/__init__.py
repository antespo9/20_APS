"""Performance benchmarks for the local e-voting prototype."""

from evoting.benchmarks.models import BenchmarkResult
from evoting.benchmarks.scenarios import run_benchmark_profile

__all__ = ["BenchmarkResult", "run_benchmark_profile"]
