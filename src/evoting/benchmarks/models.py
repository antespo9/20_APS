"""Structured benchmark result records."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import statistics
from typing import Any


@dataclass(frozen=True, slots=True)
class BenchmarkResult:
    """Aggregate timings for one measured protocol operation."""

    operation: str
    profile: str
    input_size: str
    input_scale: int
    warmups: int
    repetitions: int
    min_ms: float
    median_ms: float
    mean_ms: float
    stdev_ms: float
    unit: str = "ms"
    message_size_bytes: int = 0
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.operation or not self.profile or not self.input_size:
            raise ValueError("benchmark result identifiers must be non-empty")
        for field_name in ("input_scale", "warmups", "repetitions", "message_size_bytes"):
            value = getattr(self, field_name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{field_name} must be a non-negative integer")
        if self.repetitions < 1:
            raise ValueError("repetitions must be positive")
        for field_name in ("min_ms", "median_ms", "mean_ms", "stdev_ms"):
            value = getattr(self, field_name)
            if not isinstance(value, (int, float)) or value < 0:
                raise ValueError(f"{field_name} must be a non-negative number")
        if self.unit != "ms":
            raise ValueError("benchmark timings are stored in milliseconds")

    @classmethod
    def from_samples(
        cls,
        *,
        operation: str,
        profile: str,
        input_size: str,
        input_scale: int,
        warmups: int,
        repetitions: int,
        samples_ns: list[int],
        message_size_bytes: int = 0,
        notes: str = "",
    ) -> "BenchmarkResult":
        if len(samples_ns) != repetitions:
            raise ValueError("sample count must match repetitions")
        samples_ms = [sample / 1_000_000 for sample in samples_ns]
        stdev_ms = statistics.stdev(samples_ms) if len(samples_ms) > 1 else 0.0
        return cls(
            operation=operation,
            profile=profile,
            input_size=input_size,
            input_scale=input_scale,
            warmups=warmups,
            repetitions=repetitions,
            min_ms=min(samples_ms),
            median_ms=statistics.median(samples_ms),
            mean_ms=statistics.fmean(samples_ms),
            stdev_ms=stdev_ms,
            message_size_bytes=message_size_bytes,
            notes=notes,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


CSV_FIELDS = (
    "operation",
    "profile",
    "input_size",
    "input_scale",
    "warmups",
    "repetitions",
    "min_ms",
    "median_ms",
    "mean_ms",
    "stdev_ms",
    "unit",
    "message_size_bytes",
    "notes",
)


__all__ = ["BenchmarkResult", "CSV_FIELDS"]
