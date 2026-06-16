"""Centralized configuration profiles for local demonstration workflows."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re

from evoting.crypto.password import ScryptParameters
from evoting.errors import ModelValidationError
from evoting.models import ElectionList, ThresholdParams


DEFAULT_ELECTION_ID = "demo-election-2026"
DEFAULT_OPEN_MS = 1_800_000_000_000
DEFAULT_CLOSE_MS = DEFAULT_OPEN_MS + 60_000
DEFAULT_VMAX = 3
DEFAULT_THRESHOLD_T = 3
DEFAULT_THRESHOLD_N = 5

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")


@dataclass(frozen=True, slots=True)
class DemoVoter:
    """Fictional voter identity used only inside the local prototype."""

    institutional_id: str
    local_voter_id: str

    def __post_init__(self) -> None:
        _validate_identifier(self.institutional_id, "institutional_id")
        _validate_identifier(self.local_voter_id, "local_voter_id")


@dataclass(frozen=True, slots=True)
class DemoVotePlan:
    """Plaintext choices used internally to drive a repeatable local scenario."""

    initial_vote_codes: tuple[str, ...]
    replacement_voter_index: int | None = None
    replacement_vote_code: str | None = None

    def __post_init__(self) -> None:
        codes = _as_tuple(self.initial_vote_codes, "initial_vote_codes")
        for code in codes:
            _validate_identifier(code, "initial_vote_codes item")
        object.__setattr__(self, "initial_vote_codes", codes)

        if self.replacement_voter_index is None or self.replacement_vote_code is None:
            if self.replacement_voter_index is not None or self.replacement_vote_code is not None:
                raise ModelValidationError("replacement configuration must be complete")
            return

        if (
            not isinstance(self.replacement_voter_index, int)
            or isinstance(self.replacement_voter_index, bool)
            or self.replacement_voter_index < 0
        ):
            raise ModelValidationError("replacement_voter_index must be a non-negative integer")
        _validate_identifier(self.replacement_vote_code, "replacement_vote_code")


@dataclass(frozen=True, slots=True)
class DemoProfile:
    """Configurable public profile for the stand-alone demonstration election."""

    election_id: str
    lists: tuple[ElectionList, ...]
    vmax: int
    threshold: ThresholdParams
    voters: tuple[DemoVoter, ...]
    opens_at_ms: int
    closes_at_ms: int
    vote_plan: DemoVotePlan
    commissioner_ids: tuple[str, ...]
    runtime_dir: Path = Path("runtime")
    scrypt_parameters: ScryptParameters = field(default_factory=ScryptParameters)

    def __post_init__(self) -> None:
        _validate_identifier(self.election_id, "election_id")
        _validate_positive_int(self.vmax, "vmax")
        if not isinstance(self.threshold, ThresholdParams):
            raise ModelValidationError("threshold must be ThresholdParams")

        lists = _as_tuple(self.lists, "lists")
        if not all(isinstance(item, ElectionList) for item in lists):
            raise ModelValidationError("lists must contain ElectionList values")
        list_codes = tuple(item.code for item in lists)
        if len(set(list_codes)) != len(list_codes):
            raise ModelValidationError("list codes must be unique")
        object.__setattr__(self, "lists", lists)

        voters = _as_tuple(self.voters, "voters")
        if not all(isinstance(item, DemoVoter) for item in voters):
            raise ModelValidationError("voters must contain DemoVoter values")
        institutional_ids = tuple(item.institutional_id for item in voters)
        local_ids = tuple(item.local_voter_id for item in voters)
        if len(set(institutional_ids)) != len(institutional_ids):
            raise ModelValidationError("institutional voter identifiers must be unique")
        if len(set(local_ids)) != len(local_ids):
            raise ModelValidationError("local voter identifiers must be unique")
        object.__setattr__(self, "voters", voters)

        _validate_timestamp(self.opens_at_ms, "opens_at_ms")
        _validate_timestamp(self.closes_at_ms, "closes_at_ms")
        if self.opens_at_ms >= self.closes_at_ms:
            raise ModelValidationError("opens_at_ms must be before closes_at_ms")

        if not isinstance(self.vote_plan, DemoVotePlan):
            raise ModelValidationError("vote_plan must be DemoVotePlan")
        if len(self.vote_plan.initial_vote_codes) != len(voters):
            raise ModelValidationError("vote plan must contain one initial vote per voter")
        for code in self.vote_plan.initial_vote_codes:
            if code not in list_codes:
                raise ModelValidationError("initial vote code is not in the configured lists")
        if self.vote_plan.replacement_vote_code is not None:
            if self.vmax < 2:
                raise ModelValidationError("vmax must allow the configured replacement")
            if self.vote_plan.replacement_voter_index is None:
                raise ModelValidationError("replacement voter index is required")
            if self.vote_plan.replacement_voter_index >= len(voters):
                raise ModelValidationError("replacement voter index is outside the voter set")
            if self.vote_plan.replacement_vote_code not in list_codes:
                raise ModelValidationError("replacement vote code is not in the configured lists")

        commissioner_ids = _as_tuple(self.commissioner_ids, "commissioner_ids")
        for commissioner_id in commissioner_ids:
            _validate_identifier(commissioner_id, "commissioner_id")
        if len(commissioner_ids) != self.threshold.n:
            raise ModelValidationError("commissioner_ids length must match threshold.n")
        if len(set(commissioner_ids)) != len(commissioner_ids):
            raise ModelValidationError("commissioner_ids must be unique")
        object.__setattr__(self, "commissioner_ids", commissioner_ids)

        if not isinstance(self.runtime_dir, Path):
            object.__setattr__(self, "runtime_dir", Path(self.runtime_dir))
        if not isinstance(self.scrypt_parameters, ScryptParameters):
            raise ModelValidationError("scrypt_parameters must be ScryptParameters")

    @property
    def voter_count(self) -> int:
        return len(self.voters)

    @property
    def allowed_list_codes(self) -> tuple[str, ...]:
        return tuple(item.code for item in self.lists)


def default_demo_profile(
    *,
    runtime_dir: str | Path = Path("runtime"),
    scrypt_parameters: ScryptParameters | None = None,
) -> DemoProfile:
    """Return the default fictional profile for the repeatable local demo."""

    return DemoProfile(
        election_id=DEFAULT_ELECTION_ID,
        lists=(
            ElectionList(code="LIST-001", label="Lista Alfa"),
            ElectionList(code="LIST-002", label="Lista Beta"),
            ElectionList(code="LIST-003", label="Lista Gamma"),
        ),
        vmax=DEFAULT_VMAX,
        threshold=ThresholdParams(t=DEFAULT_THRESHOLD_T, n=DEFAULT_THRESHOLD_N),
        voters=(
            DemoVoter(institutional_id="engineer-001", local_voter_id="local-voter-001"),
            DemoVoter(institutional_id="engineer-002", local_voter_id="local-voter-002"),
            DemoVoter(institutional_id="engineer-003", local_voter_id="local-voter-003"),
        ),
        opens_at_ms=DEFAULT_OPEN_MS,
        closes_at_ms=DEFAULT_CLOSE_MS,
        vote_plan=DemoVotePlan(
            initial_vote_codes=("LIST-001", "LIST-002", "LIST-003"),
            replacement_voter_index=2,
            replacement_vote_code="LIST-002",
        ),
        commissioner_ids=tuple(
            f"commissioner-{index:03d}" for index in range(1, DEFAULT_THRESHOLD_N + 1)
        ),
        runtime_dir=Path(runtime_dir),
        scrypt_parameters=scrypt_parameters or ScryptParameters(),
    )


def _as_tuple(values: tuple | list, field_name: str) -> tuple:
    if not isinstance(values, (tuple, list)) or len(values) == 0:
        raise ModelValidationError(f"{field_name} must be a non-empty sequence")
    return tuple(values)


def _validate_identifier(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not _IDENTIFIER_RE.fullmatch(value):
        raise ModelValidationError(f"{field_name} must be a non-empty protocol identifier")


def _validate_positive_int(value: int, field_name: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ModelValidationError(f"{field_name} must be a positive integer")


def _validate_timestamp(value: int, field_name: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ModelValidationError(f"{field_name} must be a non-negative timestamp")


__all__ = [
    "DEFAULT_CLOSE_MS",
    "DEFAULT_ELECTION_ID",
    "DEFAULT_OPEN_MS",
    "DEFAULT_THRESHOLD_N",
    "DEFAULT_THRESHOLD_T",
    "DEFAULT_VMAX",
    "DemoProfile",
    "DemoVotePlan",
    "DemoVoter",
    "default_demo_profile",
]
