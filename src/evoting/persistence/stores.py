"""Small JSON file stores for the stand-alone runtime."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
import tempfile
from typing import Any

from evoting.errors import EvotingError


DEFAULT_RUNTIME_DIR = Path("runtime")
RA_REGISTRY_RELATIVE_PATH = Path("ra") / "registry.json"
VOTER_STATE_FILENAME = "state.enc.json"
_SAFE_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")


class StoreError(EvotingError):
    """Raised for local persistence failures."""


@dataclass(frozen=True, slots=True)
class JsonFileStore:
    path: Path

    def __init__(self, path: str | Path) -> None:
        object.__setattr__(self, "path", Path(path))

    def exists(self) -> bool:
        return self.path.exists()

    def read(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                value = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise StoreError("persistence operation failed") from exc
        if not isinstance(value, dict):
            raise StoreError("persistence operation failed")
        return value

    def write(self, value: dict[str, Any]) -> None:
        if not isinstance(value, dict):
            raise StoreError("persistence operation failed")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=self.path.parent,
                delete=False,
                prefix=f".{self.path.name}.",
                suffix=".tmp",
            ) as handle:
                json.dump(value, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                temp_path = Path(handle.name)
            temp_path.replace(self.path)
        except OSError as exc:
            raise StoreError("persistence operation failed") from exc
        finally:
            if temp_path is not None and temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass


def default_ra_store_path(runtime_dir: str | Path = DEFAULT_RUNTIME_DIR) -> Path:
    return Path(runtime_dir) / RA_REGISTRY_RELATIVE_PATH


def default_voter_state_path(
    local_voter_id: str,
    runtime_dir: str | Path = DEFAULT_RUNTIME_DIR,
) -> Path:
    if not isinstance(local_voter_id, str) or not _SAFE_COMPONENT_RE.fullmatch(local_voter_id):
        raise StoreError("persistence operation failed")
    return Path(runtime_dir) / "voters" / local_voter_id / VOTER_STATE_FILENAME


__all__ = [
    "DEFAULT_RUNTIME_DIR",
    "JsonFileStore",
    "RA_REGISTRY_RELATIVE_PATH",
    "StoreError",
    "VOTER_STATE_FILENAME",
    "default_ra_store_path",
    "default_voter_state_path",
]
