"""Canonical serialization for protocol values."""

from __future__ import annotations

import base64
from collections.abc import Mapping, Sequence
from dataclasses import fields, is_dataclass
from enum import Enum
import json
from typing import Any


class CanonicalSerializationError(TypeError):
    """Raised when a value cannot be represented canonically."""


_BYTES_MARKER = "__bytes__"


def canonical_bytes(value: Any) -> bytes:
    """Return the deterministic UTF-8 JSON representation of a protocol value."""

    normalized = _normalize(value)
    try:
        text = json.dumps(
            normalized,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise CanonicalSerializationError(
            f"unsupported value for canonical serialization: {type(value).__name__}"
        ) from exc
    return text.encode("utf-8")


def _normalize(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: _normalize(getattr(value, field.name)) for field in fields(value)}

    if isinstance(value, bytes):
        return {_BYTES_MARKER: base64.b64encode(value).decode("ascii")}

    if isinstance(value, Enum):
        return _normalize(value.value)

    if value is None or isinstance(value, str):
        return value

    if isinstance(value, bool):
        raise CanonicalSerializationError("bool is not a supported protocol value")

    if isinstance(value, int):
        return value

    if isinstance(value, Mapping):
        normalized_mapping: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalSerializationError("mapping keys must be strings")
            if key == _BYTES_MARKER:
                raise CanonicalSerializationError(f"mapping key {_BYTES_MARKER!r} is reserved")
            normalized_mapping[key] = _normalize(item)
        return normalized_mapping

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_normalize(item) for item in value]

    raise CanonicalSerializationError(
        f"unsupported value for canonical serialization: {type(value).__name__}"
    )


__all__ = ["CanonicalSerializationError", "canonical_bytes"]
