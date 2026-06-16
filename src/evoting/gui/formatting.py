"""Public formatting helpers for the local GUI."""

from __future__ import annotations

from evoting.errors import ModelValidationError


DEFAULT_ABBREVIATION_LENGTH = 12


def abbreviate_hex(value: bytes | str | None, *, length: int = DEFAULT_ABBREVIATION_LENGTH) -> str:
    """Return a short public prefix for a binary or hexadecimal protocol value."""

    if value is None:
        return ""
    if not isinstance(length, int) or isinstance(length, bool) or length < 4:
        raise ModelValidationError("abbreviation length must be an integer greater than or equal to 4")
    if isinstance(value, bytes):
        rendered = value.hex()
    elif isinstance(value, str):
        rendered = value.strip()
    else:
        raise ModelValidationError("value must be bytes, text or None")
    if not rendered:
        return ""
    return rendered[:length]


def short_rid(value: bytes | str | None) -> str:
    return abbreviate_hex(value)


def short_hash(value: bytes | str | None) -> str:
    return abbreviate_hex(value)


def short_pseudonym(value: bytes | str | None) -> str:
    return abbreviate_hex(value)


def yes_no(value: bool | None) -> str:
    if value is None:
        return "n/d"
    return "si" if value else "no"


__all__ = [
    "DEFAULT_ABBREVIATION_LENGTH",
    "abbreviate_hex",
    "short_hash",
    "short_pseudonym",
    "short_rid",
    "yes_no",
]
