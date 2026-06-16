import pytest

from evoting.errors import ModelValidationError
from evoting.gui.formatting import abbreviate_hex, short_hash, short_pseudonym, short_rid, yes_no


def test_hash_rid_and_pseudonym_are_abbreviated_by_default() -> None:
    value = bytes(range(32))
    expected = value.hex()[:12]

    assert short_hash(value) == expected
    assert short_rid(value) == expected
    assert short_pseudonym(value) == expected
    assert short_hash(value) != value.hex()


def test_abbreviation_accepts_text_and_none_without_expanding_values() -> None:
    value = "abcdef1234567890"

    assert abbreviate_hex(value, length=8) == "abcdef12"
    assert abbreviate_hex(None) == ""


def test_abbreviation_rejects_invalid_lengths_and_types() -> None:
    with pytest.raises(ModelValidationError):
        abbreviate_hex(b"abc", length=3)

    with pytest.raises(ModelValidationError):
        abbreviate_hex(object())


def test_yes_no_public_labels() -> None:
    assert yes_no(True) == "si"
    assert yes_no(False) == "no"
    assert yes_no(None) == "n/d"
