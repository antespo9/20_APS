from datetime import datetime, timezone

import pytest

from evoting.models import AuthorizationRequest, ElectionList, ElectionParams, ThresholdParams
from evoting.serialization import CanonicalSerializationError, canonical_bytes


def test_canonical_serialization_is_deterministic_and_order_independent() -> None:
    first = {"b": 2, "a": 1}
    second = {"a": 1, "b": 2}

    assert canonical_bytes(first) == canonical_bytes(second)
    assert canonical_bytes(first) == b'{"a":1,"b":2}'


def test_canonical_serialization_orders_nested_fields() -> None:
    value = {"outer": {"z": 3, "a": {"b": 2, "a": 1}}}

    assert canonical_bytes(value) == b'{"outer":{"a":{"a":1,"b":2},"z":3}}'


def test_canonical_serialization_has_no_insignificant_spaces() -> None:
    encoded = canonical_bytes({"b": [1, 2], "a": {"c": 3}})

    assert encoded == b'{"a":{"c":3},"b":[1,2]}'
    assert b" " not in encoded
    assert b"\n" not in encoded


def test_canonical_serialization_preserves_unicode_as_utf8() -> None:
    encoded = canonical_bytes({"label": "Lista Citta e Sanita"})
    unicode_encoded = canonical_bytes({"label": "Lista Città e Sanità"})

    assert encoded == b'{"label":"Lista Citta e Sanita"}'
    assert unicode_encoded == '{"label":"Lista Città e Sanità"}'.encode("utf-8")
    assert b"\\u" not in unicode_encoded


def test_canonical_serialization_encodes_bytes_with_standard_base64_padding() -> None:
    assert canonical_bytes({"payload": b"\x01\x02"}) == b'{"payload":{"__bytes__":"AQI="}}'


def test_canonical_serialization_handles_integers_and_model_nulls() -> None:
    params = ElectionParams(
        election_id="election-2026",
        lists=(ElectionList(code="L1", label="Lista Alfa"),),
        opens_at_ms=1_800_000_000_000,
        closes_at_ms=1_800_086_400_000,
        eligible_count=1,
        pk_ta_enc=b"ta enc",
        pk_ta_sig=b"ta sig",
        pk_ra=b"ra",
        pk_bb=b"bb",
        threshold=ThresholdParams(t=1, n=1),
        vmax=3,
        params_hash=None,
    )

    encoded = canonical_bytes(params)

    assert b'"eligible_count":1' in encoded
    assert b'"opens_at_ms":1800000000000' in encoded
    assert b'"params_hash":null' in encoded


def test_canonical_serialization_supports_nested_models() -> None:
    params = ElectionParams(
        election_id="election-2026",
        lists=(ElectionList(code="L2", label="Lista Beta"), ElectionList(code="L1", label="Lista Alfa")),
        opens_at_ms=10,
        closes_at_ms=20,
        eligible_count=2,
        pk_ta_enc=b"enc",
        pk_ta_sig=b"sig",
        pk_ra=b"ra",
        pk_bb=b"bb",
        threshold=ThresholdParams(t=1, n=2),
        vmax=3,
        params_hash=b"h" * 32,
    )

    encoded = canonical_bytes(params)

    assert b'"lists":[{"code":"L2","label":"Lista Beta"},{"code":"L1","label":"Lista Alfa"}]' in encoded
    assert b'"threshold":{"n":2,"t":1}' in encoded
    assert b'"params_hash":{"__bytes__":' in encoded


def test_canonical_serialization_output_for_signable_authorization_is_stable() -> None:
    request = AuthorizationRequest(
        election_id="election-2026",
        p_i=b"\x01" * 32,
        pk_vote_i=b"pk",
    )

    assert canonical_bytes(request) == (
        b'{"election_id":"election-2026",'
        b'"p_i":{"__bytes__":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="},'
        b'"pk_vote_i":{"__bytes__":"cGs="}}'
    )


@pytest.mark.parametrize(
    "value",
    [
        {"unsupported": {1, 2}},
        {"unsupported": datetime(2026, 6, 12, tzinfo=timezone.utc)},
        {"unsupported": 1.2},
        {"unsupported": True},
        {1: "non-string key"},
        {"__bytes__": "reserved"},
    ],
)
def test_canonical_serialization_rejects_unsupported_types(value: object) -> None:
    with pytest.raises(CanonicalSerializationError):
        canonical_bytes(value)


def test_canonical_serialization_does_not_mutate_inputs() -> None:
    value = {"items": [b"\x01\x02"], "nested": {"b": 2, "a": 1}}
    expected = {"items": [b"\x01\x02"], "nested": {"b": 2, "a": 1}}

    canonical_bytes(value)

    assert value == expected
