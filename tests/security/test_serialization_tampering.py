import hashlib

from evoting.models import (
    AuthorizationRequest,
    BoardEntry,
    BoardEntryType,
    ElectionList,
    ElectionParams,
    ThresholdParams,
    VoteMessage,
)
from evoting.serialization import canonical_bytes


PSEUDONYM = b"p" * 32
RID = b"r" * 32


def _digest(value: object) -> bytes:
    return hashlib.sha256(canonical_bytes(value)).digest()


def test_tampered_message_field_changes_canonical_bytes_and_digest() -> None:
    original = AuthorizationRequest(
        election_id="election-2026",
        p_i=PSEUDONYM,
        pk_vote_i=b"vote public key",
    )
    tampered = AuthorizationRequest(
        election_id="election-2027",
        p_i=PSEUDONYM,
        pk_vote_i=b"vote public key",
    )

    assert canonical_bytes(original) != canonical_bytes(tampered)
    assert _digest(original) != _digest(tampered)


def test_tampered_binary_field_changes_canonical_bytes_and_digest() -> None:
    original = VoteMessage(
        election_id="election-2026",
        p_i=PSEUDONYM,
        c=b"ciphertext-a",
        pk_vote_i=b"vote public key",
        v_i=1,
    )
    tampered = VoteMessage(
        election_id="election-2026",
        p_i=PSEUDONYM,
        c=b"ciphertext-b",
        pk_vote_i=b"vote public key",
        v_i=1,
    )

    assert canonical_bytes(original) != canonical_bytes(tampered)
    assert _digest(original) != _digest(tampered)


def test_tampered_timestamp_changes_canonical_bytes_and_digest() -> None:
    original = BoardEntry(
        type=BoardEntryType.BALLOT,
        election_id="election-2026",
        c=b"ciphertext",
        p_i=PSEUDONYM,
        pk_vote_i=b"vote public key",
        tau_i=b"ra signature",
        v_i=1,
        sigma_i=b"vote signature",
        rid=RID,
        timestamp_ms=1_800_000_000_000,
    )
    tampered = BoardEntry(
        type=BoardEntryType.BALLOT,
        election_id="election-2026",
        c=b"ciphertext",
        p_i=PSEUDONYM,
        pk_vote_i=b"vote public key",
        tau_i=b"ra signature",
        v_i=1,
        sigma_i=b"vote signature",
        rid=RID,
        timestamp_ms=1_800_000_000_001,
    )

    assert canonical_bytes(original) != canonical_bytes(tampered)
    assert _digest(original) != _digest(tampered)


def test_tampered_version_changes_canonical_bytes_and_digest() -> None:
    original = VoteMessage(
        election_id="election-2026",
        p_i=PSEUDONYM,
        c=b"ciphertext",
        pk_vote_i=b"vote public key",
        v_i=1,
    )
    tampered = VoteMessage(
        election_id="election-2026",
        p_i=PSEUDONYM,
        c=b"ciphertext",
        pk_vote_i=b"vote public key",
        v_i=2,
    )

    assert canonical_bytes(original) != canonical_bytes(tampered)
    assert _digest(original) != _digest(tampered)


def test_null_and_present_value_are_canonically_distinct_when_allowed() -> None:
    without_hash = ElectionParams(
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
    with_hash = ElectionParams(
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
        params_hash=b"h" * 32,
    )

    assert b'"params_hash":null' in canonical_bytes(without_hash)
    assert canonical_bytes(without_hash) != canonical_bytes(with_hash)
    assert _digest(without_hash) != _digest(with_hash)


def test_logically_identical_representations_produce_same_canonical_bytes() -> None:
    first = {
        "election_id": "election-2026",
        "p_i": PSEUDONYM,
        "pk_vote_i": b"vote public key",
    }
    second = {
        "pk_vote_i": b"vote public key",
        "p_i": PSEUDONYM,
        "election_id": "election-2026",
    }

    assert canonical_bytes(first) == canonical_bytes(second)
    assert _digest(first) == _digest(second)


def test_semantically_relevant_changes_produce_different_canonical_bytes() -> None:
    baseline = {
        "election_id": "election-2026",
        "p_i": PSEUDONYM,
        "pk_vote_i": b"vote public key",
        "v_i": 1,
    }
    changed_values = [
        {**baseline, "election_id": "election-2027"},
        {**baseline, "p_i": b"q" * 32},
        {**baseline, "pk_vote_i": b"other vote public key"},
        {**baseline, "v_i": 2},
    ]

    baseline_bytes = canonical_bytes(baseline)
    baseline_digest = _digest(baseline)

    for changed in changed_values:
        assert canonical_bytes(changed) != baseline_bytes
        assert _digest(changed) != baseline_digest
