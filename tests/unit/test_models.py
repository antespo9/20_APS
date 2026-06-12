import pytest

from evoting.errors import ModelValidationError
from evoting.models import (
    Ack,
    AuthorizationRequest,
    BoardEntry,
    BoardEntryType,
    CloseEntry,
    CloseState,
    ElectionList,
    ElectionParams,
    TallyResult,
    ThresholdParams,
    VoteMessage,
    VotePackage,
)


HASH = b"h" * 32


def test_election_params_accept_protocol_shape() -> None:
    params = ElectionParams(
        election_id="election-2026",
        lists=(ElectionList(code="L1", label="Lista Alfa"), ElectionList(code="L2", label="Lista Beta")),
        opens_at_ms=1_800_000_000_000,
        closes_at_ms=1_800_086_400_000,
        eligible_count=2,
        pk_ta_enc=b"ta enc public key",
        pk_ta_sig=b"ta sig public key",
        pk_ra=b"ra public key",
        pk_bb=b"bb public key",
        threshold=ThresholdParams(t=3, n=5),
        vmax=3,
        params_hash=None,
    )

    assert params.election_id == "election-2026"
    assert params.params_hash is None
    assert params.threshold.t == 3


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("election_id", "bad id"),
        ("lists", (ElectionList(code="L1", label="One"), ElectionList(code="L1", label="Duplicate"))),
        ("opens_at_ms", 20),
        ("eligible_count", 0),
        ("pk_ra", b""),
        ("vmax", 0),
        ("params_hash", b"short"),
    ],
)
def test_election_params_reject_invalid_structure(field: str, value: object) -> None:
    kwargs = {
        "election_id": "election-2026",
        "lists": (ElectionList(code="L1", label="Lista Alfa"),),
        "opens_at_ms": 10,
        "closes_at_ms": 20,
        "eligible_count": 1,
        "pk_ta_enc": b"ta enc",
        "pk_ta_sig": b"ta sig",
        "pk_ra": b"ra",
        "pk_bb": b"bb",
        "threshold": ThresholdParams(t=1, n=1),
        "vmax": 1,
        "params_hash": None,
    }
    kwargs[field] = value

    with pytest.raises(ValueError):
        ElectionParams(**kwargs)


def test_threshold_rejects_impossible_values() -> None:
    with pytest.raises(ModelValidationError):
        ThresholdParams(t=4, n=3)

    with pytest.raises(ModelValidationError):
        ThresholdParams(t=0, n=3)


@pytest.mark.parametrize(
    "model",
    [
        AuthorizationRequest(election_id="election-2026", p_i=HASH, pk_vote_i=b"vote public key"),
        VoteMessage(election_id="election-2026", p_i=HASH, c=b"ciphertext", pk_vote_i=b"vote public key", v_i=1),
        VotePackage(c=b"ciphertext", p_i=HASH, pk_vote_i=b"vote public key", tau_i=b"ra signature", v_i=1, sigma_i=b"vote signature"),
        BoardEntry(
            type=BoardEntryType.BALLOT,
            election_id="election-2026",
            c=b"ciphertext",
            p_i=HASH,
            pk_vote_i=b"vote public key",
            tau_i=b"ra signature",
            v_i=1,
            sigma_i=b"vote signature",
            rid=HASH,
            timestamp_ms=1_800_000_000_123,
        ),
        CloseEntry(type=BoardEntryType.CLOSE, election_id="election-2026", timestamp_ms=1_800_000_000_456),
        Ack(election_id="election-2026", index=0, rid=HASH, chain_hash=HASH, signature_bb=b"bb signature"),
        CloseState(election_id="election-2026", h_close=HASH, signature_bb=b"bb signature"),
        TallyResult(election_id="election-2026", h_close=HASH, totals_by_list={"L1": 2, "L2": 0}, anomalous_count=1, signature_ta=b"ta signature"),
    ],
)
def test_main_protocol_models_accept_valid_structure(model: object) -> None:
    assert model is not None


@pytest.mark.parametrize(
    "factory",
    [
        lambda: AuthorizationRequest(election_id="election-2026", p_i=b"short", pk_vote_i=b"vote public key"),
        lambda: VoteMessage(election_id="election-2026", p_i=HASH, c=b"ciphertext", pk_vote_i=b"vote public key", v_i=0),
        lambda: VotePackage(c=b"ciphertext", p_i=HASH, pk_vote_i=b"vote public key", tau_i=b"ra signature", v_i=-1, sigma_i=b"vote signature"),
        lambda: BoardEntry(type=BoardEntryType.CLOSE, election_id="election-2026", c=b"ciphertext", p_i=HASH, pk_vote_i=b"vote public key", tau_i=b"ra signature", v_i=1, sigma_i=b"vote signature", rid=HASH, timestamp_ms=1),
        lambda: CloseEntry(type=BoardEntryType.BALLOT, election_id="election-2026", timestamp_ms=1),
        lambda: Ack(election_id="election-2026", index=-1, rid=HASH, chain_hash=HASH, signature_bb=b"bb signature"),
        lambda: CloseState(election_id="election-2026", h_close=b"short", signature_bb=b"bb signature"),
        lambda: TallyResult(election_id="election-2026", h_close=HASH, totals_by_list={"bad code": 1}, anomalous_count=0, signature_ta=b"ta signature"),
    ],
)
def test_main_protocol_models_reject_invalid_structure(factory) -> None:
    with pytest.raises(ValueError):
        factory()
