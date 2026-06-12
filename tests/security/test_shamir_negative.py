import pytest

from evoting.crypto.shamir import FIELD_PRIME, ShamirShare, reconstruct_secret, split_secret
from evoting.errors import CRYPTOGRAPHIC_ERROR_MESSAGE, CryptographicError


SECRET = b"s" * 32


def test_duplicate_shares_are_rejected() -> None:
    shares = split_secret(SECRET, threshold=3, share_count=5)
    duplicated = (shares[0], shares[1], ShamirShare(x=shares[1].x, y=shares[2].y))

    with pytest.raises(CryptographicError) as exc_info:
        reconstruct_secret(duplicated, threshold=3)

    assert str(exc_info.value) == CRYPTOGRAPHIC_ERROR_MESSAGE


def test_zero_index_is_rejected() -> None:
    with pytest.raises(CryptographicError) as exc_info:
        ShamirShare(x=0, y=1)

    assert str(exc_info.value) == CRYPTOGRAPHIC_ERROR_MESSAGE


@pytest.mark.parametrize(
    ("x", "y"),
    [
        (FIELD_PRIME, 1),
        (1, FIELD_PRIME),
        (-1, 1),
        (1, -1),
        (True, 1),
        (1, False),
    ],
)
def test_out_of_field_values_are_rejected(x: int, y: int) -> None:
    with pytest.raises(CryptographicError) as exc_info:
        ShamirShare(x=x, y=y)

    assert str(exc_info.value) == CRYPTOGRAPHIC_ERROR_MESSAGE


@pytest.mark.parametrize(
    "shares",
    [
        object(),
        b"not shares",
        [object(), object()],
        [("x", "y")],
    ],
)
def test_malformed_shares_are_rejected(shares: object) -> None:
    with pytest.raises(CryptographicError) as exc_info:
        reconstruct_secret(shares, threshold=2)

    assert str(exc_info.value) == CRYPTOGRAPHIC_ERROR_MESSAGE


def test_null_or_empty_share_sequence_is_rejected() -> None:
    with pytest.raises(CryptographicError) as exc_info:
        reconstruct_secret([], threshold=2)

    assert str(exc_info.value) == CRYPTOGRAPHIC_ERROR_MESSAGE
