import pytest

from evoting.crypto.shamir import ShamirShare, reconstruct_secret, split_secret
from evoting.errors import CRYPTOGRAPHIC_ERROR_MESSAGE, CryptographicError


SECRET = bytes(range(32))


def test_reconstructs_with_exact_threshold() -> None:
    shares = split_secret(SECRET, threshold=3, share_count=5)

    assert reconstruct_secret(shares[:3], threshold=3) == SECRET


def test_reconstructs_with_more_than_threshold() -> None:
    shares = split_secret(SECRET, threshold=3, share_count=5)

    assert reconstruct_secret(shares[:4], threshold=3) == SECRET


def test_reconstructs_from_different_valid_subsets() -> None:
    shares = split_secret(SECRET, threshold=3, share_count=5)

    assert reconstruct_secret((shares[0], shares[2], shares[4]), threshold=3) == SECRET
    assert reconstruct_secret((shares[1], shares[3], shares[4]), threshold=3) == SECRET


def test_less_than_threshold_does_not_reconstruct() -> None:
    shares = split_secret(SECRET, threshold=3, share_count=5)

    with pytest.raises(CryptographicError) as exc_info:
        reconstruct_secret(shares[:2], threshold=3)

    assert str(exc_info.value) == CRYPTOGRAPHIC_ERROR_MESSAGE


@pytest.mark.parametrize(
    "secret",
    [
        b"",
        b"short",
        b"x" * 31,
        b"x" * 33,
    ],
)
def test_secret_must_be_exactly_32_bytes(secret: bytes) -> None:
    with pytest.raises(CryptographicError) as exc_info:
        split_secret(secret, threshold=2, share_count=3)

    assert str(exc_info.value) == CRYPTOGRAPHIC_ERROR_MESSAGE


@pytest.mark.parametrize(
    ("threshold", "share_count"),
    [
        (1, 3),
        (0, 3),
        (4, 3),
        (True, 3),
        (2, False),
    ],
)
def test_invalid_thresholds_are_rejected(threshold: int, share_count: int) -> None:
    with pytest.raises(CryptographicError) as exc_info:
        split_secret(SECRET, threshold=threshold, share_count=share_count)

    assert str(exc_info.value) == CRYPTOGRAPHIC_ERROR_MESSAGE


def test_altered_share_does_not_reconstruct_the_correct_key() -> None:
    shares = split_secret(SECRET, threshold=3, share_count=5)
    altered = (
        shares[0],
        ShamirShare(x=shares[1].x, y=(shares[1].y + 1)),
        shares[2],
    )

    try:
        reconstructed = reconstruct_secret(altered, threshold=3)
    except CryptographicError as exc:
        assert str(exc) == CRYPTOGRAPHIC_ERROR_MESSAGE
    else:
        assert reconstructed != SECRET
