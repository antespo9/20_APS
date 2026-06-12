import inspect

import pytest

from evoting.crypto import hashes
from evoting.crypto.hashes import SHA256_DIGEST_SIZE, sha256_digest
from evoting.errors import CRYPTOGRAPHIC_ERROR_MESSAGE, CryptographicError


def test_sha256_digest_known_value() -> None:
    assert sha256_digest(b"abc").hex() == (
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad"
    )


def test_sha256_digest_returns_bytes_with_expected_size() -> None:
    digest = sha256_digest(b"protocol value")

    assert isinstance(digest, bytes)
    assert len(digest) == SHA256_DIGEST_SIZE


@pytest.mark.parametrize("value", ["abc", bytearray(b"abc"), memoryview(b"abc"), 123])
def test_sha256_digest_accepts_only_bytes(value: object) -> None:
    with pytest.raises(CryptographicError) as exc_info:
        sha256_digest(value)  # type: ignore[arg-type]

    assert str(exc_info.value) == CRYPTOGRAPHIC_ERROR_MESSAGE


def test_hash_module_does_not_use_md5_or_sha1() -> None:
    source = inspect.getsource(hashes).lower()

    assert "md5" not in source
    assert "sha1" not in source
