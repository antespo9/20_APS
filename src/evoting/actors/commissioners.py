"""Commissioner share custody for the local prototype."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from evoting.crypto.shamir import ShamirShare
from evoting.errors import CRYPTOGRAPHIC_ERROR_MESSAGE, CryptographicError


@dataclass(frozen=True, slots=True)
class CommissionerShare:
    commissioner_id: str
    election_id: str
    share: ShamirShare

    def __post_init__(self) -> None:
        _require_identifier(self.commissioner_id)
        _require_identifier(self.election_id)
        if not isinstance(self.share, ShamirShare):
            raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)


@dataclass(frozen=True, slots=True)
class CommissionerSet:
    election_id: str
    shares: tuple[CommissionerShare, ...]

    def __post_init__(self) -> None:
        _require_identifier(self.election_id)
        if not isinstance(self.shares, tuple) or not self.shares:
            raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)

        commissioner_ids: set[str] = set()
        share_x_values: set[int] = set()
        for item in self.shares:
            if not isinstance(item, CommissionerShare) or item.election_id != self.election_id:
                raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
            if item.commissioner_id in commissioner_ids or item.share.x in share_x_values:
                raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
            commissioner_ids.add(item.commissioner_id)
            share_x_values.add(item.share.x)

    @classmethod
    def from_shares(
        cls,
        election_id: str,
        shares: Sequence[ShamirShare],
        commissioner_ids: Sequence[str] | None = None,
    ) -> "CommissionerSet":
        if not isinstance(shares, Sequence) or isinstance(shares, (bytes, bytearray, str)):
            raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)
        if commissioner_ids is None:
            normalized_ids = tuple(f"commissioner-{index}" for index in range(1, len(shares) + 1))
        else:
            normalized_ids = tuple(commissioner_ids)
        if len(normalized_ids) != len(shares):
            raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)

        return cls(
            election_id=election_id,
            shares=tuple(
                CommissionerShare(commissioner_id=commissioner_id, election_id=election_id, share=share)
                for commissioner_id, share in zip(normalized_ids, shares, strict=True)
            ),
        )

    def collect(self, commissioner_ids: Iterable[str]) -> tuple[CommissionerShare, ...]:
        requested_ids = tuple(commissioner_ids)
        if not requested_ids or len(set(requested_ids)) != len(requested_ids):
            raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)

        by_id = {share.commissioner_id: share for share in self.shares}
        try:
            return tuple(by_id[commissioner_id] for commissioner_id in requested_ids)
        except KeyError as exc:
            raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE) from exc


def _require_identifier(value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise CryptographicError(CRYPTOGRAPHIC_ERROR_MESSAGE)


__all__ = ["CommissionerSet", "CommissionerShare"]
