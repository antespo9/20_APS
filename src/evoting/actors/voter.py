"""Voter-side pseudonymous state for Milestone 4."""

from __future__ import annotations

from dataclasses import dataclass
import os

from evoting.crypto.hashes import SHA256_DIGEST_SIZE, sha256_digest
from evoting.crypto.signatures import (
    generate_signature_private_key,
    signature_private_key_to_pem,
    signature_public_key_to_pem,
)
from evoting.errors import ModelValidationError
from evoting.models import AuthorizationRequest


VOTER_SECRET_SIZE = 32


@dataclass(frozen=True, slots=True)
class VoterAuthorizationMaterial:
    election_id: str
    t_i: bytes
    p_i: bytes
    pk_vote_i: bytes
    sk_vote_i: bytes

    def __post_init__(self) -> None:
        _validate_identifier(self.election_id, "election_id")
        _validate_non_empty_bytes(self.t_i, "t_i")
        _validate_pseudonym(self.p_i)
        _validate_non_empty_bytes(self.pk_vote_i, "pk_vote_i")
        _validate_non_empty_bytes(self.sk_vote_i, "sk_vote_i")
        if sha256_digest(self.t_i) != self.p_i:
            raise ModelValidationError("p_i must be SHA-256(t_i)")

    @property
    def authorization_request(self) -> AuthorizationRequest:
        return AuthorizationRequest(
            election_id=self.election_id,
            p_i=self.p_i,
            pk_vote_i=self.pk_vote_i,
        )

    def complete(self, tau_i: bytes) -> "PseudonymousVoterState":
        return PseudonymousVoterState(
            election_id=self.election_id,
            t_i=self.t_i,
            p_i=self.p_i,
            pk_vote_i=self.pk_vote_i,
            sk_vote_i=self.sk_vote_i,
            tau_i=tau_i,
        )


@dataclass(frozen=True, slots=True)
class PseudonymousVoterState:
    election_id: str
    t_i: bytes
    p_i: bytes
    pk_vote_i: bytes
    sk_vote_i: bytes
    tau_i: bytes
    current_vote_version: int = 0
    receipts: tuple[bytes, ...] = ()

    def __post_init__(self) -> None:
        _validate_identifier(self.election_id, "election_id")
        _validate_non_empty_bytes(self.t_i, "t_i")
        _validate_pseudonym(self.p_i)
        _validate_non_empty_bytes(self.pk_vote_i, "pk_vote_i")
        _validate_non_empty_bytes(self.sk_vote_i, "sk_vote_i")
        _validate_non_empty_bytes(self.tau_i, "tau_i")
        if sha256_digest(self.t_i) != self.p_i:
            raise ModelValidationError("p_i must be SHA-256(t_i)")
        if (
            not isinstance(self.current_vote_version, int)
            or isinstance(self.current_vote_version, bool)
            or self.current_vote_version < 0
        ):
            raise ModelValidationError("current_vote_version must be a non-negative integer")
        receipts = tuple(self.receipts)
        if not all(isinstance(receipt, bytes) and receipt for receipt in receipts):
            raise ModelValidationError("receipts must contain non-empty bytes")
        object.__setattr__(self, "receipts", receipts)

    @property
    def authorization_request(self) -> AuthorizationRequest:
        return AuthorizationRequest(
            election_id=self.election_id,
            p_i=self.p_i,
            pk_vote_i=self.pk_vote_i,
        )


def generate_authorization_material(election_id: str) -> VoterAuthorizationMaterial:
    """Generate local pseudonymous material for one election."""

    _validate_identifier(election_id, "election_id")
    private_key = generate_signature_private_key()
    t_i = os.urandom(VOTER_SECRET_SIZE)
    return VoterAuthorizationMaterial(
        election_id=election_id,
        t_i=t_i,
        p_i=sha256_digest(t_i),
        pk_vote_i=signature_public_key_to_pem(private_key.public_key()),
        sk_vote_i=signature_private_key_to_pem(private_key),
    )


def _validate_identifier(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ModelValidationError(f"{field_name} must be a non-empty protocol identifier")


def _validate_non_empty_bytes(value: bytes, field_name: str) -> None:
    if not isinstance(value, bytes) or len(value) == 0:
        raise ModelValidationError(f"{field_name} must be non-empty bytes")


def _validate_pseudonym(value: bytes) -> None:
    if not isinstance(value, bytes) or len(value) != SHA256_DIGEST_SIZE:
        raise ModelValidationError(f"p_i must be {SHA256_DIGEST_SIZE} bytes")


__all__ = [
    "PseudonymousVoterState",
    "VOTER_SECRET_SIZE",
    "VoterAuthorizationMaterial",
    "generate_authorization_material",
]
