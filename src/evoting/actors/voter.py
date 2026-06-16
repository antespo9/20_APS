"""Voter-side pseudonymous state for Milestone 4."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
import os

from evoting.crypto.encryption import encrypt_vote, load_encryption_public_key
from evoting.crypto.hashes import SHA256_DIGEST_SIZE, sha256_digest
from evoting.crypto.signatures import (
    generate_signature_private_key,
    load_signature_private_key,
    sign_message,
    signature_private_key_to_pem,
    signature_public_key_to_pem,
)
from evoting.errors import ModelValidationError
from evoting.models import Ack, AuthorizationRequest, VoteMessage, VotePackage
from evoting.serialization import canonical_bytes


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


def prepare_vote_package(
    state: PseudonymousVoterState,
    list_code: str,
    *,
    allowed_list_codes: Iterable[str],
    ta_public_key_pem: bytes,
) -> VotePackage:
    """Encrypt and sign a vote package without mutating local voter state."""

    if not isinstance(state, PseudonymousVoterState):
        raise ModelValidationError("state must be PseudonymousVoterState")
    _validate_list_choice(list_code, allowed_list_codes)
    public_key = load_encryption_public_key(ta_public_key_pem)
    ciphertext = encrypt_vote(public_key, list_code.encode("utf-8"))
    version = state.current_vote_version + 1
    message = VoteMessage(
        election_id=state.election_id,
        p_i=state.p_i,
        c=ciphertext,
        pk_vote_i=state.pk_vote_i,
        v_i=version,
    )
    private_key = load_signature_private_key(state.sk_vote_i)
    signature = sign_message(private_key, canonical_bytes(message))
    return VotePackage(
        c=ciphertext,
        p_i=state.p_i,
        pk_vote_i=state.pk_vote_i,
        tau_i=state.tau_i,
        v_i=version,
        sigma_i=signature,
    )


def apply_accepted_receipt(
    state: PseudonymousVoterState,
    package: VotePackage,
    receipt: Ack,
    *,
    bb_public_key_pem: bytes,
) -> PseudonymousVoterState:
    """Return updated state only after a coherent signed BB receipt verifies."""

    if not isinstance(state, PseudonymousVoterState):
        raise ModelValidationError("state must be PseudonymousVoterState")
    if not isinstance(package, VotePackage):
        raise ModelValidationError("package must be VotePackage")
    if not isinstance(receipt, Ack):
        raise ModelValidationError("receipt must be Ack")
    if (
        package.p_i != state.p_i
        or package.pk_vote_i != state.pk_vote_i
        or package.tau_i != state.tau_i
        or package.v_i != state.current_vote_version + 1
    ):
        raise ModelValidationError("receipt does not match voter state")

    from evoting.actors.bulletin_board import ballot_rid, verify_receipt

    expected_rid = ballot_rid(state.election_id, package)
    if not verify_receipt(
        bb_public_key_pem,
        receipt,
        expected_election_id=state.election_id,
        expected_rid=expected_rid,
    ):
        raise ModelValidationError("receipt does not verify")

    return PseudonymousVoterState(
        election_id=state.election_id,
        t_i=state.t_i,
        p_i=state.p_i,
        pk_vote_i=state.pk_vote_i,
        sk_vote_i=state.sk_vote_i,
        tau_i=state.tau_i,
        current_vote_version=package.v_i,
        receipts=state.receipts + (canonical_bytes(receipt),),
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


def _validate_list_choice(list_code: str, allowed_list_codes: Iterable[str]) -> None:
    if not isinstance(list_code, str) or not list_code:
        raise ModelValidationError("list_code must be a non-empty list code")
    try:
        allowed = tuple(allowed_list_codes)
    except TypeError as exc:
        raise ModelValidationError("allowed_list_codes must be iterable") from exc
    if not allowed or not all(isinstance(code, str) and code for code in allowed):
        raise ModelValidationError("allowed_list_codes must contain non-empty list codes")
    if list_code not in allowed:
        raise ModelValidationError("list_code is not allowed")


__all__ = [
    "PseudonymousVoterState",
    "VOTER_SECRET_SIZE",
    "VoterAuthorizationMaterial",
    "apply_accepted_receipt",
    "generate_authorization_material",
    "prepare_vote_package",
]
