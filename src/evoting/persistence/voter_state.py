"""Encrypted persistence for the voter pseudonymous state."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import os
from pathlib import Path
from typing import Any

from evoting.actors.voter import PseudonymousVoterState
from evoting.crypto.aead import AeadCiphertext, decrypt_aead, encrypt_aead
from evoting.crypto.password import SCRYPT_SALT_SIZE, ScryptParameters, derive_key
from evoting.errors import EvotingError
from evoting.persistence.stores import JsonFileStore, StoreError
from evoting.serialization import canonical_bytes


VOTER_STATE_AAD_CONTEXT = "evoting.voter_state.v1"
VOTER_STATE_CONTAINER_SCHEMA = "evoting.voter_state.container.v1"
VOTER_STATE_PAYLOAD_SCHEMA = "evoting.voter_state.payload.v1"
VOTER_STATE_ERROR_MESSAGE = "voter state unavailable"


class VoterStateError(EvotingError):
    """Raised when encrypted voter state cannot be recovered."""


@dataclass(frozen=True, slots=True)
class VoterStateFileStore:
    path: Path

    def __init__(self, path: str | Path) -> None:
        object.__setattr__(self, "path", Path(path))

    def save(
        self,
        state: PseudonymousVoterState,
        local_password: bytes,
        *,
        scrypt_parameters: ScryptParameters = ScryptParameters(),
    ) -> None:
        save_voter_state(self.path, state, local_password, scrypt_parameters=scrypt_parameters)

    def load(
        self,
        local_password: bytes,
        *,
        election_id: str | None = None,
    ) -> PseudonymousVoterState:
        return load_voter_state(self.path, local_password, election_id=election_id)


def voter_state_aad(election_id: str, aad_context: str = VOTER_STATE_AAD_CONTEXT) -> bytes:
    if not isinstance(election_id, str) or not election_id.strip():
        raise VoterStateError(VOTER_STATE_ERROR_MESSAGE)
    if not isinstance(aad_context, str) or not aad_context.strip():
        raise VoterStateError(VOTER_STATE_ERROR_MESSAGE)
    return canonical_bytes({"context": aad_context, "election_id": election_id})


def save_voter_state(
    path: str | Path,
    state: PseudonymousVoterState,
    local_password: bytes,
    *,
    scrypt_parameters: ScryptParameters = ScryptParameters(),
) -> None:
    if not isinstance(state, PseudonymousVoterState):
        raise VoterStateError(VOTER_STATE_ERROR_MESSAGE)
    try:
        salt = os.urandom(SCRYPT_SALT_SIZE)
        key = derive_key(local_password, salt, scrypt_parameters, length=32)
        encrypted = encrypt_aead(key, _state_payload_bytes(state), voter_state_aad(state.election_id))
        container = {
            "aad_context": VOTER_STATE_AAD_CONTEXT,
            "aead": {
                "algorithm": "AES-256-GCM",
                "ciphertext": _b64encode(encrypted.ciphertext),
                "nonce": _b64encode(encrypted.nonce),
                "tag": _b64encode(encrypted.tag),
            },
            "election_id": state.election_id,
            "kdf": {
                "algorithm": "scrypt",
                "length": 32,
                "n": scrypt_parameters.n,
                "p": scrypt_parameters.p,
                "r": scrypt_parameters.r,
                "salt": _b64encode(salt),
            },
            "schema": VOTER_STATE_CONTAINER_SCHEMA,
        }
        JsonFileStore(path).write(container)
    except Exception as exc:
        if isinstance(exc, VoterStateError):
            raise
        raise VoterStateError(VOTER_STATE_ERROR_MESSAGE) from exc


def load_voter_state(
    path: str | Path,
    local_password: bytes,
    *,
    election_id: str | None = None,
) -> PseudonymousVoterState:
    try:
        container = JsonFileStore(path).read()
        if container is None:
            raise VoterStateError(VOTER_STATE_ERROR_MESSAGE)
        if container.get("schema") != VOTER_STATE_CONTAINER_SCHEMA:
            raise VoterStateError(VOTER_STATE_ERROR_MESSAGE)
        container_election_id = _require_str(container["election_id"])
        aad_context = _require_str(container["aad_context"])
        aad_election_id = election_id if election_id is not None else container_election_id
        kdf = _require_mapping(container["kdf"])
        aead = _require_mapping(container["aead"])
        parameters = ScryptParameters(
            n=_require_int(kdf["n"]),
            r=_require_int(kdf["r"]),
            p=_require_int(kdf["p"]),
            length=_require_int(kdf["length"]),
        )
        salt = _b64decode(_require_str(kdf["salt"]))
        key = derive_key(local_password, salt, parameters, length=32)
        encrypted = AeadCiphertext(
            nonce=_b64decode(_require_str(aead["nonce"])),
            ciphertext=_b64decode(_require_str(aead["ciphertext"])),
            tag=_b64decode(_require_str(aead["tag"])),
        )
        plaintext = decrypt_aead(key, encrypted, voter_state_aad(aad_election_id, aad_context))
        state = _state_from_payload_bytes(plaintext)
        if state.election_id != container_election_id or state.election_id != aad_election_id:
            raise VoterStateError(VOTER_STATE_ERROR_MESSAGE)
        return state
    except Exception as exc:
        if isinstance(exc, VoterStateError):
            raise
        if isinstance(exc, StoreError):
            raise VoterStateError(VOTER_STATE_ERROR_MESSAGE) from exc
        raise VoterStateError(VOTER_STATE_ERROR_MESSAGE) from exc


def _state_payload_bytes(state: PseudonymousVoterState) -> bytes:
    return canonical_bytes(
        {
            "current_vote_version": state.current_vote_version,
            "election_id": state.election_id,
            "p_i": state.p_i,
            "pk_vote_i": state.pk_vote_i,
            "receipts": list(state.receipts),
            "schema": VOTER_STATE_PAYLOAD_SCHEMA,
            "sk_vote_i": state.sk_vote_i,
            "t_i": state.t_i,
            "tau_i": state.tau_i,
        }
    )


def _state_from_payload_bytes(value: bytes) -> PseudonymousVoterState:
    import json

    payload = json.loads(value.decode("utf-8"))
    if not isinstance(payload, dict) or payload.get("schema") != VOTER_STATE_PAYLOAD_SCHEMA:
        raise VoterStateError(VOTER_STATE_ERROR_MESSAGE)
    receipts = _require_sequence(payload["receipts"])
    return PseudonymousVoterState(
        election_id=_require_str(payload["election_id"]),
        t_i=_canonical_b64decode(payload["t_i"]),
        p_i=_canonical_b64decode(payload["p_i"]),
        pk_vote_i=_canonical_b64decode(payload["pk_vote_i"]),
        sk_vote_i=_canonical_b64decode(payload["sk_vote_i"]),
        tau_i=_canonical_b64decode(payload["tau_i"]),
        current_vote_version=_require_int(payload["current_vote_version"]),
        receipts=tuple(_canonical_b64decode(item) for item in receipts),
    )


def _canonical_b64decode(value: object) -> bytes:
    mapping = _require_mapping(value)
    marker = mapping.get("__bytes__")
    if not isinstance(marker, str):
        raise VoterStateError(VOTER_STATE_ERROR_MESSAGE)
    return _b64decode(marker)


def _b64encode(value: bytes) -> str:
    if not isinstance(value, bytes):
        raise VoterStateError(VOTER_STATE_ERROR_MESSAGE)
    return base64.b64encode(value).decode("ascii")


def _b64decode(value: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise VoterStateError(VOTER_STATE_ERROR_MESSAGE) from exc


def _require_mapping(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise VoterStateError(VOTER_STATE_ERROR_MESSAGE)
    return value


def _require_sequence(value: object) -> list[Any]:
    if not isinstance(value, list):
        raise VoterStateError(VOTER_STATE_ERROR_MESSAGE)
    return value


def _require_str(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise VoterStateError(VOTER_STATE_ERROR_MESSAGE)
    return value


def _require_int(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise VoterStateError(VOTER_STATE_ERROR_MESSAGE)
    return value


__all__ = [
    "VOTER_STATE_AAD_CONTEXT",
    "VOTER_STATE_CONTAINER_SCHEMA",
    "VOTER_STATE_ERROR_MESSAGE",
    "VoterStateError",
    "VoterStateFileStore",
    "load_voter_state",
    "save_voter_state",
    "voter_state_aad",
]
