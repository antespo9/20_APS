"""Registration Authority for pseudonymous authorization issuance."""

from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import rsa

from evoting.crypto.password import (
    PasswordVerifier,
    ScryptParameters,
    create_password_verifier,
    verify_password,
)
from evoting.crypto.signatures import (
    load_signature_private_key,
    load_signature_public_key,
    sign_message,
    signature_public_key_to_pem,
    verify_signature,
)
from evoting.errors import EvotingError
from evoting.models import AuthorizationRequest
from evoting.persistence.stores import JsonFileStore, default_ra_store_path
from evoting.serialization import canonical_bytes


RA_REGISTRY_SCHEMA = "evoting.ra.registry.v1"
AUTHORIZATION_ERROR_MESSAGE = "authorization failed"


class AuthorizationError(EvotingError):
    """Raised when the RA refuses an authentication or authorization operation."""


@dataclass(frozen=True, slots=True)
class IssuedAuthorizationRecord:
    election_id: str
    p_i: bytes
    pk_vote_i: bytes
    tau_i: bytes

    def __post_init__(self) -> None:
        _require_identifier(self.election_id)
        _require_bytes(self.p_i)
        _require_bytes(self.pk_vote_i)
        _require_bytes(self.tau_i)


@dataclass(frozen=True, slots=True)
class EligibleVoterRecord:
    institutional_id: str
    password_verifier: PasswordVerifier
    enabled: bool
    issued_authorizations: Mapping[str, IssuedAuthorizationRecord]

    def __post_init__(self) -> None:
        _require_identifier(self.institutional_id)
        if not isinstance(self.password_verifier, PasswordVerifier):
            raise AuthorizationError(AUTHORIZATION_ERROR_MESSAGE)
        if not isinstance(self.enabled, bool):
            raise AuthorizationError(AUTHORIZATION_ERROR_MESSAGE)
        issued = dict(self.issued_authorizations)
        for election_id, record in issued.items():
            _require_identifier(election_id)
            if not isinstance(record, IssuedAuthorizationRecord) or record.election_id != election_id:
                raise AuthorizationError(AUTHORIZATION_ERROR_MESSAGE)
        object.__setattr__(self, "issued_authorizations", issued)


class RegistrationAuthority:
    """Local simulated RA with a private registry of eligible voters."""

    def __init__(
        self,
        *,
        election_id: str,
        private_key: rsa.RSAPrivateKey | bytes,
        store_path: str | Path | None = None,
        scrypt_parameters: ScryptParameters = ScryptParameters(),
    ) -> None:
        _require_identifier(election_id)
        if isinstance(private_key, bytes):
            loaded_private_key = load_signature_private_key(private_key)
        else:
            loaded_private_key = private_key
        if not isinstance(loaded_private_key, rsa.RSAPrivateKey):
            raise AuthorizationError(AUTHORIZATION_ERROR_MESSAGE)
        if not isinstance(scrypt_parameters, ScryptParameters):
            raise AuthorizationError(AUTHORIZATION_ERROR_MESSAGE)
        self.election_id = election_id
        self._private_key = loaded_private_key
        self._store = JsonFileStore(default_ra_store_path() if store_path is None else store_path)
        self._scrypt_parameters = scrypt_parameters

    @property
    def public_key_pem(self) -> bytes:
        return signature_public_key_to_pem(self._private_key.public_key())

    def register_voter(self, institutional_id: str, password: bytes, *, enabled: bool = True) -> None:
        _require_identifier(institutional_id)
        if not isinstance(enabled, bool):
            raise AuthorizationError(AUTHORIZATION_ERROR_MESSAGE)
        records = self._load_records()
        if institutional_id in records:
            raise AuthorizationError(AUTHORIZATION_ERROR_MESSAGE)
        records[institutional_id] = EligibleVoterRecord(
            institutional_id=institutional_id,
            password_verifier=create_password_verifier(password, self._scrypt_parameters),
            enabled=enabled,
            issued_authorizations={},
        )
        self._save_records(records)

    def authenticate_voter(self, institutional_id: str, password: bytes) -> bool:
        try:
            record = self._load_records()[institutional_id]
        except Exception:
            return False
        if not record.enabled:
            return False
        return verify_password(password, record.password_verifier)

    def issue_authorization(
        self,
        institutional_id: str,
        password: bytes,
        request: AuthorizationRequest,
    ) -> bytes:
        if not isinstance(request, AuthorizationRequest) or request.election_id != self.election_id:
            raise AuthorizationError(AUTHORIZATION_ERROR_MESSAGE)
        records = self._load_records()
        record = records.get(institutional_id)
        if record is None or not record.enabled:
            raise AuthorizationError(AUTHORIZATION_ERROR_MESSAGE)
        if not verify_password(password, record.password_verifier):
            raise AuthorizationError(AUTHORIZATION_ERROR_MESSAGE)
        if self.election_id in record.issued_authorizations:
            raise AuthorizationError(AUTHORIZATION_ERROR_MESSAGE)

        tau_i = sign_message(self._private_key, authorization_message(request))
        issued = dict(record.issued_authorizations)
        issued[self.election_id] = IssuedAuthorizationRecord(
            election_id=self.election_id,
            p_i=request.p_i,
            pk_vote_i=request.pk_vote_i,
            tau_i=tau_i,
        )
        records[institutional_id] = EligibleVoterRecord(
            institutional_id=record.institutional_id,
            password_verifier=record.password_verifier,
            enabled=record.enabled,
            issued_authorizations=issued,
        )
        self._save_records(records)
        return tau_i

    def issued_authorization(self, institutional_id: str, election_id: str | None = None) -> IssuedAuthorizationRecord:
        selected_election_id = self.election_id if election_id is None else election_id
        try:
            return self._load_records()[institutional_id].issued_authorizations[selected_election_id]
        except Exception as exc:
            raise AuthorizationError(AUTHORIZATION_ERROR_MESSAGE) from exc

    def verify_authorization(self, request: AuthorizationRequest, tau_i: bytes) -> bool:
        return verify_authorization(self.public_key_pem, request, tau_i)

    def _load_records(self) -> dict[str, EligibleVoterRecord]:
        raw = self._store.read()
        if raw is None:
            return {}
        if raw.get("schema") != RA_REGISTRY_SCHEMA:
            raise AuthorizationError(AUTHORIZATION_ERROR_MESSAGE)
        voters = raw.get("voters")
        if not isinstance(voters, dict):
            raise AuthorizationError(AUTHORIZATION_ERROR_MESSAGE)
        return {institutional_id: _record_from_json(value) for institutional_id, value in voters.items()}

    def _save_records(self, records: Mapping[str, EligibleVoterRecord]) -> None:
        self._store.write(
            {
                "schema": RA_REGISTRY_SCHEMA,
                "voters": {
                    institutional_id: _record_to_json(record)
                    for institutional_id, record in sorted(records.items())
                },
            }
        )


def authorization_message(request: AuthorizationRequest) -> bytes:
    if not isinstance(request, AuthorizationRequest):
        raise AuthorizationError(AUTHORIZATION_ERROR_MESSAGE)
    return canonical_bytes(request)


def verify_authorization(
    public_key_pem: bytes,
    request: AuthorizationRequest,
    tau_i: bytes,
) -> bool:
    if not isinstance(request, AuthorizationRequest):
        raise AuthorizationError(AUTHORIZATION_ERROR_MESSAGE)
    public_key = load_signature_public_key(public_key_pem)
    return verify_signature(public_key, authorization_message(request), tau_i)


def _record_to_json(record: EligibleVoterRecord) -> dict[str, Any]:
    return {
        "enabled": record.enabled,
        "institutional_id": record.institutional_id,
        "issued_authorizations": {
            election_id: {
                "election_id": issued.election_id,
                "p_i": _b64encode(issued.p_i),
                "pk_vote_i": _b64encode(issued.pk_vote_i),
                "tau_i": _b64encode(issued.tau_i),
            }
            for election_id, issued in sorted(record.issued_authorizations.items())
        },
        "password_verifier": {
            "parameters": {
                "length": record.password_verifier.parameters.length,
                "n": record.password_verifier.parameters.n,
                "p": record.password_verifier.parameters.p,
                "r": record.password_verifier.parameters.r,
            },
            "salt": _b64encode(record.password_verifier.salt),
            "verifier": _b64encode(record.password_verifier.verifier),
        },
    }


def _record_from_json(value: object) -> EligibleVoterRecord:
    mapping = _require_mapping(value)
    verifier = _password_verifier_from_json(mapping["password_verifier"])
    issued = {
        election_id: IssuedAuthorizationRecord(
            election_id=_require_str(raw_issued["election_id"]),
            p_i=_b64decode(_require_str(raw_issued["p_i"])),
            pk_vote_i=_b64decode(_require_str(raw_issued["pk_vote_i"])),
            tau_i=_b64decode(_require_str(raw_issued["tau_i"])),
        )
        for election_id, raw_issued in _require_mapping(mapping["issued_authorizations"]).items()
    }
    return EligibleVoterRecord(
        institutional_id=_require_str(mapping["institutional_id"]),
        password_verifier=verifier,
        enabled=_require_bool(mapping["enabled"]),
        issued_authorizations=issued,
    )


def _password_verifier_from_json(value: object) -> PasswordVerifier:
    mapping = _require_mapping(value)
    parameters = _require_mapping(mapping["parameters"])
    scrypt_parameters = ScryptParameters(
        n=_require_int(parameters["n"]),
        r=_require_int(parameters["r"]),
        p=_require_int(parameters["p"]),
        length=_require_int(parameters["length"]),
    )
    return PasswordVerifier(
        salt=_b64decode(_require_str(mapping["salt"])),
        verifier=_b64decode(_require_str(mapping["verifier"])),
        parameters=scrypt_parameters,
    )


def _b64encode(value: bytes) -> str:
    _require_bytes(value)
    return base64.b64encode(value).decode("ascii")


def _b64decode(value: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise AuthorizationError(AUTHORIZATION_ERROR_MESSAGE) from exc


def _require_mapping(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AuthorizationError(AUTHORIZATION_ERROR_MESSAGE)
    return value


def _require_str(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise AuthorizationError(AUTHORIZATION_ERROR_MESSAGE)
    return value


def _require_int(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise AuthorizationError(AUTHORIZATION_ERROR_MESSAGE)
    return value


def _require_bool(value: object) -> bool:
    if not isinstance(value, bool):
        raise AuthorizationError(AUTHORIZATION_ERROR_MESSAGE)
    return value


def _require_identifier(value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise AuthorizationError(AUTHORIZATION_ERROR_MESSAGE)


def _require_bytes(value: bytes) -> None:
    if not isinstance(value, bytes) or len(value) == 0:
        raise AuthorizationError(AUTHORIZATION_ERROR_MESSAGE)


__all__ = [
    "AUTHORIZATION_ERROR_MESSAGE",
    "RA_REGISTRY_SCHEMA",
    "AuthorizationError",
    "EligibleVoterRecord",
    "IssuedAuthorizationRecord",
    "RegistrationAuthority",
    "authorization_message",
    "verify_authorization",
]
