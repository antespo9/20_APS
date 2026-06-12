import pytest

from evoting.crypto.password import (
    SCRYPT_DEFAULT_N,
    SCRYPT_DEFAULT_P,
    SCRYPT_DEFAULT_R,
    SCRYPT_SALT_SIZE,
    SCRYPT_VERIFIER_SIZE,
    PasswordVerifier,
    ScryptParameters,
    create_password_verifier,
    derive_key,
    verify_password,
)
from evoting.errors import CRYPTOGRAPHIC_ERROR_MESSAGE, CryptographicError


def test_scrypt_default_parameters_match_requirement() -> None:
    parameters = ScryptParameters()

    assert parameters.n == SCRYPT_DEFAULT_N == 2**15
    assert parameters.r == SCRYPT_DEFAULT_R == 8
    assert parameters.p == SCRYPT_DEFAULT_P == 1
    assert parameters.length == SCRYPT_VERIFIER_SIZE


def test_password_verifier_is_persistible_and_does_not_store_password() -> None:
    verifier = create_password_verifier(b"correct horse battery staple")

    assert len(verifier.salt) == SCRYPT_SALT_SIZE
    assert len(verifier.verifier) == verifier.parameters.length
    assert verifier.parameters == ScryptParameters()
    assert not hasattr(verifier, "password")


def test_correct_password_is_accepted_and_wrong_password_is_rejected() -> None:
    verifier = create_password_verifier(b"correct-password")

    assert verify_password(b"correct-password", verifier) is True
    assert verify_password(b"wrong-password", verifier) is False


def test_password_verifiers_use_distinct_random_salts() -> None:
    first = create_password_verifier(b"same-password")
    second = create_password_verifier(b"same-password")

    assert first.salt != second.salt
    assert first.verifier != second.verifier


def test_derive_key_is_deterministic_for_same_password_salt_and_parameters() -> None:
    verifier = create_password_verifier(b"password")

    first = derive_key(b"password", verifier.salt, verifier.parameters)
    second = derive_key(b"password", verifier.salt, verifier.parameters)

    assert first == second
    assert len(first) == 32


@pytest.mark.parametrize(
    "parameters",
    [
        ScryptParameters(n=2**14, r=8, p=1, length=32),
        ScryptParameters(n=2**15, r=4, p=2, length=64),
    ],
)
def test_scrypt_parameters_are_persisted(parameters: ScryptParameters) -> None:
    verifier = create_password_verifier(b"password", parameters)

    assert verifier.parameters == parameters
    assert verify_password(b"password", verifier) is True


@pytest.mark.parametrize(
    "parameters",
    [
        lambda: ScryptParameters(n=3),
        lambda: ScryptParameters(r=0),
        lambda: ScryptParameters(p=0),
        lambda: ScryptParameters(length=0),
    ],
)
def test_invalid_scrypt_parameters_are_rejected(parameters: object) -> None:
    with pytest.raises(CryptographicError) as exc_info:
        parameters()

    assert str(exc_info.value) == CRYPTOGRAPHIC_ERROR_MESSAGE


@pytest.mark.parametrize(
    "factory",
    [
        lambda: create_password_verifier("password"),
        lambda: derive_key(b"password", b"short"),
        lambda: verify_password("password", create_password_verifier(b"password")),
        lambda: PasswordVerifier(salt=b"short", verifier=b"x" * 32, parameters=ScryptParameters()),
        lambda: PasswordVerifier(salt=b"s" * 16, verifier=b"", parameters=ScryptParameters()),
    ],
)
def test_password_inputs_with_invalid_structure_are_rejected(factory: object) -> None:
    with pytest.raises(CryptographicError) as exc_info:
        factory()

    assert str(exc_info.value) == CRYPTOGRAPHIC_ERROR_MESSAGE
