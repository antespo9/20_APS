from dataclasses import replace

import pytest

from evoting.actors.commissioners import CommissionerShare
from evoting.actors.tallying_authority import (
    BLOB_TA_CONTEXT,
    TaBlob,
    TallyingAuthority,
    create_protected_blob,
    open_protected_blob,
)
from evoting.crypto.encryption import encryption_private_key_to_pem, generate_encryption_private_key
from evoting.crypto.shamir import FIELD_PRIME, ShamirShare
from evoting.errors import CRYPTOGRAPHIC_ERROR_MESSAGE, CryptographicError


ELECTION_ID = "election-2026"


def _private_key_pem() -> bytes:
    return encryption_private_key_to_pem(generate_encryption_private_key())


def _setup() -> tuple[bytes, TaBlob, tuple[CommissionerShare, ...]]:
    private_key_pem = _private_key_pem()
    blob, commissioners = create_protected_blob(
        election_id=ELECTION_ID,
        private_key_pem=private_key_pem,
        threshold_t=3,
        threshold_n=5,
        commissioner_ids=("c1", "c2", "c3", "c4", "c5"),
    )
    return private_key_pem, blob, commissioners.shares


def _assert_generic_error(operation: object) -> None:
    with pytest.raises(CryptographicError) as exc_info:
        operation()

    assert str(exc_info.value) == CRYPTOGRAPHIC_ERROR_MESSAGE


def test_blob_opens_with_at_least_threshold_valid_commissioner_shares() -> None:
    private_key_pem, blob, shares = _setup()

    assert open_protected_blob(blob, shares[:3]) == private_key_pem
    assert open_protected_blob(blob, shares[:4]) == private_key_pem


def test_tallying_authority_class_creates_and_opens_blob() -> None:
    private_key_pem = _private_key_pem()
    ta = TallyingAuthority(
        election_id=ELECTION_ID,
        threshold_t=3,
        threshold_n=5,
        commissioner_ids=("c1", "c2", "c3", "c4", "c5"),
    )
    blob, commissioners = ta.create_blob(private_key_pem)

    assert ta.open_blob(blob, commissioners.collect(("c1", "c3", "c5"))) == private_key_pem


def test_tallying_authority_rejects_blob_for_another_election() -> None:
    _, blob, shares = _setup()
    ta = TallyingAuthority(election_id="election-2027", threshold_t=3, threshold_n=5)

    _assert_generic_error(lambda: ta.open_blob(blob, shares[:3]))


def test_blob_does_not_open_with_less_than_threshold_shares() -> None:
    _, blob, shares = _setup()

    _assert_generic_error(lambda: open_protected_blob(blob, shares[:2]))


def test_altered_share_does_not_open_blob() -> None:
    _, blob, shares = _setup()
    altered_inner = ShamirShare(x=shares[1].share.x, y=(shares[1].share.y + 1) % FIELD_PRIME)
    altered_share = CommissionerShare(
        commissioner_id=shares[1].commissioner_id,
        election_id=shares[1].election_id,
        share=altered_inner,
    )

    _assert_generic_error(lambda: open_protected_blob(blob, (shares[0], altered_share, shares[2])))


def test_altered_mac_does_not_open_blob() -> None:
    _, blob, shares = _setup()
    altered = replace(blob, mac=blob.mac[:-1] + bytes([blob.mac[-1] ^ 1]))

    _assert_generic_error(lambda: open_protected_blob(altered, shares[:3]))


def test_altered_ciphertext_does_not_open_blob() -> None:
    _, blob, shares = _setup()
    altered = replace(blob, ciphertext=blob.ciphertext[:-1] + bytes([blob.ciphertext[-1] ^ 1]))

    _assert_generic_error(lambda: open_protected_blob(altered, shares[:3]))


def test_altered_iv_does_not_open_blob() -> None:
    _, blob, shares = _setup()
    altered = replace(blob, iv=blob.iv[:-1] + bytes([blob.iv[-1] ^ 1]))

    _assert_generic_error(lambda: open_protected_blob(altered, shares[:3]))


def test_altered_context_does_not_open_blob() -> None:
    _, blob, shares = _setup()
    altered = replace(blob, context=BLOB_TA_CONTEXT + ".altered")

    _assert_generic_error(lambda: open_protected_blob(altered, shares[:3]))


def test_altered_election_id_does_not_open_blob() -> None:
    _, blob, shares = _setup()
    altered = replace(blob, election_id="election-2027")

    _assert_generic_error(lambda: open_protected_blob(altered, shares[:3]))


def test_altered_threshold_metadata_does_not_open_blob() -> None:
    _, blob, shares = _setup()
    altered = replace(blob, threshold_n=6)

    _assert_generic_error(lambda: open_protected_blob(altered, shares[:3]))


def test_raw_shamir_share_is_rejected_when_opening_blob() -> None:
    _, blob, shares = _setup()

    _assert_generic_error(lambda: open_protected_blob(blob, (shares[0].share, shares[1], shares[2])))


def test_commissioner_share_from_another_election_is_rejected() -> None:
    _, blob, shares = _setup()
    other_election_share = CommissionerShare("other", "other-election", shares[1].share)

    _assert_generic_error(lambda: open_protected_blob(blob, (shares[0], other_election_share, shares[2])))


def test_duplicate_commissioner_ids_are_rejected_when_opening_blob() -> None:
    _, blob, shares = _setup()
    duplicate_commissioner = CommissionerShare(shares[0].commissioner_id, ELECTION_ID, shares[1].share)

    _assert_generic_error(lambda: open_protected_blob(blob, (shares[0], duplicate_commissioner, shares[2])))


def test_duplicate_share_x_values_are_rejected_when_opening_blob() -> None:
    _, blob, shares = _setup()
    duplicate_x_share = CommissionerShare("other", ELECTION_ID, shares[0].share)

    _assert_generic_error(lambda: open_protected_blob(blob, (shares[0], duplicate_x_share, shares[2])))


def test_blob_uses_cbc_hmac_fields_and_does_not_contain_wrapping_key_field() -> None:
    _, blob, _ = _setup()

    assert not hasattr(blob, "kwrap")
    assert not hasattr(blob, "wrapping_key")
    assert not hasattr(blob, "kenc")
    assert not hasattr(blob, "kmac")
    assert not hasattr(blob, "nonce")
    assert not hasattr(blob, "tag")
    assert set(blob.__dataclass_fields__) == {
        "election_id",
        "context",
        "iv",
        "ciphertext",
        "mac",
        "threshold_t",
        "threshold_n",
    }


def test_commissioner_shares_do_not_contain_ta_private_key() -> None:
    private_key_pem, _, shares = _setup()

    assert private_key_pem not in repr(shares).encode("utf-8")


def test_duplicate_or_incompatible_commissioner_shares_are_rejected() -> None:
    _, blob, shares = _setup()
    duplicate = (shares[0], shares[0], shares[2])
    incompatible = (
        shares[0],
        CommissionerShare("other", "other-election", shares[1].share),
        shares[2],
    )

    _assert_generic_error(lambda: open_protected_blob(blob, duplicate))
    _assert_generic_error(lambda: open_protected_blob(blob, incompatible))
