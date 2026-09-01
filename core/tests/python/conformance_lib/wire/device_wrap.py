"""§5a / §3a per-device wrap files (`devices/<uuid>.wrap`, file_kind 0x0004).

The third unlock path (ADR 0009), additive to the password and recovery
paths: `device_kek = HKDF-SHA-256(device_secret)` unwraps the IBK. Includes
the B.2 enrol/open round-trip the FFI surface exposes.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from conformance_lib.constants import FORMAT_VERSION, MAGIC
from conformance_lib.primitives import aead_decrypt, aead_encrypt, hkdf_sha256

# §3a / §5a device-slot constants (crypto-design §5a, vault-format §3a).
FILE_KIND_DEVICE_WRAP = 0x0004
TAG_DEVICE_KEK = b"secretary-v1-device-kek"
TAG_ID_WRAP_DEV = b"secretary-v1-id-wrap-dev"
DEVICE_KEK_SALT = b"\x00" * 32  # §5a: 32 bytes of 0x00.
WRAP_DEV_CT_PLUS_TAG_LEN = 32 + 16  # IBK ciphertext (32) + Poly1305 tag (16).


def device_uuid_to_filename(uuid_hex: str) -> str:
    """32-hex-char device UUID -> lowercase-hyphenated 8-4-4-4-12 `<uuid>.wrap`
    filename (vault-format §1 / §3a)."""
    return (
        f"{uuid_hex[0:8]}-{uuid_hex[8:12]}-{uuid_hex[12:16]}"
        f"-{uuid_hex[16:20]}-{uuid_hex[20:32]}.wrap"
    )


def derive_device_kek(device_secret: bytes) -> bytes:
    """§5a `device_kek = HKDF-SHA-256(ikm=device_secret, salt=0x00*32,
    info="secretary-v1-device-kek", len=32)`. No Argon2id: the secret already
    carries 256 bits of CSPRNG entropy."""
    return hkdf_sha256(
        salt=DEVICE_KEK_SALT, ikm=device_secret, info=TAG_DEVICE_KEK, length=32
    )


def device_wrap_aad(vault_uuid: bytes) -> bytes:
    """§5a AEAD AAD: `"secretary-v1-id-wrap-dev" || vault_uuid`."""
    return TAG_ID_WRAP_DEV + vault_uuid


def encode_device_wrap(
    *, vault_uuid: bytes, device_uuid: bytes, nonce: bytes, ct_with_tag: bytes
) -> bytes:
    """Encode the §3a `devices/<uuid>.wrap` byte layout (the enrol direction).

    Big-endian throughout; `suite_id` omitted (identity-layer file, §3a). Inverse
    of `decode_device_wrap` below -- the two together prove the §3a container
    round-trips clean-room.
    """
    if len(vault_uuid) != 16:
        raise ValueError(f"device-wrap vault_uuid length {len(vault_uuid)} (expected 16)")
    if len(device_uuid) != 16:
        raise ValueError(f"device-wrap device_uuid length {len(device_uuid)} (expected 16)")
    if len(nonce) != 24:
        raise ValueError(f"device-wrap nonce length {len(nonce)} (expected 24)")
    if len(ct_with_tag) != WRAP_DEV_CT_PLUS_TAG_LEN:
        raise ValueError(
            f"device-wrap ct||tag length {len(ct_with_tag)} "
            f"(expected {WRAP_DEV_CT_PLUS_TAG_LEN})"
        )
    return (
        MAGIC.to_bytes(4, "big")
        + FORMAT_VERSION.to_bytes(2, "big")
        + FILE_KIND_DEVICE_WRAP.to_bytes(2, "big")
        + vault_uuid
        + device_uuid
        + nonce
        + (32).to_bytes(4, "big")  # wrap_dev_ct_len, MUST be 32 (§3a).
        + ct_with_tag
    )


def decode_device_wrap(blob: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """Decode the §3a `devices/<uuid>.wrap` byte layout.

    Returns `(vault_uuid, device_uuid, nonce, ct_with_tag)`. Asserts magic,
    format_version, file_kind 0x0004, and `wrap_dev_ct_len == 32` per §3a.
    """
    assert int.from_bytes(blob[0:4], "big") == MAGIC, "device wrap magic"
    assert int.from_bytes(blob[4:6], "big") == FORMAT_VERSION, "format_version"
    assert int.from_bytes(blob[6:8], "big") == FILE_KIND_DEVICE_WRAP, (
        "file_kind device-wrap"
    )
    vault_uuid = blob[8:24]
    device_uuid = blob[24:40]
    nonce = blob[40:64]
    assert int.from_bytes(blob[64:68], "big") == 32, "wrap_dev_ct_len"
    ct_with_tag = blob[68:68 + WRAP_DEV_CT_PLUS_TAG_LEN]
    return vault_uuid, device_uuid, nonce, ct_with_tag


def unwrap_device_slot(
    blob: bytes, device_secret: bytes, *, expected_device_uuid: bytes
) -> bytes:
    """Decode a §3a wrap file + §5a-unwrap the IBK it carries.

    Shared open-path core used by both the B.1 `verify_device_slot` cross-check
    and the B.2 `open_with_device_secret` replay. Asserts the §3a header
    `device_uuid` equals `expected_device_uuid` (the filename UUID). Returns the
    recovered IBK bytes.
    """
    vault_uuid, device_uuid_in_header, nonce, ct_with_tag = decode_device_wrap(blob)
    # §3a: the header device_uuid MUST equal the filename's UUID.
    assert device_uuid_in_header == expected_device_uuid, (
        f"device_uuid header/filename mismatch: "
        f"{device_uuid_in_header.hex()} != {expected_device_uuid.hex()}"
    )
    device_kek = derive_device_kek(device_secret)
    return aead_decrypt(device_kek, nonce, device_wrap_aad(vault_uuid), ct_with_tag)


def verify_device_slot(base: Path, inputs: dict[str, Any], ibk_expected: bytes) -> None:
    """Clean-room vault-format §3a / crypto-design §5a: derive device_kek via
    HKDF-SHA-256 and AEAD-unwrap the IBK from devices/<uuid>.wrap, asserting it
    matches the IBK recovered via the password path. Proves §3a is implementable
    from docs/ alone."""
    secret = bytes.fromhex(inputs["device_slot_secret_hex"])
    uuid_hex = inputs["device_slot_uuid_hex"]
    with open(base / "devices" / device_uuid_to_filename(uuid_hex), "rb") as fh:
        blob = fh.read()
    ibk = unwrap_device_slot(
        blob, secret, expected_device_uuid=bytes.fromhex(uuid_hex)
    )
    assert ibk == ibk_expected, "device-slot IBK must match the password/recovery IBK"


def verify_device_slot_b2_ops(
    base: Path, inputs: dict[str, Any], ibk_from_pw: bytes
) -> None:
    """Clean-room replay of the two B.2 device-slot operations (§3a / §5a).

    (a) open -- replays `open_with_device_secret`'s observable contract using the
        shared §3a decode + §5a unwrap helpers: derive device_kek from the pinned
        `device_slot_secret_hex`, decode the golden `devices/<uuid>.wrap`, unwrap
        the IBK, and assert it EQUALS the IBK independently recovered from the
        PASSWORD path (`ibk_from_pw`). Also asserts the §3a header `device_uuid`
        equals the filename UUID (enforced inside `unwrap_device_slot`).

    (b) enrol round-trip -- proves the ENROL direction is spec-implementable. Take
        the password-path IBK, pick a fresh deterministic test device secret +
        device UUID, derive device_kek, AEAD-ENCRYPT the IBK under the §5a AAD,
        ENCODE the §3a wrap-file byte layout, then DECODE it back and UNWRAP,
        asserting the recovered IBK equals the original. This closes the loop B.1
        only walked one-way (decode/unwrap). Purely in-memory -- no file is
        written into the fixture.
    """
    # (a) open: replay open_with_device_secret against the golden wrap file and
    #     cross-check the recovered IBK against the password-path IBK.
    secret = bytes.fromhex(inputs["device_slot_secret_hex"])
    uuid_hex = inputs["device_slot_uuid_hex"]
    device_uuid = bytes.fromhex(uuid_hex)
    with open(base / "devices" / device_uuid_to_filename(uuid_hex), "rb") as fh:
        golden_blob = fh.read()
    ibk_from_device = unwrap_device_slot(
        golden_blob, secret, expected_device_uuid=device_uuid
    )
    assert ibk_from_device == ibk_from_pw, (
        "B.2 open: device-path IBK must equal the password-path IBK"
    )

    # (b) enrol round-trip: encode a fresh §3a wrap in memory, then decode+unwrap.
    #     Deterministic literals are fine -- this is a clean-room round-trip proof,
    #     not a KAT. Choose values DISTINCT from the golden fixture's so a stray
    #     mix-up could not pass by coincidence.
    enrol_secret = bytes(range(32))  # 00 01 02 ... 1f
    enrol_device_uuid = bytes(range(0x20, 0x30))  # 16 distinct bytes 20..2f
    enrol_vault_uuid = bytes.fromhex(inputs["vault_uuid"].replace("-", ""))
    enrol_nonce = bytes(range(0x40, 0x58))  # 24 distinct nonce bytes 40..57

    enrol_kek = derive_device_kek(enrol_secret)
    enrol_ct_with_tag = aead_encrypt(
        enrol_kek, enrol_nonce, device_wrap_aad(enrol_vault_uuid), ibk_from_pw
    )
    assert len(enrol_ct_with_tag) == WRAP_DEV_CT_PLUS_TAG_LEN, (
        f"enrol ct||tag length {len(enrol_ct_with_tag)} "
        f"(expected {WRAP_DEV_CT_PLUS_TAG_LEN})"
    )

    enrol_blob = encode_device_wrap(
        vault_uuid=enrol_vault_uuid,
        device_uuid=enrol_device_uuid,
        nonce=enrol_nonce,
        ct_with_tag=enrol_ct_with_tag,
    )
    recovered_ibk = unwrap_device_slot(
        enrol_blob, enrol_secret, expected_device_uuid=enrol_device_uuid
    )
    assert recovered_ibk == ibk_from_pw, (
        "B.2 enrol round-trip: §3a encode -> decode -> §5a unwrap must recover the IBK"
    )
