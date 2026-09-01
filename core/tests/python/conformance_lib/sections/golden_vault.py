"""Section 2 -- the full `golden_vault_001/` crypto verify, plus three
in-script tamper checks.

The tamper checks are what stop the section from being vacuous: a verify
path that accepted everything would pass every positive row.
"""

from __future__ import annotations

from typing import Any

from conformance_lib.constants import TAG_ID_WRAP_PW
from conformance_lib.cursor import ParseError
from conformance_lib.derivations import compose_aad
from conformance_lib.fixtures import _require_file, golden_vault_inputs_path, golden_vault_path, load_json_fixture
from conformance_lib.primitives import aead_decrypt, argon2id_raw
from conformance_lib.tamper import _bytes_flip
from conformance_lib.wire.card import parse_and_verify_card
from conformance_lib.wire.device_wrap import verify_device_slot, verify_device_slot_b2_ops
from conformance_lib.wire.envelopes import parse_identity_bundle_envelope
from conformance_lib.wire.golden_vault_verify import verify_block_and_manifest
from conformance_lib.wire.vault_toml import parse_vault_toml

# Note: conformance.py verifies golden_vault_001/ only. core/tests/data/
# also contains a golden_vault_002/ fixture used by the FFI integration
# tests (secretary-ffi-bridge, secretary-ffi-py, secretary-ffi-uniffi)
# to exercise the VaultMismatch error path with a real second vault.
# That fixture is intentionally out of scope here — one canonical fixture
# is sufficient for the spec-clean-room contract this script enforces.
# §15 cross-language conformance is a per-fixture property; vault_002
# does not need its own conformance check because it shares vault_001's
# build pipeline (core/tests/common/fixture_builder.rs).


def section2_golden_vault_001() -> tuple[bool, list[str]]:
    """Run Task 15's full crypto verify against golden_vault_001.

    Returns (ok, lines). Loads every input fixture, runs the verify
    path, then re-runs against three tampered in-memory copies to
    confirm the verify path reliably rejects mutation.
    """
    lines: list[str] = []
    inputs = load_json_fixture(golden_vault_inputs_path(), "golden_vault_001_inputs.json")

    base = golden_vault_path()
    vault_toml_bytes = _require_file(base / "vault.toml", "golden_vault_001/vault.toml")
    bundle_bytes = _require_file(
        base / "identity.bundle.enc", "golden_vault_001/identity.bundle.enc"
    )
    manifest_bytes = _require_file(
        base / "manifest.cbor.enc", "golden_vault_001/manifest.cbor.enc"
    )
    block_uuid_str = inputs["block_uuid"]
    block_path = base / "blocks" / f"{block_uuid_str}.cbor.enc"
    block_bytes = _require_file(block_path, f"golden_vault_001/blocks/{block_uuid_str}.cbor.enc")

    # Parse vault.toml + identity bundle envelope (sanity-only on the
    # bundle envelope -- we don't decrypt the inner identity bundle).
    try:
        vt = parse_vault_toml(vault_toml_bytes.decode("utf-8"))
    except (ParseError, UnicodeDecodeError, KeyError) as e:
        return False, [f"FAIL: vault.toml parse: {e}"]
    expected_vault_uuid = bytes.fromhex(inputs["vault_uuid"].replace("-", ""))
    if vt.vault_uuid != expected_vault_uuid:
        return False, [
            f"FAIL: vault.toml.vault_uuid {vt.vault_uuid!r} != inputs {expected_vault_uuid!r}"
        ]

    try:
        bundle = parse_identity_bundle_envelope(bundle_bytes)
    except ParseError as e:
        return False, [f"FAIL: identity.bundle.enc parse: {e}"]
    if bundle.vault_uuid != vt.vault_uuid:
        return False, [
            f"FAIL: identity bundle vault_uuid {bundle.vault_uuid!r}"
            f" != vault.toml {vt.vault_uuid!r}"
        ]
    if bundle.created_at_ms != vt.created_at_ms:
        return False, [
            f"FAIL: identity bundle created_at_ms {bundle.created_at_ms}"
            f" != vault.toml {vt.created_at_ms}"
        ]

    # Parse and verify each contact card.
    owner_card: dict[str, Any] | None = None
    for card_path in sorted((base / "contacts").iterdir()):
        if not card_path.is_file() or card_path.suffix != ".card":
            continue
        try:
            card = parse_and_verify_card(card_path.read_bytes())
        except ParseError as e:
            return False, [f"FAIL: contact card {card_path.name}: {e}"]
        if card["decoded"]["contact_uuid"] == bytes.fromhex(
            inputs["owner"]["user_uuid"].replace("-", "")
        ):
            owner_card = card
        lines.append(
            f"PASS  card {card_path.name} (fp={card['fingerprint'].hex()})"
        )

    if owner_card is None:
        return False, lines + [
            f"FAIL: owner card not found in {base / 'contacts'}"
        ]

    # Cross-check the owner card's embedded keys against the JSON inputs.
    owner_inputs = inputs["owner"]
    if owner_card["decoded"]["x25519_pk"] != bytes.fromhex(owner_inputs["x25519_pk"]):
        return False, lines + ["FAIL: owner card x25519_pk != inputs"]
    if owner_card["decoded"]["ml_kem_768_pk"] != bytes.fromhex(owner_inputs["ml_kem_768_pk"]):
        return False, lines + ["FAIL: owner card ml_kem_768_pk != inputs"]
    if owner_card["decoded"]["ed25519_pk"] != bytes.fromhex(owner_inputs["ed25519_pk"]):
        return False, lines + ["FAIL: owner card ed25519_pk != inputs"]
    if owner_card["decoded"]["ml_dsa_65_pk"] != bytes.fromhex(owner_inputs["ml_dsa_65_pk"]):
        return False, lines + ["FAIL: owner card ml_dsa_65_pk != inputs"]

    # Full crypto verify on the original (untampered) files.
    ok, issues = verify_block_and_manifest(
        block_bytes=block_bytes,
        manifest_bytes=manifest_bytes,
        inputs=inputs,
        vt=vt,
        bundle=bundle,
        owner_card=owner_card,
    )
    if ok:
        lines.append("PASS  golden_vault_001 hybrid-decap + AEAD-decrypt + hybrid-verify")
    else:
        lines.append("FAIL  golden_vault_001 hybrid-decap + AEAD-decrypt + hybrid-verify")
        for i in issues:
            lines.append(f"      - {i}")
        return False, lines

    # Device-slot §3a/§5a clean-room replay.
    # Re-derive the IBK from the password path independently, so verify_device_slot
    # cross-checks the device path against a spec-derived value (not a shared local).
    password = inputs["password"].encode("utf-8")
    master_kek = argon2id_raw(
        password,
        vt.kdf_salt,
        memory_kib=vt.kdf_memory_kib,
        iterations=vt.kdf_iterations,
        parallelism=vt.kdf_parallelism,
    )
    try:
        ibk_from_pw = aead_decrypt(
            master_kek,
            bundle.wrap_pw_nonce,
            compose_aad(TAG_ID_WRAP_PW, vt.vault_uuid),
            bundle.wrap_pw_ct_with_tag,
        )
    except ValueError as e:
        lines.append(f"FAIL  device-slot: IBK re-derivation from password path: {e}")
        return False, lines
    try:
        verify_device_slot(base, inputs, ibk_from_pw)
        lines.append("PASS  device-slot (§3a/§5a): OK")
    except (AssertionError, FileNotFoundError, ValueError) as e:
        lines.append(f"FAIL  device-slot (§3a/§5a): {e}")
        return False, lines

    # Device-slot B.2 operation-level clean-room replay: open (against the golden
    # wrap, cross-checked vs the password-path IBK) + enrol round-trip (in-memory
    # §3a encode -> decode -> §5a unwrap). Reuses the shared §3a/§5a helpers.
    try:
        verify_device_slot_b2_ops(base, inputs, ibk_from_pw)
        lines.append("PASS  device-slot B.2 ops (open + enrol round-trip): OK")
    except (AssertionError, FileNotFoundError, ValueError) as e:
        lines.append(f"FAIL  device-slot B.2 ops (open + enrol round-trip): {e}")
        return False, lines

    # Tamper checks: every mutation must trigger a FAIL.
    tamper_cases = [
        (
            "flip byte 100 of manifest.cbor.enc",
            _bytes_flip(manifest_bytes, 100),
            block_bytes,
        ),
        (
            "flip byte 200 of block.cbor.enc",
            manifest_bytes,
            _bytes_flip(block_bytes, 200),
        ),
        (
            "truncate manifest signature by 5 bytes",
            manifest_bytes[:-5],
            block_bytes,
        ),
    ]
    for label, tampered_manifest, tampered_block in tamper_cases:
        ok2, _issues = verify_block_and_manifest(
            block_bytes=tampered_block,
            manifest_bytes=tampered_manifest,
            inputs=inputs,
            vt=vt,
            bundle=bundle,
            owner_card=owner_card,
        )
        if ok2:
            lines.append(f"FAIL  tamper-check: {label} -- verify did NOT reject")
            return False, lines
        lines.append(f"PASS  tamper-check: {label} (verify rejected as expected)")

    return True, lines
