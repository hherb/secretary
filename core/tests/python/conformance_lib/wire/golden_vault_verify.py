"""§2.6 the full `golden_vault_001/` open-vault verification.

One function, deliberately kept whole: it is the end-to-end transcript a
clean-room implementer follows -- parse `vault.toml`, Argon2id -> Master
KEK, unwrap the IBK, AEAD-decrypt the manifest body, hybrid-KEM-decap the
owner's recipient wrap, AEAD-decrypt the block body, hybrid-verify both
signatures, and cross-check every plaintext field. Splitting it would
scatter the one ordering the spec actually mandates.
"""

from __future__ import annotations

from typing import Any

from conformance_lib.codec.manifest_decode import py_decode_manifest
from conformance_lib.codec.manifest_encode import py_encode_manifest
from conformance_lib.constants import ED25519_SIG_LEN, FINGERPRINT_LEN, ML_DSA_65_SIG_LEN, TAG_BLOCK_SIG, TAG_ID_WRAP_PW, TAG_MANIFEST_SIG
from conformance_lib.cursor import ParseError
from conformance_lib.derivations import compose_aad, hybrid_decap, hybrid_verify
from conformance_lib.primitives import aead_decrypt, argon2id_raw, blake3_256
from conformance_lib.rejection import _REJECTION_EXCEPTIONS
from conformance_lib.wire.block_file import parse_block_file
from conformance_lib.wire.envelopes import IdentityBundleEnvelope, block_aead_aad, block_signed_range, manifest_aead_aad, manifest_signed_range, parse_manifest_file
from conformance_lib.wire.vault_toml import VaultToml

# ---------------------------------------------------------------------------
# §2.6 The full golden_vault_001 verification
# ---------------------------------------------------------------------------


def verify_block_and_manifest(
    *,
    block_bytes: bytes,
    manifest_bytes: bytes,
    inputs: dict[str, Any],
    vt: VaultToml,
    bundle: IdentityBundleEnvelope,
    owner_card: dict[str, Any],
) -> tuple[bool, list[str]]:
    """Run the full hybrid-decap + AEAD-decrypt + hybrid-verify path
    on both files. Returns (ok, issues).

    Pure(-ish) function: takes already-loaded inputs/files, returns
    diagnostics. Easy to call again on tampered copies.
    """
    issues: list[str] = []

    # ----- Block file -----
    try:
        parsed_block = parse_block_file(block_bytes)
    except ParseError as e:
        return False, [f"block parse: {e}"]

    # 1. Recompute signed range and verify §8 hybrid signature.
    block_signed = block_signed_range(parsed_block, block_bytes)
    expected_signed_len = (
        len(block_bytes)
        - FINGERPRINT_LEN
        - 2
        - ED25519_SIG_LEN
        - 2
        - ML_DSA_65_SIG_LEN
    )
    if len(block_signed) != expected_signed_len:
        issues.append(
            f"block signed-range length: recomputed={len(block_signed)},"
            f" file-implied={expected_signed_len}"
        )

    ok, reason = hybrid_verify(
        TAG_BLOCK_SIG,
        block_signed,
        parsed_block.signature.sig_ed,
        parsed_block.signature.sig_pq,
        owner_card["decoded"]["ed25519_pk"],
        owner_card["decoded"]["ml_dsa_65_pk"],
    )
    if not ok:
        issues.append(f"block signature: {reason}")

    # 2. Owner is the only recipient on this fixture (§14 generator
    # output). Locate the owner's wrap entry and decap.
    owner_fp = owner_card["fingerprint"]
    owner_entry = None
    for e in parsed_block.recipients:
        if e.fingerprint == owner_fp:
            owner_entry = e
            break
    if owner_entry is None:
        issues.append("block recipient table missing owner entry")
        return False, issues

    sender_pk_bundle = owner_card["pk_bundle"]
    recipient_pk_bundle = owner_card["pk_bundle"]
    try:
        bck = hybrid_decap(
            ct_x=owner_entry.ct_x,
            ct_pq=owner_entry.ct_pq,
            nonce_w=owner_entry.nonce_w,
            ct_w_with_tag=owner_entry.ct_w,
            sender_fp=owner_fp,
            recipient_fp=owner_fp,
            sender_pk_bundle=sender_pk_bundle,
            recipient_pk_bundle=recipient_pk_bundle,
            recipient_x_sk=bytes.fromhex(inputs["owner"]["x25519_sk"]),
            recipient_pq_sk=bytes.fromhex(inputs["owner"]["ml_kem_768_sk"]),
            block_uuid=parsed_block.header.block_uuid,
        )
    except ValueError as e:
        issues.append(f"block hybrid-decap: {e}")
        return False, issues

    # 3. AEAD-decrypt block body.
    body_aad = block_aead_aad(parsed_block, block_bytes)
    body_ct_with_tag = parsed_block.aead.ct + parsed_block.aead.tag
    try:
        block_pt_bytes = aead_decrypt(
            bck, parsed_block.aead.nonce, body_aad, body_ct_with_tag
        )
    except ValueError as e:
        issues.append(f"block body AEAD: {e}")
        return False, issues

    # 4. Parse plaintext + cross-check records.
    import cbor2

    try:
        block_pt = cbor2.loads(block_pt_bytes)
    except cbor2.CBORDecodeError as e:
        issues.append(f"block plaintext CBOR decode: {e}")
        return False, issues

    expected_pt = inputs["block_plaintext"]
    if block_pt.get("block_version") != expected_pt["block_version"]:
        issues.append(
            f"block_version: parsed={block_pt.get('block_version')},"
            f" expected={expected_pt['block_version']}"
        )
    if block_pt.get("block_name") != expected_pt["block_name"]:
        issues.append(
            f"block_name: parsed={block_pt.get('block_name')!r},"
            f" expected={expected_pt['block_name']!r}"
        )
    if block_pt.get("schema_version") != expected_pt["schema_version"]:
        issues.append(
            f"schema_version: parsed={block_pt.get('schema_version')},"
            f" expected={expected_pt['schema_version']}"
        )

    parsed_records = block_pt.get("records") or []
    expected_records = expected_pt["records"]
    if len(parsed_records) != len(expected_records):
        issues.append(
            f"records count: parsed={len(parsed_records)},"
            f" expected={len(expected_records)}"
        )
    else:
        for i, (got, want) in enumerate(zip(parsed_records, expected_records)):
            got_uuid = got.get("record_uuid")
            want_uuid = bytes.fromhex(want["record_uuid"].replace("-", ""))
            if got_uuid != want_uuid:
                issues.append(
                    f"records[{i}].record_uuid: parsed={got_uuid!r},"
                    f" expected={want_uuid!r}"
                )
            if got.get("record_type") != want["record_type"]:
                issues.append(
                    f"records[{i}].record_type: parsed={got.get('record_type')!r},"
                    f" expected={want['record_type']!r}"
                )
            if got.get("tags", []) != want.get("tags", []):
                issues.append(
                    f"records[{i}].tags: parsed={got.get('tags')!r},"
                    f" expected={want.get('tags')!r}"
                )
            # tombstone is omitted on the wire when False; defensively
            # treat absent == False (matches block.rs:408-410).
            got_tomb = bool(got.get("tombstone", False))
            want_tomb = bool(want.get("tombstone", False))
            if got_tomb != want_tomb:
                issues.append(
                    f"records[{i}].tombstone: parsed={got_tomb}, expected={want_tomb}"
                )
            got_fields = got.get("fields") or {}
            want_fields = want.get("fields") or {}
            if set(got_fields.keys()) != set(want_fields.keys()):
                issues.append(
                    f"records[{i}].fields keys: parsed={sorted(got_fields)},"
                    f" expected={sorted(want_fields)}"
                )
            for fname, want_field in want_fields.items():
                got_field = got_fields.get(fname) or {}
                if want_field.get("value_type") == "text":
                    got_v = got_field.get("value")
                    want_v = want_field.get("value_text")
                    if got_v != want_v:
                        issues.append(
                            f"records[{i}].fields[{fname}].value:"
                            f" parsed={got_v!r}, expected={want_v!r}"
                        )

    # ----- Manifest file -----
    try:
        manifest = parse_manifest_file(manifest_bytes)
    except ParseError as e:
        issues.append(f"manifest parse: {e}")
        return False, issues

    # 5. Recompute manifest signed range; sanity-length-check.
    manifest_signed = manifest_signed_range(manifest)
    expected_msigned_len = (
        len(manifest_bytes)
        - FINGERPRINT_LEN
        - 2
        - ED25519_SIG_LEN
        - 2
        - ML_DSA_65_SIG_LEN
    )
    if len(manifest_signed) != expected_msigned_len:
        issues.append(
            f"manifest signed-range length: recomputed={len(manifest_signed)},"
            f" file-implied={expected_msigned_len}"
        )

    # 6. Manifest hybrid-verify.
    ok, reason = hybrid_verify(
        TAG_MANIFEST_SIG,
        manifest_signed,
        manifest.sig_ed,
        manifest.sig_pq,
        owner_card["decoded"]["ed25519_pk"],
        owner_card["decoded"]["ml_dsa_65_pk"],
    )
    if not ok:
        issues.append(f"manifest signature: {reason}")

    # 7. Derive master KEK from password+salt+params, unwrap IBK.
    password = inputs["password"].encode("utf-8")
    master_kek = argon2id_raw(
        password,
        vt.kdf_salt,
        memory_kib=vt.kdf_memory_kib,
        iterations=vt.kdf_iterations,
        parallelism=vt.kdf_parallelism,
    )
    try:
        ibk = aead_decrypt(
            master_kek,
            bundle.wrap_pw_nonce,
            compose_aad(TAG_ID_WRAP_PW, vt.vault_uuid),
            bundle.wrap_pw_ct_with_tag,
        )
    except ValueError as e:
        issues.append(f"IBK unwrap (wrap_pw): {e}")
        return False, issues
    if len(ibk) != 32:
        issues.append(f"IBK length: {len(ibk)} (expected 32)")
        return False, issues

    # 8. AEAD-decrypt manifest body.
    manifest_aad = manifest_aead_aad(manifest)
    manifest_ct_with_tag = manifest.aead_ct + manifest.aead_tag
    try:
        manifest_pt_bytes = aead_decrypt(
            ibk, manifest.aead_nonce, manifest_aad, manifest_ct_with_tag
        )
    except ValueError as e:
        issues.append(f"manifest body AEAD: {e}")
        return False, issues

    try:
        # §4.2/§4.3 strict decode, not a bare `cbor2.loads` (#585). The
        # strict decoder enforces the five array sort disciplines, rejects
        # duplicate keys at every KNOWN level, and retains each unknown
        # subtree's raw bytes so it can be re-emitted verbatim (#592).
        manifest_pt = py_decode_manifest(manifest_pt_bytes)
    except (*_REJECTION_EXCEPTIONS, RecursionError) as e:
        # `RecursionError` is included deliberately: `_scan_item` and
        # `_check_canonical_item` recurse once per CBOR nesting level, so a
        # deeply nested unknown subtree exhausts the stack. Without it that
        # crashes the whole conformance run with a traceback instead of
        # reporting a clean FAIL for this vault (#595).
        issues.append(f"manifest plaintext CBOR decode: {type(e).__name__}: {e}")
        return False, issues

    # 9. Cross-check manifest body fields.
    expected_vault_uuid = bytes.fromhex(inputs["vault_uuid"].replace("-", ""))
    expected_block_uuid = bytes.fromhex(inputs["block_uuid"].replace("-", ""))
    expected_owner_uuid = bytes.fromhex(inputs["owner"]["user_uuid"].replace("-", ""))

    if manifest_pt.get("vault_uuid") != expected_vault_uuid:
        issues.append(
            f"manifest.vault_uuid: parsed={manifest_pt.get('vault_uuid')!r},"
            f" expected={expected_vault_uuid!r}"
        )
    if manifest_pt.get("owner_user_uuid") != expected_owner_uuid:
        issues.append(
            f"manifest.owner_user_uuid: parsed={manifest_pt.get('owner_user_uuid')!r},"
            f" expected={expected_owner_uuid!r}"
        )
    if manifest_pt.get("manifest_version") != 1:
        issues.append(
            f"manifest.manifest_version: parsed={manifest_pt.get('manifest_version')!r}"
        )

    blocks = manifest_pt.get("blocks") or []
    if len(blocks) != 1:
        issues.append(f"manifest.blocks count: parsed={len(blocks)} (expected 1)")
    else:
        b0 = blocks[0]
        if b0.get("block_uuid") != expected_block_uuid:
            issues.append(
                f"manifest.blocks[0].block_uuid: parsed={b0.get('block_uuid')!r},"
                f" expected={expected_block_uuid!r}"
            )
        actual_block_fp = blake3_256(block_bytes)
        if b0.get("fingerprint") != actual_block_fp:
            issues.append(
                f"manifest.blocks[0].fingerprint: parsed={b0.get('fingerprint')!r},"
                f" expected (BLAKE3-256 of block file)={actual_block_fp!r}"
            )
        # Recipients in the manifest are USER UUIDs (not card
        # fingerprints) -- block.rs:333-338 + manifest.rs:336-338.
        # The owner is the only recipient in this fixture.
        recipients = b0.get("recipients") or []
        if len(recipients) != 1 or recipients[0] != expected_owner_uuid:
            issues.append(
                f"manifest.blocks[0].recipients: parsed={recipients!r},"
                f" expected=[{expected_owner_uuid!r}]"
            )

    # KDF params should mirror vault.toml.
    kdf = manifest_pt.get("kdf_params") or {}
    if kdf.get("memory_kib") != vt.kdf_memory_kib:
        issues.append(
            f"manifest.kdf_params.memory_kib: parsed={kdf.get('memory_kib')},"
            f" expected={vt.kdf_memory_kib}"
        )
    if kdf.get("iterations") != vt.kdf_iterations:
        issues.append(
            f"manifest.kdf_params.iterations: parsed={kdf.get('iterations')},"
            f" expected={vt.kdf_iterations}"
        )
    if kdf.get("parallelism") != vt.kdf_parallelism:
        issues.append(
            f"manifest.kdf_params.parallelism: parsed={kdf.get('parallelism')},"
            f" expected={vt.kdf_parallelism}"
        )
    if kdf.get("salt") != vt.kdf_salt:
        issues.append(
            f"manifest.kdf_params.salt: parsed={kdf.get('salt')!r},"
            f" expected={vt.kdf_salt!r}"
        )

    # The §4.3 step-4 obligation, exercised against the frozen fixture:
    # re-encoding the parsed manifest must reproduce the input byte for byte.
    reencoded = py_encode_manifest(manifest_pt)
    if reencoded != manifest_pt_bytes:
        issues.append(
            "manifest body re-encode is not byte-identical: "
            f"{len(reencoded)} bytes out vs {len(manifest_pt_bytes)} in"
        )

    return (not issues), issues
