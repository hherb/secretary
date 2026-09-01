"""Section R -- revoke re-key clean-room verification (vault-format.md §6.5.1).

Proves from `docs/` and the committed fixture alone that revoking a
recipient is a real RE-KEY: the revoked recipient's §6.2 wrap is gone AND
the body is re-encrypted under a fresh Block Content Key.
"""

from __future__ import annotations

from conformance_lib.cursor import ParseError
from conformance_lib.derivations import hybrid_decap
from conformance_lib.fixtures import _require_file, load_json_fixture, revoke_kat_dir
from conformance_lib.primitives import aead_decrypt
from conformance_lib.wire.block_file import parse_block_file
from conformance_lib.wire.envelopes import block_aead_aad

# ---------------------------------------------------------------------------
# Section R: revoke re-key clean-room verification (vault-format.md §6.5.1)
# ---------------------------------------------------------------------------
#
# Proves from docs/ + the committed fixture alone that revoking a recipient
# is a real re-key: the revoked recipient's §6.2 wrap is gone, the remaining
# recipient decaps+AEAD-decrypts the body under a FRESH block_content_key to
# the committed expected_plaintext, and the body ciphertext changed between
# the before- and after-revoke blocks. Mirrors the Rust always-run guard
# `revoke_kat_after_block_matches_inputs` (core/tests/revoke_kat.rs) but
# derives everything from the parsed after_block + inputs.json + the
# documented §7 hybrid-decap construction — no Rust-only knowledge.


def section_revoke_kat() -> tuple[bool, list[str]]:
    """Clean-room verification of the revoke re-key (vault-format.md §6.5.1).

    Proves from docs/ + the fixture alone that revoking a recipient:
      (a) drops the revoked recipient's §6.2 wrap (absent in after_block) while
          keeping the remaining recipient's wrap;
      (b) lets the remaining recipient decap+AEAD-decrypt the body under the NEW
          block_content_key to the expected plaintext;
      (c) is a real re-key — before_block held the revoked wrap and the body
          ciphertext differs between before and after (fresh BCK).
    """
    lines: list[str] = []
    base = revoke_kat_dir()
    inputs = load_json_fixture(base / "inputs.json", "revoke_kat/inputs.json")

    before_bytes = _require_file(
        base / "before_block.cbor.enc", "revoke_kat/before_block.cbor.enc"
    )
    after_bytes = _require_file(
        base / "after_block.cbor.enc", "revoke_kat/after_block.cbor.enc"
    )

    try:
        before = parse_block_file(before_bytes)
        after = parse_block_file(after_bytes)
    except ParseError as e:
        return False, [f"FAIL  revoke_kat::after_block_rekeyed - block parse: {e}"]

    remaining_fp = bytes.fromhex(inputs["remaining_recipient"]["fingerprint"])
    revoked_fp = bytes.fromhex(inputs["revoked_recipient"]["fingerprint"])
    block_uuid = bytes.fromhex(inputs["block_uuid"])

    before_fps = [e.fingerprint for e in before.recipients]
    after_fps = [e.fingerprint for e in after.recipients]

    issues: list[str] = []

    # (a) revoked wrap dropped; remaining wrap kept.
    if revoked_fp in after_fps:
        issues.append("(a) revoked recipient's wrap must be absent from after_block")
    if remaining_fp not in after_fps:
        issues.append("(a) remaining recipient's wrap must be present in after_block")

    # (b) remaining recipient decaps the new BCK and AEAD-decrypts the body.
    after_entry = None
    for e in after.recipients:
        if e.fingerprint == remaining_fp:
            after_entry = e
            break

    # Skip the decap leg when the remaining wrap is absent (already reported by
    # (a)); there is nothing to decap. Control falls through to the single
    # terminal report block, which prints FAIL then the accumulated issues.
    if after_entry is not None:
        sender_fp = bytes.fromhex(inputs["author"]["fingerprint"])
        sender_pk_bundle = bytes.fromhex(inputs["author"]["pk_bundle"])
        recipient_pk_bundle = bytes.fromhex(
            inputs["remaining_recipient"]["pk_bundle"]
        )
        try:
            bck = hybrid_decap(
                ct_x=after_entry.ct_x,
                ct_pq=after_entry.ct_pq,
                nonce_w=after_entry.nonce_w,
                ct_w_with_tag=after_entry.ct_w,
                sender_fp=sender_fp,
                recipient_fp=remaining_fp,
                sender_pk_bundle=sender_pk_bundle,
                recipient_pk_bundle=recipient_pk_bundle,
                recipient_x_sk=bytes.fromhex(
                    inputs["remaining_recipient"]["x25519_sk"]
                ),
                recipient_pq_sk=bytes.fromhex(
                    inputs["remaining_recipient"]["ml_kem_768_sk"]
                ),
                block_uuid=block_uuid,
            )
        except ValueError as e:
            issues.append(f"(b) hybrid-decap of new BCK failed: {e}")
            bck = None

        if bck is not None:
            body_aad = block_aead_aad(after, after_bytes)
            body_ct_with_tag = after.aead.ct + after.aead.tag
            try:
                recovered = aead_decrypt(
                    bck, after.aead.nonce, body_aad, body_ct_with_tag
                )
            except ValueError as e:
                issues.append(f"(b) body AEAD-decrypt under new BCK failed: {e}")
                recovered = None
            if recovered is not None:
                expected_cbor = bytes.fromhex(inputs["expected_plaintext"]["cbor"])
                if recovered != expected_cbor:
                    issues.append(
                        "(b) recovered plaintext bytes != committed "
                        "expected_plaintext.cbor"
                    )

    # (c) before held the revoked wrap; body ciphertext changed (real re-key).
    if revoked_fp not in before_fps:
        issues.append("(c) before_block must have contained the revoked recipient's wrap")
    if remaining_fp not in before_fps:
        issues.append(
            "(c) before_block must have contained the remaining recipient's wrap"
        )
    if before.aead.ct == after.aead.ct:
        issues.append("(c) re-key must change the body ciphertext (fresh BCK)")

    if issues:
        lines.append("FAIL  revoke_kat::after_block_rekeyed")
        for i in issues:
            lines.append(f"      - {i}")
        return False, lines

    lines.append("PASS  revoke_kat::after_block_rekeyed")
    return True, lines
