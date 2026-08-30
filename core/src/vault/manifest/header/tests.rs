//! Unit tests for the manifest binary header (§4.1) and AEAD body wiring.
//!
//! Moved verbatim out of the pre-split `manifest/tests.rs` (#564); shared
//! fixtures live in [`crate::vault::manifest::test_support`].

use crate::crypto::aead::AEAD_TAG_LEN;
use crate::vault::manifest::encode_manifest;
use crate::vault::manifest::test_support::{
    fixed_manifest_header, minimal_manifest, populated_manifest, test_ibk, test_nonce,
};

use super::*;

// ---- Binary header encode/decode (§4.1) ------------------------------
//
// The header is the 42-byte AAD prefix that wraps the AEAD body. Every
// negative test below pins one §4.1 invariant; the round-trip and
// tamper tests pin the AAD-binding property (a tampered header
// invalidates the Poly1305 tag).

#[test]
fn header_encode_round_trips() {
    let h = fixed_manifest_header();
    let bytes = h.encode();
    assert_eq!(
        bytes.len(),
        MANIFEST_HEADER_LEN,
        "encoded header is 42 bytes"
    );
    assert_eq!(bytes.len(), 42, "MANIFEST_HEADER_LEN spec value");

    // Pin the constant prefix. magic = "SECR" big-endian.
    assert_eq!(&bytes[0..4], b"SECR");
    // format_version 0x0001
    assert_eq!(&bytes[4..6], &[0x00, 0x01]);
    // suite_id 0x0001
    assert_eq!(&bytes[6..8], &[0x00, 0x01]);
    // file_kind 0x0002 (manifest)
    assert_eq!(&bytes[8..10], &[0x00, 0x02]);

    let (decoded, tail) = ManifestHeader::decode(&bytes).expect("decode round-trip");
    assert!(tail.is_empty(), "exact-length input leaves no tail");
    assert_eq!(decoded, h, "header round-trips");
}

#[test]
fn header_decode_returns_tail() {
    // Decoder leaves any post-header bytes as the returned tail so a
    // future ManifestFile decoder (Task 7) can keep parsing.
    let h = fixed_manifest_header();
    let mut buf = h.encode().to_vec();
    buf.extend_from_slice(&[0xab, 0xcd, 0xef]);
    let (decoded, tail) = ManifestHeader::decode(&buf).expect("decode with trailer");
    assert_eq!(decoded, h);
    assert_eq!(tail, &[0xab, 0xcd, 0xef]);
}

#[test]
fn header_decode_rejects_bad_magic() {
    let mut bytes = [0u8; MANIFEST_HEADER_LEN];
    // First 4 bytes deliberately wrong; rest doesn't matter — magic
    // is checked first.
    let err = ManifestHeader::decode(&bytes).expect_err("bad magic must reject");
    assert!(
        matches!(err, ManifestError::BadMagic { expected, got }
            if expected == MAGIC && got == 0),
        "expected BadMagic with expected=MAGIC and got=0, got {err:?}"
    );
    // Also try a non-zero wrong magic to make sure the comparison is
    // structural, not just zero-vs-nonzero.
    bytes[0..4].copy_from_slice(&0xdead_beef_u32.to_be_bytes());
    let err = ManifestHeader::decode(&bytes).expect_err("bad magic must reject");
    assert!(
        matches!(err, ManifestError::BadMagic { expected, got }
            if expected == MAGIC && got == 0xdead_beef),
        "expected BadMagic with got=0xdeadbeef, got {err:?}"
    );
}

#[test]
fn header_decode_rejects_wrong_format_version() {
    let mut bytes = fixed_manifest_header().encode();
    // format_version lives at offset 4..6 (after magic).
    bytes[4..6].copy_from_slice(&0x0002_u16.to_be_bytes());
    let err = ManifestHeader::decode(&bytes).expect_err("non-v1 format_version must reject");
    assert!(
        matches!(err, ManifestError::UnsupportedFormatVersion(2)),
        "expected UnsupportedFormatVersion(2), got {err:?}"
    );
}

#[test]
fn header_decode_rejects_wrong_suite_id() {
    let mut bytes = fixed_manifest_header().encode();
    // suite_id lives at offset 6..8.
    bytes[6..8].copy_from_slice(&0x0099_u16.to_be_bytes());
    let err = ManifestHeader::decode(&bytes).expect_err("non-v1 suite_id must reject");
    assert!(
        matches!(err, ManifestError::UnsupportedSuiteId(0x99)),
        "expected UnsupportedSuiteId(0x99), got {err:?}"
    );
}

#[test]
fn header_decode_rejects_wrong_file_kind() {
    let mut bytes = fixed_manifest_header().encode();
    // file_kind lives at offset 8..10. 0x0001 is the identity-bundle
    // file kind; rejecting it here pins the §4.1 cross-file-kind
    // anti-substitution check at the binary layer (the AEAD AAD also
    // catches it later, but we'd rather fail with a typed error than
    // a generic AEAD failure when the file-kind alone is enough to
    // disambiguate).
    bytes[8..10].copy_from_slice(&0x0001_u16.to_be_bytes());
    let err = ManifestHeader::decode(&bytes).expect_err("non-manifest file_kind must reject");
    assert!(
        matches!(
            err,
            ManifestError::UnsupportedFileKind {
                expected: FILE_KIND_MANIFEST,
                got: 0x0001
            }
        ),
        "expected UnsupportedFileKind {{ expected: 0x0002, got: 0x0001 }}, got {err:?}"
    );
}

#[test]
fn header_decode_rejects_truncation() {
    // 41 bytes — one short of the §4.1 header length.
    let bytes = [0u8; MANIFEST_HEADER_LEN - 1];
    let err = ManifestHeader::decode(&bytes).expect_err("41 bytes must reject as truncated");
    assert!(
        matches!(
            err,
            ManifestError::HeaderTruncated {
                need: MANIFEST_HEADER_LEN,
                got: 41
            }
        ),
        "expected HeaderTruncated {{ need: 42, got: 41 }}, got {err:?}"
    );

    // Also: empty input.
    let err = ManifestHeader::decode(&[]).expect_err("empty input must reject as truncated");
    assert!(
        matches!(
            err,
            ManifestError::HeaderTruncated {
                need: MANIFEST_HEADER_LEN,
                got: 0
            }
        ),
        "expected HeaderTruncated with got=0, got {err:?}"
    );
}

// ---- AEAD body encrypt/decrypt round-trip ---------------------------
//
// Each test below also drives `encode::encode_manifest` for its plaintext
// and `decode::decode_manifest` on the return leg; the property pinned is
// `encrypt_manifest_body` / `decrypt_manifest_body`'s AAD binding.

#[test]
fn encrypt_decrypt_body_round_trip() {
    let m = populated_manifest();
    let manifest_bytes = encode_manifest(&m).expect("encode manifest body");
    let header = fixed_manifest_header();
    let ibk = test_ibk(0x00);
    let nonce = test_nonce();

    let ct_with_tag =
        encrypt_manifest_body(&header, &manifest_bytes, &ibk, &nonce).expect("encrypt body");
    // The tag is appended to the ciphertext per crypto::aead's contract.
    assert_eq!(
        ct_with_tag.len(),
        manifest_bytes.len() + AEAD_TAG_LEN,
        "ct||tag length is plaintext+16"
    );

    let ibk2 = test_ibk(0x00);
    let recovered =
        decrypt_manifest_body(&header, &ct_with_tag, &ibk2, &nonce).expect("decrypt body");

    // populated_manifest's input arrays are non-canonical-order; the
    // decoded copy is in canonical order. Use the same sort-then-compare
    // discipline as the existing `roundtrip_populated_manifest` test.
    let mut m_sorted = m.clone();
    m_sorted.vector_clock.sort_by_key(|a| a.device_uuid);
    m_sorted.blocks.sort_by_key(|a| a.block_uuid);
    for blk in &mut m_sorted.blocks {
        blk.recipients.sort();
        blk.vector_clock_summary.sort_by_key(|a| a.device_uuid);
    }
    m_sorted.trash.sort_by_key(|a| a.block_uuid);
    assert_eq!(recovered, m_sorted, "decrypted manifest matches original");
}

#[test]
fn tamper_header_breaks_aead() {
    // Central §4.1 spec property: the header is bound into the AEAD
    // tag via AAD, so a single-byte flip in the header invalidates
    // the tag on decrypt.
    let m = minimal_manifest();
    let manifest_bytes = encode_manifest(&m).expect("encode");
    let header = fixed_manifest_header();
    let ibk = test_ibk(0x00);
    let nonce = test_nonce();
    let ct_with_tag =
        encrypt_manifest_body(&header, &manifest_bytes, &ibk, &nonce).expect("encrypt");

    // Tamper #1: flip a byte in vault_uuid.
    let mut tampered = header;
    tampered.vault_uuid[0] ^= 0xff;
    let err = decrypt_manifest_body(&tampered, &ct_with_tag, &ibk, &nonce)
        .expect_err("tampered header must fail AEAD");
    assert!(
        matches!(err, ManifestError::AeadFailure),
        "expected AeadFailure (tampered vault_uuid), got {err:?}"
    );

    // Tamper #2: change last_mod_ms.
    let tampered = ManifestHeader {
        last_mod_ms: header.last_mod_ms.wrapping_add(1),
        ..header
    };
    let err = decrypt_manifest_body(&tampered, &ct_with_tag, &ibk, &nonce)
        .expect_err("tampered last_mod_ms must fail AEAD");
    assert!(
        matches!(err, ManifestError::AeadFailure),
        "expected AeadFailure (tampered last_mod_ms), got {err:?}"
    );
}

#[test]
fn tamper_ct_breaks_aead() {
    let m = minimal_manifest();
    let manifest_bytes = encode_manifest(&m).expect("encode");
    let header = fixed_manifest_header();
    let ibk = test_ibk(0x00);
    let nonce = test_nonce();
    let mut ct_with_tag =
        encrypt_manifest_body(&header, &manifest_bytes, &ibk, &nonce).expect("encrypt");

    // Flip a byte deep inside the ciphertext (not the tag region).
    // `manifest_bytes.len()` would be the start of the tag; pick
    // somewhere safely before that.
    ct_with_tag[2] ^= 0xff;
    let err = decrypt_manifest_body(&header, &ct_with_tag, &ibk, &nonce)
        .expect_err("tampered ct must fail AEAD");
    assert!(
        matches!(err, ManifestError::AeadFailure),
        "expected AeadFailure on flipped ciphertext byte, got {err:?}"
    );
}

#[test]
fn wrong_ibk_breaks_aead() {
    let m = minimal_manifest();
    let manifest_bytes = encode_manifest(&m).expect("encode");
    let header = fixed_manifest_header();
    let ibk = test_ibk(0x00);
    let nonce = test_nonce();
    let ct_with_tag =
        encrypt_manifest_body(&header, &manifest_bytes, &ibk, &nonce).expect("encrypt");

    let wrong_ibk = test_ibk(0xff);
    let err = decrypt_manifest_body(&header, &ct_with_tag, &wrong_ibk, &nonce)
        .expect_err("wrong IBK must fail AEAD");
    assert!(
        matches!(err, ManifestError::AeadFailure),
        "expected AeadFailure under wrong IBK, got {err:?}"
    );
}
