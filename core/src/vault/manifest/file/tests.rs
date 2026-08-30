//! Unit tests for the `ManifestFile` §4.1 envelope encode/decode.
//!
//! Moved verbatim out of the pre-split `manifest/tests.rs` (#564); shared
//! fixtures live in [`crate::vault::manifest::test_support`].
//!
//! Sign / verify (§8) and §10 rollback resistance are
//! [`sign`](super::sign)'s own `tests`.
//!
//! One edit beyond the move: `fixture_manifest_file`'s doc said the
//! sign/verify tests were "below", which the split made false.

use crate::vault::manifest::test_support::{fixed_manifest_header, test_nonce};

use super::*;

// ---- ManifestFile envelope encode/decode (§4.1) ----------------------

/// Build a deterministic, fully-populated `ManifestFile` for the
/// envelope-level tests: pinned header, pinned AEAD ciphertext and
/// tag, pinned author fingerprint, and a length-correct (but
/// fake-content) ML-DSA-65 signature. The "fake content" makes the
/// envelope tests truly orthogonal to signature verification — the
/// signature is just bytes here. The sign/verify tests — in
/// [`sign`](super::sign)'s own `tests` since #564, "below" here before
/// that — use real `sign_manifest` output.
fn fixture_manifest_file() -> ManifestFile {
    ManifestFile {
        header: fixed_manifest_header(),
        aead_nonce: test_nonce(),
        aead_ct: vec![0x77; 32],
        aead_tag: [0x88; AEAD_TAG_LEN],
        author_fingerprint: [0xa5; 16],
        sig_ed: [0x44; ED25519_SIG_LEN],
        sig_pq: MlDsa65Sig::from_bytes(&vec![0x55; ML_DSA_65_SIG_LEN])
            .expect("ML-DSA-65 sig bytes"),
    }
}

#[test]
fn manifest_file_encode_decode_round_trip() {
    let file = fixture_manifest_file();
    let bytes = encode_manifest_file(&file).expect("encode_manifest_file");
    let decoded = decode_manifest_file(&bytes).expect("decode_manifest_file");
    assert_eq!(decoded, file, "ManifestFile round-trips bit-identically");
    let bytes_again = encode_manifest_file(&decoded).expect("re-encode_manifest_file");
    assert_eq!(bytes, bytes_again, "encode is deterministic");
}

#[test]
fn encode_decode_pinned_byte_layout() {
    // Spec arithmetic for §4.1:
    //   header(42) + aead_nonce(24) + aead_ct_len(4) + aead_ct(N)
    //   + aead_tag(16) + author_fingerprint(16) + sig_ed_len(2)
    //   + sig_ed(64) + sig_pq_len(2) + sig_pq(3309)
    let file = fixture_manifest_file();
    let bytes = encode_manifest_file(&file).expect("encode");
    let ct_len = file.aead_ct.len();
    let expected = 42 + 24 + 4 + ct_len + 16 + 16 + 2 + 64 + 2 + 3309;
    assert_eq!(
        bytes.len(),
        expected,
        "encoded length matches §4.1 spec arithmetic"
    );

    // Spot-check: sig_ed_len at offset (42+24+4+ct_len+16+16) = 64.
    let sig_ed_len_offset = 42 + 24 + 4 + ct_len + 16 + 16;
    let sig_ed_len_bytes = [bytes[sig_ed_len_offset], bytes[sig_ed_len_offset + 1]];
    assert_eq!(
        u16::from_be_bytes(sig_ed_len_bytes),
        64,
        "sig_ed_len encodes 64 at the spec offset"
    );

    // Spot-check: aead_ct_len is u32 BE at offset 42+24=66.
    let ct_len_offset = 42 + 24;
    let ct_len_bytes = [
        bytes[ct_len_offset],
        bytes[ct_len_offset + 1],
        bytes[ct_len_offset + 2],
        bytes[ct_len_offset + 3],
    ];
    assert_eq!(
        u32::from_be_bytes(ct_len_bytes) as usize,
        ct_len,
        "aead_ct_len encodes the actual aead_ct length"
    );

    // Spot-check: sig_pq_len at offset (sig_ed_len_offset+2+64) = 3309.
    let sig_pq_len_offset = sig_ed_len_offset + 2 + 64;
    let sig_pq_len_bytes = [bytes[sig_pq_len_offset], bytes[sig_pq_len_offset + 1]];
    assert_eq!(
        u16::from_be_bytes(sig_pq_len_bytes),
        3309,
        "sig_pq_len encodes 3309 at the spec offset"
    );
}

#[test]
fn decode_rejects_sig_ed_wrong_length() {
    let file = fixture_manifest_file();
    let mut bytes = encode_manifest_file(&file).expect("encode");
    let ct_len = file.aead_ct.len();
    // sig_ed_len lives at offset (42+24+4+ct_len+16+16); flip it from
    // 64 to 63.
    let off = 42 + 24 + 4 + ct_len + 16 + 16;
    bytes[off..off + 2].copy_from_slice(&63u16.to_be_bytes());
    let err = decode_manifest_file(&bytes).expect_err("sig_ed_len=63 must reject");
    assert!(
        matches!(
            err,
            ManifestError::SigEdWrongLength {
                expected: 64,
                got: 63
            }
        ),
        "expected SigEdWrongLength {{ expected: 64, got: 63 }}, got {err:?}"
    );
}

#[test]
fn decode_rejects_sig_pq_wrong_length() {
    let file = fixture_manifest_file();
    let mut bytes = encode_manifest_file(&file).expect("encode");
    let ct_len = file.aead_ct.len();
    // sig_pq_len lives at offset (42+24+4+ct_len+16+16+2+64).
    let off = 42 + 24 + 4 + ct_len + 16 + 16 + 2 + 64;
    bytes[off..off + 2].copy_from_slice(&3308u16.to_be_bytes());
    let err = decode_manifest_file(&bytes).expect_err("sig_pq_len=3308 must reject");
    assert!(
        matches!(
            err,
            ManifestError::SigPqWrongLength {
                expected: 3309,
                got: 3308
            }
        ),
        "expected SigPqWrongLength {{ expected: 3309, got: 3308 }}, got {err:?}"
    );
}

#[test]
fn decode_rejects_aead_ct_len_overflow() {
    // Encode a valid file, then bump aead_ct_len past the available
    // remaining body. Decoder must surface AeadCtLenMismatch (or, if
    // the declared length pushes the suffix-reservation impossible,
    // SectionTruncated at "aead_ct"). We pin the AeadCtLenMismatch
    // case here: declared = ct_len + 100, plenty of fixed-suffix
    // bytes still present.
    let file = fixture_manifest_file();
    let mut bytes = encode_manifest_file(&file).expect("encode");
    let original_ct_len = file.aead_ct.len() as u32;
    // aead_ct_len lives at offset 42+24=66.
    let off = 42 + 24;
    let bumped = original_ct_len + 100;
    bytes[off..off + 4].copy_from_slice(&bumped.to_be_bytes());
    let err = decode_manifest_file(&bytes).expect_err("oversized aead_ct_len must reject");
    assert!(
        matches!(
            err,
            ManifestError::AeadCtLenMismatch {
                declared,
                remaining,
            } if declared == bumped && remaining == original_ct_len as usize
        ),
        "expected AeadCtLenMismatch, got {err:?}"
    );
}

#[test]
fn decode_rejects_trailing_bytes() {
    let file = fixture_manifest_file();
    let mut bytes = encode_manifest_file(&file).expect("encode");
    bytes.push(0x99);
    let err = decode_manifest_file(&bytes).expect_err("trailing junk byte must reject");
    assert!(
        matches!(err, ManifestError::TrailingBytes(1)),
        "expected TrailingBytes(1), got {err:?}"
    );
}

#[test]
fn decode_rejects_truncation_at_header() {
    // 41 bytes — one short of the §4.1 header.
    let bytes = [0u8; MANIFEST_HEADER_LEN - 1];
    let err = decode_manifest_file(&bytes).expect_err("41 bytes must reject as truncated");
    assert!(
        matches!(
            err,
            ManifestError::HeaderTruncated {
                need: MANIFEST_HEADER_LEN,
                got: 41
            }
        ),
        "expected HeaderTruncated, got {err:?}"
    );
}

#[test]
fn decode_rejects_truncation_at_aead_section() {
    // Header (42) plus 23 of the 24 nonce bytes.
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&fixed_manifest_header().encode());
    bytes.extend_from_slice(&[0u8; 23]);
    let err =
        decode_manifest_file(&bytes).expect_err("header + 23 bytes must reject as nonce-truncated");
    assert!(
        matches!(
            err,
            ManifestError::SectionTruncated {
                section: "aead_nonce",
                need: 24,
                got: 23
            }
        ),
        "expected SectionTruncated at aead_nonce, got {err:?}"
    );
}

#[test]
fn decode_rejects_truncation_at_signature_suffix() {
    // Header (42) + nonce (24) + aead_ct_len (4) + nothing else —
    // the fixed-size suffix needs 16 (tag) + 16 (fp) + 2 + 64 + 2 +
    // 3309 = 3409 bytes; we provide 0 so the decoder should reject
    // truncated at the aead_ct boundary.
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(&fixed_manifest_header().encode());
    bytes.extend_from_slice(&[0u8; 24]); // nonce
    bytes.extend_from_slice(&0u32.to_be_bytes()); // aead_ct_len = 0
                                                  // No more bytes — the fixed suffix-after-ct (3409) is missing.
    let err = decode_manifest_file(&bytes).expect_err("missing signature suffix must reject");
    assert!(
        matches!(
            err,
            ManifestError::SectionTruncated {
                section: "aead_ct",
                need,
                got: 0,
            } if need == AEAD_TAG_LEN + 16 + 2 + 64 + 2 + ML_DSA_65_SIG_LEN
        ),
        "expected SectionTruncated at aead_ct (need=fixed-suffix, got=0), got {err:?}"
    );
}
