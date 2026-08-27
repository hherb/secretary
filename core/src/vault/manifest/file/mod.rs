//! `ManifestFile` — the full §4.1 envelope (header + AEAD section + sig suffix).

mod sign;

pub use sign::{is_rollback, sign_manifest, verify_manifest};

use crate::crypto::aead::AEAD_TAG_LEN;
use crate::crypto::sig::{Ed25519Sig, MlDsa65Sig, SigError, ED25519_SIG_LEN, ML_DSA_65_SIG_LEN};
use crate::identity::fingerprint::Fingerprint;

use super::{ManifestError, ManifestHeader, MANIFEST_HEADER_LEN};

// ---------------------------------------------------------------------------
// ManifestFile — full §4.1 envelope (header + AEAD section + sig suffix)
// ---------------------------------------------------------------------------

const _: () = {
    // Spec-conformance assertion: §4.1 / §14 pin the Ed25519 signature
    // length at 64 bytes; the wire `sig_ed_len` field declares the same
    // value. Mirrors block.rs's compile-time guard.
    assert!(ED25519_SIG_LEN == 64);
};

const _: () = {
    // Spec-conformance assertion: §4.1 / §14 pin the ML-DSA-65 signature
    // length at 3309 bytes under suite v1 (`secretary-v1-pq-hybrid`).
    assert!(ML_DSA_65_SIG_LEN == 3309);
};

/// 16-byte fingerprint length: matches [`Fingerprint`]'s underlying
/// type alias. Pinned here so the §4.1 envelope size arithmetic is
/// self-evident at the call site.
const IDENTITY_FINGERPRINT_LEN: usize = 16;

/// The complete manifest file as it sits on disk: header (§4.1, 42
/// bytes) + AEAD section (24-byte nonce + 4-byte ct-len + variable ct
/// + 16-byte tag) + signature suffix (16-byte author fingerprint +
///   length-prefixed Ed25519 sig + length-prefixed ML-DSA-65 sig).
///
/// [`Manifest`] is the *opened* (decrypted) body that lives inside
/// `aead_ct`; `ManifestFile` is the on-disk envelope. They are
/// intentionally distinct types: a [`ManifestFile`] never holds
/// plaintext, and [`sign_manifest`] / [`verify_manifest`] +
/// [`decrypt_manifest_body`] are the only conversion paths between the
/// two. Same discipline as [`crate::vault::block::BlockFile`] vs
/// [`crate::vault::block::BlockPlaintext`].
///
/// [`Manifest`]: crate::vault::manifest::Manifest
/// [`decrypt_manifest_body`]: crate::vault::manifest::decrypt_manifest_body
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestFile {
    /// Binary header (§4.1, 42 bytes from `magic` through `last_mod_ms`).
    pub header: ManifestHeader,
    /// 24-byte XChaCha20 nonce for the body AEAD.
    pub aead_nonce: [u8; 24],
    /// AEAD ciphertext of the canonical-CBOR manifest body (§4.2),
    /// *without* the trailing 16-byte Poly1305 tag. The tag is held
    /// separately because §4.1 splits them on the wire (`aead_ct` is
    /// variable-length, `aead_tag` is a fixed 16-byte field).
    pub aead_ct: Vec<u8>,
    /// 16-byte Poly1305 authentication tag for the body AEAD.
    pub aead_tag: [u8; AEAD_TAG_LEN],
    /// 16-byte fingerprint of the manifest author's contact card
    /// (§4.1). For the single-user vault case this is the owner's
    /// fingerprint.
    pub author_fingerprint: Fingerprint,
    /// Ed25519 half of the §8 hybrid signature, 64 bytes.
    pub sig_ed: Ed25519Sig,
    /// ML-DSA-65 half of the §8 hybrid signature, 3309 bytes (suite v1).
    pub sig_pq: MlDsa65Sig,
}

/// Build the bytes the §4.1 hybrid signature commits to: header(42) ||
/// aead_nonce(24) || aead_ct_len(4 BE) || aead_ct(var) || aead_tag(16).
///
/// This is the bytes-from-`magic`-through-`aead_tag`-inclusive range.
/// The role-tag prefix `"secretary-v1-manifest-sig"` is added by
/// [`crate::crypto::sig::sign`] / [`crate::crypto::sig::verify`] via
/// [`SigRole::Manifest`] — DO NOT prepend it here, or both halves of
/// the hybrid signature would double-tag and round-trip verify would
/// break. Same discipline as [`crate::vault::block::signed_message_bytes`].
///
/// Takes the four signed-range fields directly (rather than a
/// `&ManifestFile`) so `sign_manifest` doesn't need to fabricate a
/// zero-filled placeholder `ManifestFile` to compute the pre-image. A
/// future refactor adding new fields to `ManifestFile` cannot
/// accidentally extend the signed range without updating this
/// function's signature — the compiler enforces the invariant.
fn signed_message_bytes(
    header: &ManifestHeader,
    aead_nonce: &[u8; 24],
    aead_ct: &[u8],
    aead_tag: &[u8; AEAD_TAG_LEN],
) -> Result<Vec<u8>, ManifestError> {
    let header_bytes = header.encode();
    let ct_len_u32 = u32::try_from(aead_ct.len()).map_err(|_| {
        // u32 overflow on aead_ct.len() is a degenerate case: a single
        // manifest body would have to exceed 4 GiB. Surface it as the
        // declared/remaining mismatch rather than inventing a fresh
        // variant — the resulting envelope would be unparseable anyway.
        ManifestError::AeadCtLenMismatch {
            declared: u32::MAX,
            remaining: aead_ct.len(),
        }
    })?;
    let mut out = Vec::with_capacity(MANIFEST_HEADER_LEN + 24 + 4 + aead_ct.len() + AEAD_TAG_LEN);
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(aead_nonce);
    out.extend_from_slice(&ct_len_u32.to_be_bytes());
    out.extend_from_slice(aead_ct);
    out.extend_from_slice(aead_tag);
    Ok(out)
}

/// Encode a complete [`ManifestFile`] to its §4.1 wire form: header
/// (42) || aead_nonce (24) || aead_ct_len (u32 BE = 4) || aead_ct
/// (var) || aead_tag (16) || author_fingerprint (16) || sig_ed_len
/// (u16 BE = 2) || sig_ed (64) || sig_pq_len (u16 BE = 2) || sig_pq
/// (3309 in suite v1).
///
/// Length-prefix fields (`aead_ct_len`, `sig_ed_len`, `sig_pq_len`)
/// are written from the corresponding field's actual length; encode-
/// time validation ensures the lengths fit their declared widths and
/// match the suite-v1 fixed sizes. A `sig_ed` whose alias has shifted
/// shape (defensive — the type is pinned `[u8; 64]`), or a `sig_pq`
/// whose suite version mismatches the wire format, surfaces as a
/// typed [`ManifestError::SigEdWrongLength`] /
/// [`ManifestError::SigPqWrongLength`] before any bytes are written.
pub fn encode_manifest_file(file: &ManifestFile) -> Result<Vec<u8>, ManifestError> {
    // Defensive length checks. `sig_ed: Ed25519Sig` is a `[u8; 64]`
    // alias so the first check cannot fire today, but pinning it here
    // matches the §4.1 wire contract and protects against a future
    // alias change. `sig_pq: MlDsa65Sig` is constructed via
    // `MlDsa65Sig::from_bytes` which already pins the length, so the
    // second check is also defensive. Both stay for symmetry with the
    // decode path's strict validation.
    if file.sig_ed.len() != ED25519_SIG_LEN {
        return Err(ManifestError::SigEdWrongLength {
            expected: ED25519_SIG_LEN as u16,
            got: file.sig_ed.len() as u16,
        });
    }
    if file.sig_pq.as_bytes().len() != ML_DSA_65_SIG_LEN {
        return Err(ManifestError::SigPqWrongLength {
            expected: ML_DSA_65_SIG_LEN as u16,
            got: file.sig_pq.as_bytes().len() as u16,
        });
    }
    let ct_len_u32 =
        u32::try_from(file.aead_ct.len()).map_err(|_| ManifestError::AeadCtLenMismatch {
            declared: u32::MAX,
            remaining: file.aead_ct.len(),
        })?;

    let header_bytes = file.header.encode();
    let sig_pq_bytes = file.sig_pq.as_bytes();
    let total = MANIFEST_HEADER_LEN
        + 24
        + 4
        + file.aead_ct.len()
        + AEAD_TAG_LEN
        + IDENTITY_FINGERPRINT_LEN
        + 2
        + ED25519_SIG_LEN
        + 2
        + sig_pq_bytes.len();
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&file.aead_nonce);
    out.extend_from_slice(&ct_len_u32.to_be_bytes());
    out.extend_from_slice(&file.aead_ct);
    out.extend_from_slice(&file.aead_tag);
    out.extend_from_slice(&file.author_fingerprint);
    out.extend_from_slice(&(ED25519_SIG_LEN as u16).to_be_bytes());
    out.extend_from_slice(&file.sig_ed);
    out.extend_from_slice(&(sig_pq_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(sig_pq_bytes);
    debug_assert_eq!(out.len(), total);
    Ok(out)
}

/// Decode a complete [`ManifestFile`] from `bytes`. Strict on lengths:
/// every section has a typed truncation diagnostic that pinpoints
/// which §4.1 field is short. Trailing bytes after `sig_pq` are
/// rejected with [`ManifestError::TrailingBytes`].
///
/// Validates:
///
/// 1. Header (42 bytes) via [`ManifestHeader::decode`] — magic,
///    format_version, suite_id, file_kind.
/// 2. Sufficient input for `aead_nonce` (24), `aead_ct_len` (4),
///    `aead_ct` (declared), `aead_tag` (16), `author_fingerprint` (16),
///    `sig_ed_len` (2), `sig_ed` (64), `sig_pq_len` (2), and `sig_pq`
///    (3309 in suite v1) — each surfaces as
///    [`ManifestError::SectionTruncated`] with a section-specific name.
/// 3. `aead_ct_len` matches the bytes available between the length
///    prefix and the trailing signature suffix (after subtracting the
///    fixed 16-byte AEAD tag and the trailing fixed-size suffix);
///    surfaces as [`ManifestError::AeadCtLenMismatch`] when the wire
///    declares a length the envelope cannot satisfy.
/// 4. `sig_ed_len == 64` and `sig_pq_len == 3309` —
///    [`ManifestError::SigEdWrongLength`] / [`ManifestError::SigPqWrongLength`].
/// 5. No bytes remain after `sig_pq` —
///    [`ManifestError::TrailingBytes`].
///
/// Does NOT decrypt the AEAD body and does NOT verify the hybrid
/// signature. Those are separate concerns: an orchestrator sequences
/// `decode_manifest_file` → `verify_manifest` → `decrypt_manifest_body`.
pub fn decode_manifest_file(bytes: &[u8]) -> Result<ManifestFile, ManifestError> {
    // Step 1: header (42 bytes). Returns the trailing slice for the
    // AEAD section to pick up from.
    let (header, rest) = ManifestHeader::decode(bytes)?;

    let mut pos = 0usize;

    // Step 2: aead_nonce (24).
    if rest.len().saturating_sub(pos) < 24 {
        return Err(ManifestError::SectionTruncated {
            section: "aead_nonce",
            need: 24,
            got: rest.len().saturating_sub(pos),
        });
    }
    // `try_into` avoids the `let mut nonce = [0u8; 24]; copy_from_slice(...)`
    // pattern that CodeQL's `rust/hard-coded-cryptographic-value` rule
    // pattern-matches as a suspected hardcoded nonce literal.
    let aead_nonce: [u8; 24] = rest[pos..pos + 24]
        .try_into()
        .expect("bounds check above guarantees 24 bytes");
    pos += 24;

    // Step 3: aead_ct_len (u32 BE).
    if rest.len().saturating_sub(pos) < 4 {
        return Err(ManifestError::SectionTruncated {
            section: "aead_ct_len",
            need: 4,
            got: rest.len().saturating_sub(pos),
        });
    }
    let mut len_buf = [0u8; 4];
    len_buf.copy_from_slice(&rest[pos..pos + 4]);
    pos += 4;
    let declared_ct_len = u32::from_be_bytes(len_buf);
    let declared_ct_len_usize = declared_ct_len as usize;

    // Step 4: We must reserve room for aead_tag(16), author_fingerprint(16),
    // sig_ed_len(2), sig_ed(64), sig_pq_len(2), sig_pq(ML_DSA_65_SIG_LEN=3309).
    // The "remaining" expected after the ct_len prefix is:
    //   declared_ct_len + 16 (tag) + 16 (fp) + 2 (sig_ed_len) + 64 (sig_ed)
    //                  + 2 (sig_pq_len) + 3309 (sig_pq)
    // If the declared aead_ct_len asks for more bytes than are present
    // (after subtracting the fixed-size suffix), surface the typed
    // mismatch rather than waiting for a downstream truncation.
    let fixed_suffix_after_ct =
        AEAD_TAG_LEN + IDENTITY_FINGERPRINT_LEN + 2 + ED25519_SIG_LEN + 2 + ML_DSA_65_SIG_LEN;
    let remaining_after_len_prefix = rest.len().saturating_sub(pos);
    if remaining_after_len_prefix < fixed_suffix_after_ct {
        // We don't even have enough bytes for the fixed-size tail; report
        // truncation at the aead_ct boundary because that's the first
        // section to overflow available bytes.
        return Err(ManifestError::SectionTruncated {
            section: "aead_ct",
            need: declared_ct_len_usize + fixed_suffix_after_ct,
            got: remaining_after_len_prefix,
        });
    }
    let max_possible_ct_len = remaining_after_len_prefix - fixed_suffix_after_ct;
    if declared_ct_len_usize > max_possible_ct_len {
        return Err(ManifestError::AeadCtLenMismatch {
            declared: declared_ct_len,
            remaining: max_possible_ct_len,
        });
    }

    // Step 5: aead_ct (declared length).
    let aead_ct = rest[pos..pos + declared_ct_len_usize].to_vec();
    pos += declared_ct_len_usize;

    // Step 6: aead_tag (16). Length already reserved above.
    let mut aead_tag = [0u8; AEAD_TAG_LEN];
    aead_tag.copy_from_slice(&rest[pos..pos + AEAD_TAG_LEN]);
    pos += AEAD_TAG_LEN;

    // Step 7: author_fingerprint (16).
    let mut author_fingerprint = [0u8; IDENTITY_FINGERPRINT_LEN];
    author_fingerprint.copy_from_slice(&rest[pos..pos + IDENTITY_FINGERPRINT_LEN]);
    pos += IDENTITY_FINGERPRINT_LEN;

    // Step 8: sig_ed_len (u16 BE).
    let mut sig_ed_len_buf = [0u8; 2];
    sig_ed_len_buf.copy_from_slice(&rest[pos..pos + 2]);
    pos += 2;
    let sig_ed_len = u16::from_be_bytes(sig_ed_len_buf);
    if sig_ed_len as usize != ED25519_SIG_LEN {
        return Err(ManifestError::SigEdWrongLength {
            expected: ED25519_SIG_LEN as u16,
            got: sig_ed_len,
        });
    }

    // Step 9: sig_ed (64). Length already reserved above.
    let mut sig_ed: Ed25519Sig = [0u8; ED25519_SIG_LEN];
    sig_ed.copy_from_slice(&rest[pos..pos + ED25519_SIG_LEN]);
    pos += ED25519_SIG_LEN;

    // Step 10: sig_pq_len (u16 BE).
    let mut sig_pq_len_buf = [0u8; 2];
    sig_pq_len_buf.copy_from_slice(&rest[pos..pos + 2]);
    pos += 2;
    let sig_pq_len = u16::from_be_bytes(sig_pq_len_buf);
    if sig_pq_len as usize != ML_DSA_65_SIG_LEN {
        return Err(ManifestError::SigPqWrongLength {
            expected: ML_DSA_65_SIG_LEN as u16,
            got: sig_pq_len,
        });
    }

    // Step 11: sig_pq. Length already reserved.
    let sig_pq_bytes = rest[pos..pos + ML_DSA_65_SIG_LEN].to_vec();
    pos += ML_DSA_65_SIG_LEN;

    // MlDsa65Sig::from_bytes hard-pins length at ML_DSA_65_SIG_LEN; the
    // wire-format check above makes this defensive (cannot fire today)
    // but it stays as the construction path for the typed wrapper.
    let sig_pq = MlDsa65Sig::from_bytes(&sig_pq_bytes).map_err(|e| match e {
        SigError::InvalidSignatureLength => ManifestError::SigPqWrongLength {
            expected: ML_DSA_65_SIG_LEN as u16,
            got: sig_pq_bytes.len() as u16,
        },
        // Other SigError variants do not fire on this path; lift
        // defensively into the closest equivalent.
        other => ManifestError::SignInternal(other),
    })?;

    // Step 12: trailing-bytes check.
    if pos != rest.len() {
        return Err(ManifestError::TrailingBytes(rest.len() - pos));
    }

    Ok(ManifestFile {
        header,
        aead_nonce,
        aead_ct,
        aead_tag,
        author_fingerprint,
        sig_ed,
        sig_pq,
    })
}
