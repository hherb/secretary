//! Manifest binary header (`docs/vault-format.md` §4.1) + AEAD body wiring.

use crate::crypto::aead::{self, AeadKey, AeadNonce};
use crate::crypto::secret::SecretBytes;
use crate::version::{FILE_KIND_MANIFEST, FORMAT_VERSION, MAGIC, SUITE_ID};

use super::decode::decode_manifest;
use super::{Manifest, ManifestError, UUID_LEN};

// ---------------------------------------------------------------------------
// Binary header (§4.1) + AEAD body wiring
// ---------------------------------------------------------------------------

/// Wire-form byte length of the manifest binary header (`docs/vault-format.md`
/// §4.1): `magic`(4) + `format_version`(2) + `suite_id`(2) + `file_kind`(2)
/// + `vault_uuid`(16) + `created_at_ms`(8) + `last_mod_ms`(8) = 42 bytes.
///
/// These 42 bytes are bound into the AEAD as Additional Authenticated Data
/// — the §4.1 cross-file-kind anti-substitution property — so any bit-flip
/// inside the header invalidates the Poly1305 tag on decrypt.
pub const MANIFEST_HEADER_LEN: usize = 4 + 2 + 2 + 2 + 16 + 8 + 8;

const _: () = {
    // Spec-conformance assertion: §4.1 fixes the manifest header at 42
    // bytes from `magic` through `last_mod_ms` inclusive. Any future
    // re-shuffle of constituent field widths must also update §4.1 of
    // the spec; this compile-time check makes the contract explicit.
    assert!(MANIFEST_HEADER_LEN == 42);
};

/// Manifest binary header (`docs/vault-format.md` §4.1).
///
/// The 42-byte prefix that sits in front of the AEAD nonce + ciphertext.
/// `magic`, `format_version`, `suite_id`, and `file_kind` are constants
/// pinned by the v1 cipher suite — callers don't pass them; [`encode`](Self::encode)
/// emits them and [`decode`](Self::decode) verifies them. Bound into the
/// AEAD as AAD so a tampered header invalidates the tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestHeader {
    pub vault_uuid: [u8; UUID_LEN],
    pub created_at_ms: u64,
    pub last_mod_ms: u64,
}

impl ManifestHeader {
    /// Encode the 42-byte header. Constant fields (magic, format_version,
    /// suite_id, file_kind) are emitted from [`crate::version`] sentinels
    /// — callers don't get to override them.
    ///
    /// Returns a fixed-size array rather than a `Vec` so the AEAD AAD
    /// length is statically obvious at the call site (and so the result
    /// can be passed directly as a `&[u8]` slice).
    pub fn encode(&self) -> [u8; MANIFEST_HEADER_LEN] {
        let mut out = [0u8; MANIFEST_HEADER_LEN];
        let mut pos = 0;
        out[pos..pos + 4].copy_from_slice(&MAGIC.to_be_bytes());
        pos += 4;
        out[pos..pos + 2].copy_from_slice(&FORMAT_VERSION.to_be_bytes());
        pos += 2;
        out[pos..pos + 2].copy_from_slice(&SUITE_ID.to_be_bytes());
        pos += 2;
        out[pos..pos + 2].copy_from_slice(&FILE_KIND_MANIFEST.to_be_bytes());
        pos += 2;
        out[pos..pos + UUID_LEN].copy_from_slice(&self.vault_uuid);
        pos += UUID_LEN;
        out[pos..pos + 8].copy_from_slice(&self.created_at_ms.to_be_bytes());
        pos += 8;
        out[pos..pos + 8].copy_from_slice(&self.last_mod_ms.to_be_bytes());
        pos += 8;
        debug_assert_eq!(pos, MANIFEST_HEADER_LEN);
        out
    }

    /// Decode the 42-byte header. Returns the parsed [`ManifestHeader`]
    /// alongside the trailing byte slice (so a caller mid-parse of the
    /// surrounding §4.1 envelope — which Task 7's `ManifestFile` will be —
    /// can keep parsing the AEAD section).
    ///
    /// Validates:
    ///
    /// 1. Sufficient input length ([`ManifestError::HeaderTruncated`]).
    /// 2. `magic == MAGIC` ([`ManifestError::BadMagic`]).
    /// 3. `format_version == FORMAT_VERSION`
    ///    ([`ManifestError::UnsupportedFormatVersion`]).
    /// 4. `suite_id == SUITE_ID` ([`ManifestError::UnsupportedSuiteId`]).
    /// 5. `file_kind == FILE_KIND_MANIFEST`
    ///    ([`ManifestError::UnsupportedFileKind`]) — the §4.1
    ///    cross-file-kind protection.
    ///
    /// `created_at_ms` and `last_mod_ms` are read verbatim — temporal
    /// invariants (e.g. `created_at_ms <= last_mod_ms`) are not policed
    /// at this layer; the manifest body and orchestrator layers handle
    /// rollback and freshness checks (Task 8 onward).
    pub fn decode(bytes: &[u8]) -> Result<(ManifestHeader, &[u8]), ManifestError> {
        if bytes.len() < MANIFEST_HEADER_LEN {
            return Err(ManifestError::HeaderTruncated {
                need: MANIFEST_HEADER_LEN,
                got: bytes.len(),
            });
        }
        let mut pos = 0;

        let magic = u32::from_be_bytes(slice_array::<4>(bytes, &mut pos));
        if magic != MAGIC {
            return Err(ManifestError::BadMagic {
                expected: MAGIC,
                got: magic,
            });
        }
        let format_version = u16::from_be_bytes(slice_array::<2>(bytes, &mut pos));
        if format_version != FORMAT_VERSION {
            return Err(ManifestError::UnsupportedFormatVersion(format_version));
        }
        let suite_id = u16::from_be_bytes(slice_array::<2>(bytes, &mut pos));
        if suite_id != SUITE_ID {
            return Err(ManifestError::UnsupportedSuiteId(suite_id));
        }
        let file_kind = u16::from_be_bytes(slice_array::<2>(bytes, &mut pos));
        if file_kind != FILE_KIND_MANIFEST {
            return Err(ManifestError::UnsupportedFileKind {
                expected: FILE_KIND_MANIFEST,
                got: file_kind,
            });
        }
        let vault_uuid = slice_array::<UUID_LEN>(bytes, &mut pos);
        let created_at_ms = u64::from_be_bytes(slice_array::<8>(bytes, &mut pos));
        let last_mod_ms = u64::from_be_bytes(slice_array::<8>(bytes, &mut pos));
        debug_assert_eq!(pos, MANIFEST_HEADER_LEN);

        Ok((
            ManifestHeader {
                vault_uuid,
                created_at_ms,
                last_mod_ms,
            },
            &bytes[MANIFEST_HEADER_LEN..],
        ))
    }
}

/// Read a fixed-size byte chunk out of `bytes`, advancing `pos`. The
/// caller has already length-checked the input, so this helper takes
/// ownership of that invariant — a panic here is a bug in the caller.
/// Mirrors block.rs's `read_array` style minus the truncation check
/// (we hoist it once at the top of [`ManifestHeader::decode`] since the
/// header is a fixed 42 bytes, not variable-length like a block header).
fn slice_array<const N: usize>(bytes: &[u8], pos: &mut usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[*pos..*pos + N]);
    *pos += N;
    out
}

/// AEAD-encrypt a canonical-CBOR-encoded manifest body under `ibk` with
/// `nonce`, binding `header.encode()` into the AAD per §4.1.
///
/// Returns `aead_ct || aead_tag` — the concatenation that the §4.1
/// envelope places between `aead_nonce` and the (Task 7) signature
/// suffix. The tag length is [`crate::crypto::aead::AEAD_TAG_LEN`] (16
/// bytes); the ciphertext length matches `manifest_bytes.len()`.
///
/// `manifest_bytes` is the output of [`encode_manifest`]; callers that
/// haven't encoded yet should pipe through that function first. We don't
/// take a `&Manifest` directly because callers occasionally already have
/// the canonical bytes in hand (e.g. cached on a previous read) — those
/// bytes now arrive wrapped: `manifest_bytes` is `&SecretBytes`, matching
/// [`encode_manifest`]'s return type, so the seventh `aead::encrypt` call
/// site (#558, #565) is pinned by the parameter type rather than by a
/// deletable wrap at each caller.
///
/// [`encode_manifest`]: crate::vault::manifest::encode_manifest
pub fn encrypt_manifest_body(
    header: &ManifestHeader,
    manifest_bytes: &SecretBytes,
    ibk: &AeadKey,
    nonce: &AeadNonce,
) -> Result<Vec<u8>, ManifestError> {
    let aad = header.encode();
    aead::encrypt(ibk, nonce, &aad, manifest_bytes.expose()).map_err(|_| ManifestError::AeadFailure)
}

/// AEAD-decrypt a manifest body. `ct_with_tag` is the concatenation of
/// `aead_ct` (length declared upstream by the §4.1 envelope's
/// `aead_ct_len` field — Task 7 territory) and `aead_tag`. AAD is
/// `header.encode()`.
///
/// On AEAD success, parses the recovered plaintext via [`decode_manifest`]
/// and returns the [`Manifest`]. AEAD failure (wrong key, wrong nonce,
/// tampered header, tampered ciphertext) collapses to a single
/// [`ManifestError::AeadFailure`] per the AEAD security model
/// — distinguishing causes would leak information to a probing attacker.
pub fn decrypt_manifest_body(
    header: &ManifestHeader,
    ct_with_tag: &[u8],
    ibk: &AeadKey,
    nonce: &AeadNonce,
) -> Result<Manifest, ManifestError> {
    let aad = header.encode();
    let plaintext =
        aead::decrypt(ibk, nonce, &aad, ct_with_tag).map_err(|_| ManifestError::AeadFailure)?;
    decode_manifest(plaintext.expose())
}

#[cfg(test)]
mod tests;
