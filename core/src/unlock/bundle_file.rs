//! `identity.bundle.enc` binary envelope (`docs/vault-format.md` §3).
//!
//! Big-endian integers throughout. Three AEAD payloads (wrap_pw, wrap_rec,
//! bundle). The wrap fields are stored as `nonce || ct_len(=32) || ct || tag`.
//! The bundle field is stored as `nonce || bundle_ct_len || bundle_ct || bundle_tag`
//! where `bundle_ct_len` is the length of `bundle_ct` ALONE, per §3 lines 102-104.
//! Internally we keep `bundle_ct_with_tag = bundle_ct || bundle_tag` (matching
//! `crypto::aead::encrypt`'s combined output); the 16-byte tag is written as the
//! separate `bundle_tag` §3 field and is NOT included in `bundle_ct_len`.

use crate::version::{FORMAT_VERSION, MAGIC};

/// File-kind identifier for the identity bundle envelope. Distinct from
/// FORMAT_VERSION — file kinds let multiple files (manifest, block, …) share
/// the same FORMAT_VERSION while remaining distinguishable.
pub(crate) const FILE_KIND_IDENTITY_BUNDLE: u16 = 0x0001;
pub(crate) const NONCE_LEN: usize = 24;
pub(crate) const WRAP_CT_PLUS_TAG_LEN: usize = 32 + 16;  // identity_block_key + tag

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleFile {
    pub vault_uuid: [u8; 16],
    pub created_at_ms: u64,
    pub wrap_pw_nonce: [u8; NONCE_LEN],
    pub wrap_pw_ct_with_tag: [u8; WRAP_CT_PLUS_TAG_LEN],
    pub wrap_rec_nonce: [u8; NONCE_LEN],
    pub wrap_rec_ct_with_tag: [u8; WRAP_CT_PLUS_TAG_LEN],
    pub bundle_nonce: [u8; NONCE_LEN],
    pub bundle_ct_with_tag: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum BundleFileError {
    #[error("file truncated at offset {offset}")]
    Truncated { offset: usize },
    #[error("trailing bytes after parse at offset {offset}")]
    TrailingBytes { offset: usize },
    #[error("bad magic: expected SECR, got {got:#010x}")]
    BadMagic { got: u32 },
    #[error("unsupported format version: {0}")]
    UnsupportedFormatVersion(u16),
    #[error("unsupported file kind: {0}")]
    UnsupportedFileKind(u16),
    /// A wrap length-prefix did not match the expected size.
    #[error("declared length for {field}: expected {expected}, got {declared}")]
    WrapLengthMismatch {
        field: &'static str,
        expected: u32,
        declared: u32,
    },
}

/// Serialize a [`BundleFile`] to its `vault-format.md` §3 byte form.
///
/// # Panics
///
/// Panics if `file.bundle_ct_with_tag.len() < 16` (a Poly1305 tag is always
/// 16 bytes; a shorter buffer is structurally invalid). Callers should be
/// constructing this from `crypto::aead::encrypt` output, which always
/// includes the tag.
pub fn encode(file: &BundleFile) -> Vec<u8> {
    debug_assert!(
        file.bundle_ct_with_tag.len() >= 16,
        "bundle_ct_with_tag must include the trailing 16-byte Poly1305 tag"
    );
    let mut out = Vec::with_capacity(
        4 + 2 + 2 + 16 + 8
            + NONCE_LEN + 4 + WRAP_CT_PLUS_TAG_LEN
            + NONCE_LEN + 4 + WRAP_CT_PLUS_TAG_LEN
            + NONCE_LEN + 4 + file.bundle_ct_with_tag.len()
    );
    out.extend_from_slice(&MAGIC.to_be_bytes());
    out.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    out.extend_from_slice(&FILE_KIND_IDENTITY_BUNDLE.to_be_bytes());
    out.extend_from_slice(&file.vault_uuid);
    out.extend_from_slice(&file.created_at_ms.to_be_bytes());

    out.extend_from_slice(&file.wrap_pw_nonce);
    // wrap_pw_ct_len: u32 = 32 (the IdentityBlockKey size). Writing the
    // unwrapped key length, NOT the ciphertext-with-tag length, per §3.
    out.extend_from_slice(&32u32.to_be_bytes());
    out.extend_from_slice(&file.wrap_pw_ct_with_tag);

    out.extend_from_slice(&file.wrap_rec_nonce);
    out.extend_from_slice(&32u32.to_be_bytes());
    out.extend_from_slice(&file.wrap_rec_ct_with_tag);

    out.extend_from_slice(&file.bundle_nonce);
    // bundle_ct_len = length of bundle_ct ALONE, per vault-format §3 lines 102-104.
    // bundle_ct_with_tag stores ct||tag (matching crypto::aead::encrypt's output);
    // the trailing 16 bytes are bundle_tag (a separate §3 field). We write both
    // in a single extend_from_slice — the wire layout is bundle_ct then bundle_tag,
    // which is exactly what bundle_ct_with_tag contains in order.
    let bundle_ct_len = u32::try_from(file.bundle_ct_with_tag.len() - 16)
        .expect("bundle ct < 4 GiB");
    out.extend_from_slice(&bundle_ct_len.to_be_bytes());
    out.extend_from_slice(&file.bundle_ct_with_tag);

    out
}

pub fn decode(bytes: &[u8]) -> Result<BundleFile, BundleFileError> {
    let mut pos = 0;
    let magic = read_u32_be(bytes, &mut pos)?;
    if magic != MAGIC {
        return Err(BundleFileError::BadMagic { got: magic });
    }
    let format_version = read_u16_be(bytes, &mut pos)?;
    if format_version != FORMAT_VERSION {
        return Err(BundleFileError::UnsupportedFormatVersion(format_version));
    }
    let file_kind = read_u16_be(bytes, &mut pos)?;
    if file_kind != FILE_KIND_IDENTITY_BUNDLE {
        return Err(BundleFileError::UnsupportedFileKind(file_kind));
    }
    let vault_uuid = read_array::<16>(bytes, &mut pos)?;
    let created_at_ms = read_u64_be(bytes, &mut pos)?;

    // wrap_pw
    let wrap_pw_nonce = read_array::<NONCE_LEN>(bytes, &mut pos)?;
    let wrap_pw_ct_len = read_u32_be(bytes, &mut pos)?;
    if wrap_pw_ct_len != 32 {
        return Err(BundleFileError::WrapLengthMismatch {
            field: "wrap_pw",
            expected: 32,
            declared: wrap_pw_ct_len,
        });
    }
    let wrap_pw_ct_with_tag = read_array::<WRAP_CT_PLUS_TAG_LEN>(bytes, &mut pos)?;

    // wrap_rec
    let wrap_rec_nonce = read_array::<NONCE_LEN>(bytes, &mut pos)?;
    let wrap_rec_ct_len = read_u32_be(bytes, &mut pos)?;
    if wrap_rec_ct_len != 32 {
        return Err(BundleFileError::WrapLengthMismatch {
            field: "wrap_rec",
            expected: 32,
            declared: wrap_rec_ct_len,
        });
    }
    let wrap_rec_ct_with_tag = read_array::<WRAP_CT_PLUS_TAG_LEN>(bytes, &mut pos)?;

    // bundle
    let bundle_nonce = read_array::<NONCE_LEN>(bytes, &mut pos)?;
    let bundle_ct_len = read_u32_be(bytes, &mut pos)? as usize;
    // §3: bundle_tag is a separate 16-byte field after bundle_ct.
    // We read both into a single combined buffer to match crypto::aead::decrypt's
    // expected ct||tag input shape.
    let total = bundle_ct_len
        .checked_add(16)
        .ok_or(BundleFileError::Truncated { offset: pos })?;
    if pos + total > bytes.len() {
        return Err(BundleFileError::Truncated { offset: pos });
    }
    let bundle_ct_with_tag = bytes[pos..pos + total].to_vec();
    pos += total;

    if pos != bytes.len() {
        return Err(BundleFileError::TrailingBytes { offset: pos });
    }

    Ok(BundleFile {
        vault_uuid,
        created_at_ms,
        wrap_pw_nonce,
        wrap_pw_ct_with_tag,
        wrap_rec_nonce,
        wrap_rec_ct_with_tag,
        bundle_nonce,
        bundle_ct_with_tag,
    })
}

fn read_u16_be(bytes: &[u8], pos: &mut usize) -> Result<u16, BundleFileError> {
    let arr = read_array::<2>(bytes, pos)?;
    Ok(u16::from_be_bytes(arr))
}
fn read_u32_be(bytes: &[u8], pos: &mut usize) -> Result<u32, BundleFileError> {
    let arr = read_array::<4>(bytes, pos)?;
    Ok(u32::from_be_bytes(arr))
}
fn read_u64_be(bytes: &[u8], pos: &mut usize) -> Result<u64, BundleFileError> {
    let arr = read_array::<8>(bytes, pos)?;
    Ok(u64::from_be_bytes(arr))
}
fn read_array<const N: usize>(bytes: &[u8], pos: &mut usize) -> Result<[u8; N], BundleFileError> {
    if *pos + N > bytes.len() {
        return Err(BundleFileError::Truncated { offset: *pos });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[*pos..*pos + N]);
    *pos += N;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> BundleFile {
        BundleFile {
            vault_uuid: [0x11; 16],
            created_at_ms: 1_714_060_800_000,
            wrap_pw_nonce: [0x22; NONCE_LEN],
            wrap_pw_ct_with_tag: [0x33; WRAP_CT_PLUS_TAG_LEN],
            wrap_rec_nonce: [0x44; NONCE_LEN],
            wrap_rec_ct_with_tag: [0x55; WRAP_CT_PLUS_TAG_LEN],
            bundle_nonce: [0x66; NONCE_LEN],
            bundle_ct_with_tag: vec![0x77; 200],
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let f = sample();
        let bytes = encode(&f);
        let parsed = decode(&bytes).expect("decode");
        assert_eq!(parsed, f);
    }

    #[test]
    fn encode_decode_roundtrip_minimum_bundle_ct() {
        // Smallest valid bundle_ct_with_tag is exactly 16 bytes (the tag with
        // empty plaintext ciphertext) — boundary case for the encode subtraction.
        let mut f = sample();
        f.bundle_ct_with_tag = vec![0xAB; 16];
        let bytes = encode(&f);
        let parsed = decode(&bytes).expect("decode");
        assert_eq!(parsed, f);
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let mut bytes = encode(&sample());
        bytes[0] ^= 0xFF;
        let err = decode(&bytes).unwrap_err();
        assert!(matches!(err, BundleFileError::BadMagic { .. }));
    }

    #[test]
    fn decode_rejects_bad_format_version() {
        let mut bytes = encode(&sample());
        bytes[5] = 0x02;  // bump format_version low byte from 0x01 to 0x02
        let err = decode(&bytes).unwrap_err();
        assert!(matches!(err, BundleFileError::UnsupportedFormatVersion(2)));
    }

    #[test]
    fn decode_rejects_bad_file_kind() {
        let mut bytes = encode(&sample());
        bytes[7] = 0x02;
        let err = decode(&bytes).unwrap_err();
        assert!(matches!(err, BundleFileError::UnsupportedFileKind(2)));
    }

    #[test]
    fn decode_rejects_truncated_at_every_boundary() {
        let bytes = encode(&sample());
        for n in 0..bytes.len() {
            let truncated = &bytes[..n];
            let result = decode(truncated);
            assert!(
                result.is_err(),
                "decode must fail on slice [..{n}] of {} bytes",
                bytes.len()
            );
        }
        decode(&bytes).expect("full bytes decode");
    }

    #[test]
    fn decode_rejects_wrap_pw_length_mismatch() {
        let bytes = encode(&sample());
        // header(magic+ver+kind+uuid+ts) + wrap_pw_nonce
        let wrap_pw_ct_len_offset = 4 + 2 + 2 + 16 + 8 + NONCE_LEN;
        assert_eq!(wrap_pw_ct_len_offset, 56);
        let mut tampered = bytes.clone();
        tampered[wrap_pw_ct_len_offset..wrap_pw_ct_len_offset + 4]
            .copy_from_slice(&64u32.to_be_bytes());
        let err = decode(&tampered).unwrap_err();
        assert!(matches!(
            err,
            BundleFileError::WrapLengthMismatch { field: "wrap_pw", expected: 32, declared: 64 }
        ));
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut bytes = encode(&sample());
        bytes.push(0xAA);
        let err = decode(&bytes).unwrap_err();
        assert!(matches!(err, BundleFileError::TrailingBytes { .. }));
    }

    #[test]
    fn decode_rejects_wrap_rec_length_mismatch() {
        let bytes = encode(&sample());
        // header + wrap_pw_section(nonce+len+ct_with_tag) + wrap_rec_nonce
        let wrap_rec_ct_len_offset =
            4 + 2 + 2 + 16 + 8 + (NONCE_LEN + 4 + WRAP_CT_PLUS_TAG_LEN) + NONCE_LEN;
        assert_eq!(wrap_rec_ct_len_offset, 132);
        let mut tampered = bytes.clone();
        tampered[wrap_rec_ct_len_offset..wrap_rec_ct_len_offset + 4]
            .copy_from_slice(&64u32.to_be_bytes());
        let err = decode(&tampered).unwrap_err();
        assert!(matches!(
            err,
            BundleFileError::WrapLengthMismatch { field: "wrap_rec", expected: 32, declared: 64 }
        ));
    }
}
