//! `identity.bundle.enc` binary envelope (`docs/vault-format.md` §3).
//!
//! Big-endian integers throughout. Three AEAD payloads (wrap_pw, wrap_rec,
//! bundle), each stored as `nonce || ct_len || ct_with_tag`, where
//! ct_with_tag is the AEAD ciphertext concatenated with its 16-byte
//! Poly1305 tag (matching `crypto::aead::encrypt`'s output format).

pub const MAGIC: u32 = 0x53454352;             // "SECR"
pub const FORMAT_VERSION_V1: u16 = 0x0001;
pub const FILE_KIND_IDENTITY_BUNDLE: u16 = 0x0001;
pub const NONCE_LEN: usize = 24;
pub const WRAP_CT_PLUS_TAG_LEN: usize = 32 + 16;  // identity_block_key + tag

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
    #[error("bad magic: expected SECR, got {got:#010x}")]
    BadMagic { got: u32 },
    #[error("unsupported format version: {0}")]
    UnsupportedFormatVersion(u16),
    #[error("unsupported file kind: {0}")]
    UnsupportedFileKind(u16),
    #[error("declared length for {field} ({declared}) does not match expected (32)")]
    WrapLengthMismatch { field: &'static str, declared: u32 },
}

pub fn encode(file: &BundleFile) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        4 + 2 + 2 + 16 + 8
            + NONCE_LEN + 4 + WRAP_CT_PLUS_TAG_LEN
            + NONCE_LEN + 4 + WRAP_CT_PLUS_TAG_LEN
            + NONCE_LEN + 4 + file.bundle_ct_with_tag.len()
    );
    out.extend_from_slice(&MAGIC.to_be_bytes());
    out.extend_from_slice(&FORMAT_VERSION_V1.to_be_bytes());
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
    // bundle_ct_len = length of the AEAD ciphertext including the 16-byte
    // tag (the §3 "bundle_ct" field is the AEAD output as a single blob).
    out.extend_from_slice(&u32::try_from(file.bundle_ct_with_tag.len())
        .expect("bundle ct < 4 GiB").to_be_bytes());
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
    if format_version != FORMAT_VERSION_V1 {
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
        return Err(BundleFileError::WrapLengthMismatch { field: "wrap_pw", declared: wrap_pw_ct_len });
    }
    let wrap_pw_ct_with_tag = read_array::<WRAP_CT_PLUS_TAG_LEN>(bytes, &mut pos)?;

    // wrap_rec
    let wrap_rec_nonce = read_array::<NONCE_LEN>(bytes, &mut pos)?;
    let wrap_rec_ct_len = read_u32_be(bytes, &mut pos)?;
    if wrap_rec_ct_len != 32 {
        return Err(BundleFileError::WrapLengthMismatch { field: "wrap_rec", declared: wrap_rec_ct_len });
    }
    let wrap_rec_ct_with_tag = read_array::<WRAP_CT_PLUS_TAG_LEN>(bytes, &mut pos)?;

    // bundle
    let bundle_nonce = read_array::<NONCE_LEN>(bytes, &mut pos)?;
    let bundle_ct_len = read_u32_be(bytes, &mut pos)? as usize;
    if pos + bundle_ct_len > bytes.len() {
        return Err(BundleFileError::Truncated { offset: pos });
    }
    let bundle_ct_with_tag = bytes[pos..pos + bundle_ct_len].to_vec();
    pos += bundle_ct_len;

    if pos != bytes.len() {
        return Err(BundleFileError::Truncated { offset: pos });
        // Trailing bytes treated as truncation indicator — file is wrong shape.
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
        // wrap_pw_ct_len starts at offset 4+2+2+16+8 + NONCE_LEN = 32 + 24 = 56
        let mut tampered = bytes.clone();
        tampered[56..60].copy_from_slice(&64u32.to_be_bytes());
        let err = decode(&tampered).unwrap_err();
        assert!(matches!(
            err,
            BundleFileError::WrapLengthMismatch { field: "wrap_pw", declared: 64 }
        ));
    }
}
