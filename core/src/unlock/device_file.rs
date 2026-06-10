//! `devices/<device-uuid>.wrap` binary envelope (`docs/vault-format.md` §3a).
//!
//! Big-endian throughout. One AEAD payload (`wrap_dev`), stored as
//! `nonce || ct_len(=32) || ct || tag`. Sibling of `bundle_file.rs`; the
//! header shares the `MAGIC || format_version || file_kind || vault_uuid`
//! prefix and then diverges (a `device_uuid` replaces §3's `created_at_ms`).

use crate::version::{FORMAT_VERSION, MAGIC};

/// File-kind identifier for a per-device wrap file (§3a). Distinct from
/// identity-bundle (0x0001), manifest (0x0002), block (0x0003).
pub(crate) const FILE_KIND_DEVICE_WRAP: u16 = 0x0004;
pub(crate) const NONCE_LEN: usize = 24;
pub(crate) const WRAP_CT_PLUS_TAG_LEN: usize = 32 + 16; // identity_block_key + tag

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceWrapFile {
    pub vault_uuid: [u8; 16],
    pub device_uuid: [u8; 16],
    pub wrap_dev_nonce: [u8; NONCE_LEN],
    pub wrap_dev_ct_with_tag: [u8; WRAP_CT_PLUS_TAG_LEN],
}

#[derive(Debug, thiserror::Error)]
pub enum DeviceFileError {
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
    #[error("declared length for wrap_dev: expected 32, got {declared}")]
    WrapLengthMismatch { declared: u32 },
}

/// Serialize a [`DeviceWrapFile`] to its §3a byte form.
pub fn encode(file: &DeviceWrapFile) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 2 + 2 + 16 + 16 + NONCE_LEN + 4 + WRAP_CT_PLUS_TAG_LEN);
    out.extend_from_slice(&MAGIC.to_be_bytes());
    out.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    out.extend_from_slice(&FILE_KIND_DEVICE_WRAP.to_be_bytes());
    out.extend_from_slice(&file.vault_uuid);
    out.extend_from_slice(&file.device_uuid);
    out.extend_from_slice(&file.wrap_dev_nonce);
    // wrap_dev_ct_len = 32 (unwrapped IBK size), per §3a, matching §3's convention.
    out.extend_from_slice(&32u32.to_be_bytes());
    out.extend_from_slice(&file.wrap_dev_ct_with_tag);
    out
}

pub fn decode(bytes: &[u8]) -> Result<DeviceWrapFile, DeviceFileError> {
    let mut pos = 0;
    let magic = read_u32_be(bytes, &mut pos)?;
    if magic != MAGIC {
        return Err(DeviceFileError::BadMagic { got: magic });
    }
    let format_version = read_u16_be(bytes, &mut pos)?;
    if format_version != FORMAT_VERSION {
        return Err(DeviceFileError::UnsupportedFormatVersion(format_version));
    }
    let file_kind = read_u16_be(bytes, &mut pos)?;
    if file_kind != FILE_KIND_DEVICE_WRAP {
        return Err(DeviceFileError::UnsupportedFileKind(file_kind));
    }
    let vault_uuid = read_array::<16>(bytes, &mut pos)?;
    let device_uuid = read_array::<16>(bytes, &mut pos)?;
    let wrap_dev_nonce = read_array::<NONCE_LEN>(bytes, &mut pos)?;
    let wrap_dev_ct_len = read_u32_be(bytes, &mut pos)?;
    if wrap_dev_ct_len != 32 {
        return Err(DeviceFileError::WrapLengthMismatch { declared: wrap_dev_ct_len });
    }
    let wrap_dev_ct_with_tag = read_array::<WRAP_CT_PLUS_TAG_LEN>(bytes, &mut pos)?;

    if pos != bytes.len() {
        return Err(DeviceFileError::TrailingBytes { offset: pos });
    }
    Ok(DeviceWrapFile {
        vault_uuid,
        device_uuid,
        wrap_dev_nonce,
        wrap_dev_ct_with_tag,
    })
}

fn read_u16_be(bytes: &[u8], pos: &mut usize) -> Result<u16, DeviceFileError> {
    Ok(u16::from_be_bytes(read_array::<2>(bytes, pos)?))
}
fn read_u32_be(bytes: &[u8], pos: &mut usize) -> Result<u32, DeviceFileError> {
    Ok(u32::from_be_bytes(read_array::<4>(bytes, pos)?))
}
fn read_array<const N: usize>(bytes: &[u8], pos: &mut usize) -> Result<[u8; N], DeviceFileError> {
    if *pos + N > bytes.len() {
        return Err(DeviceFileError::Truncated { offset: *pos });
    }
    let out: [u8; N] = bytes[*pos..*pos + N]
        .try_into()
        .expect("bounds check above guarantees N bytes");
    *pos += N;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> DeviceWrapFile {
        DeviceWrapFile {
            vault_uuid: [0x11; 16],
            device_uuid: [0x22; 16],
            wrap_dev_nonce: [0x33; NONCE_LEN],
            wrap_dev_ct_with_tag: [0x44; WRAP_CT_PLUS_TAG_LEN],
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let f = sample();
        assert_eq!(decode(&encode(&f)).unwrap(), f);
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let mut bytes = encode(&sample());
        bytes[0] ^= 0xFF;
        assert!(matches!(decode(&bytes).unwrap_err(), DeviceFileError::BadMagic { .. }));
    }

    #[test]
    fn decode_rejects_bad_format_version() {
        let mut bytes = encode(&sample());
        bytes[5] = 0x02;
        assert!(matches!(
            decode(&bytes).unwrap_err(),
            DeviceFileError::UnsupportedFormatVersion(2)
        ));
    }

    #[test]
    fn decode_rejects_bad_file_kind() {
        let mut bytes = encode(&sample());
        bytes[7] = 0x01; // pretend to be an identity bundle
        assert!(matches!(
            decode(&bytes).unwrap_err(),
            DeviceFileError::UnsupportedFileKind(1)
        ));
    }

    #[test]
    fn decode_rejects_wrap_length_mismatch() {
        let bytes = encode(&sample());
        // offset: magic(4)+ver(2)+kind(2)+vault_uuid(16)+device_uuid(16)+nonce(24)
        let len_off = 4 + 2 + 2 + 16 + 16 + NONCE_LEN;
        assert_eq!(len_off, 64);
        let mut tampered = bytes.clone();
        tampered[len_off..len_off + 4].copy_from_slice(&64u32.to_be_bytes());
        assert!(matches!(
            decode(&tampered).unwrap_err(),
            DeviceFileError::WrapLengthMismatch { declared: 64 }
        ));
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut bytes = encode(&sample());
        bytes.push(0xAA);
        assert!(matches!(decode(&bytes).unwrap_err(), DeviceFileError::TrailingBytes { .. }));
    }

    #[test]
    fn decode_rejects_truncated_at_every_boundary() {
        let bytes = encode(&sample());
        for n in 0..bytes.len() {
            assert!(decode(&bytes[..n]).is_err(), "must fail on [..{n}]");
        }
        decode(&bytes).expect("full bytes decode");
    }
}
