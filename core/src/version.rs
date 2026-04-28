//! Format and cipher-suite version constants.
//!
//! Sourced from `docs/crypto-design.md` §14 and `docs/vault-format.md` §1.

/// Vault on-disk format version. Recorded in every block header and the manifest.
pub const FORMAT_VERSION: u16 = 1;

/// Cipher-suite identifier for `secretary-v1-pq-hybrid`. Recorded per-block to
/// allow future suites to coexist in the same vault.
pub const SUITE_ID: u16 = 1;

/// File magic, ASCII `"SECR"` interpreted big-endian.
pub const MAGIC: u32 = 0x5345_4352;

/// `file_kind` value for the encrypted manifest file (`docs/vault-format.md`
/// §4.1). Distinguishes the manifest from `identity-bundle` (0x0001) and
/// `block` (0x0003) at the binary header level. Bound into the AEAD AAD via
/// the manifest header bytes, so a forged file cannot be re-classified
/// without invalidating the AEAD tag.
pub const FILE_KIND_MANIFEST: u16 = 0x0002;

#[cfg(test)]
mod tests {
    use super::{FILE_KIND_MANIFEST, MAGIC};

    #[test]
    fn magic_decodes_to_secr_ascii() {
        assert_eq!(&MAGIC.to_be_bytes(), b"SECR");
    }

    #[test]
    fn file_kind_manifest_value_matches_spec() {
        assert_eq!(FILE_KIND_MANIFEST, 0x0002);
    }
}
