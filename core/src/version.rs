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

#[cfg(test)]
mod tests {
    use super::MAGIC;

    #[test]
    fn magic_decodes_to_secr_ascii() {
        assert_eq!(&MAGIC.to_be_bytes(), b"SECR");
    }
}
