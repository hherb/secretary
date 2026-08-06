//! The ONLY place in the bridge permitted to build a detail string.
//!
//! `#474` made every `core` error payload data-free by construction — no
//! `core` variant interpolates a runtime string into its `#[error]`
//! message. That guarantee is worthless if the bridge is free to hand-roll
//! its own `format!("{e}")` at ~110 call sites, because a future call site
//! could interpolate a decrypted field name, a raw path, or any other
//! secret-bearing runtime value with nobody the wiser. This module closes
//! that gap: every bridge-authored detail string is built through one of
//! the sanctioned constructors below, and every constructor's `e: &impl
//! GatedDetail` bound only accepts a type whose `impl GatedDetail for X`
//! line lives in THIS file.
//!
//! `impl GatedDetail for X` is a **security decision** — a claim that
//! `X`'s `Display` output carries no vault plaintext, password, mnemonic,
//! or key bytes. Every impl outside this file fails CI (guard rule E4);
//! keeping all of them here means one file review covers the entire
//! allowlist rather than trusting it to stay implicit across the crate.
pub(crate) trait GatedDetail: std::fmt::Display {}

// Core error enums: safe by recursion — scripts/check-error-payload-hygiene.py
// gates each one's payloads at its own definition (rule E1).
impl GatedDetail for secretary_core::vault::VaultError {}
impl GatedDetail for secretary_core::vault::block::BlockError {}
impl GatedDetail for secretary_core::unlock::UnlockError {}
impl GatedDetail for secretary_core::unlock::mnemonic::MnemonicError {}
impl GatedDetail for secretary_core::unlock::vault_toml::VaultTomlError {}
impl GatedDetail for secretary_core::identity::card::CardError {}
impl GatedDetail for secretary_core::crypto::sig::SigError {}
impl GatedDetail for secretary_core::sync::SyncError {}

// Bridge-local, guard-scanned (rule E2 covers their declarations).
impl GatedDetail for crate::vault::manifest::ReplaceManifestError {}
impl GatedDetail for crate::settings::parse::SettingsParseError {}

// Reviewed claims OUTSIDE the guard's registries — each is an E4 allowlist
// entry (Task 8) and the claim lives in the allowlist reason column:
impl GatedDetail for std::io::Error {} // path + errno: already disclosed
impl GatedDetail for std::num::ParseIntError {} // fixed std phrases, no input echo
impl GatedDetail for std::str::ParseBoolError {} // fixed std phrase, no input echo
impl GatedDetail for secretary_cli::state::StateError {} // folds io::Error / core-gated SyncError

pub(crate) fn gated(e: &impl GatedDetail) -> String {
    e.to_string()
}

pub(crate) fn gated_with_context(context: &'static str, e: &impl GatedDetail) -> String {
    format!("{context}: {e}")
}

pub(crate) fn uuid_hex(uuid: &[u8; 16]) -> String {
    hex::encode(uuid)
}

pub(crate) fn uuid_hyphenated(uuid: &[u8; 16]) -> String {
    secretary_core::vault::format_uuid_hyphenated(uuid)
}

pub(crate) fn fingerprint_hex(fingerprint: &[u8; 16]) -> String {
    hex::encode(fingerprint)
}

pub(crate) fn gated_for_uuid(
    context: &'static str,
    uuid: &[u8; 16],
    e: &impl GatedDetail,
) -> String {
    format!("{context} {}: {e}", hex::encode(uuid))
}

pub(crate) fn literal_for_uuid(context: &'static str, uuid: &[u8; 16]) -> String {
    format!("{context} {}", hex::encode(uuid))
}

pub(crate) fn counted(context: &'static str, n: usize) -> String {
    format!("{context}: {n}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gated_renders_display() {
        let e = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        assert_eq!(gated(&e), "gone");
    }

    #[test]
    fn gated_with_context_prefixes() {
        let e = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        assert_eq!(gated_with_context("read foo", &e), "read foo: gone");
    }

    #[test]
    fn uuid_renderers() {
        let uuid = [0xABu8; 16];
        assert_eq!(uuid_hex(&uuid), "ab".repeat(16));
        assert_eq!(fingerprint_hex(&uuid), "ab".repeat(16));
        assert_eq!(
            uuid_hyphenated(&[
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
                0xFF, 0x00
            ]),
            "11223344-5566-7788-99aa-bbccddeeff00"
        );
    }

    #[test]
    fn uuid_composites() {
        let e = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let uuid = [0x01u8; 16];
        assert_eq!(
            gated_for_uuid("block file missing for", &uuid, &e),
            format!("block file missing for {}: gone", "01".repeat(16))
        );
        assert_eq!(
            literal_for_uuid("trash entry has no matching file for", &uuid),
            format!("trash entry has no matching file for {}", "01".repeat(16))
        );
    }

    #[test]
    fn counted_renders_index() {
        assert_eq!(
            counted("unknown settings field ignored; field index", 3),
            "unknown settings field ignored; field index: 3"
        );
    }
}
