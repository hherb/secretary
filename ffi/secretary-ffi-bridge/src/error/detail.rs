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
use std::path::Path;

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
// entry (#480, scripts/error-payload-hygiene-allowlist.txt) and the claim
// lives in that file's reason column:
impl GatedDetail for std::io::Error {} // CARRIER, not fixed-format: safe only while every construction site's payload is — see allowlist entry
impl GatedDetail for std::num::ParseIntError {} // fixed std phrases, no input echo
impl GatedDetail for std::str::ParseBoolError {} // fixed std phrase, no input echo
impl GatedDetail for secretary_cli::state::StateError {} // all 5 arms secret-free: errno / core-gated SyncError / disclosed lock path / disclosed vault-UUID hex — see allowlist entry

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

/// Build a `std::io::Error` whose payload is gated (#487).
///
/// `std::io::Error` is allowlisted for `GatedDetail` as a CARRIER: its
/// `Display` renders whatever it was constructed with, so — unlike
/// `ParseIntError` — its safety is a claim about every construction site,
/// not about the type. Guard rule E3 treats the payload argument of
/// `io::Error::new` / `io::Error::other` as a construction site for exactly
/// that reason, and this is the sanctioned way to satisfy it.
///
/// The payload is built through the fully-qualified `crate::error::detail::
/// gated_with_context(...)` rather than the bare in-module call. That is not
/// stylistic: guard rule E3's io-payload gate accepts only a string literal
/// or a call whose text is literally `detail::<name>(...)` (its synthetic
/// field name `<io::Error payload>` is deliberately not a valid identifier,
/// so the "same name" re-wrap arm every other gated field can use is
/// structurally unreachable here — see `IO_PAYLOAD_FIELD`'s docstring in
/// `scripts/payload_guard/rules/e3.py`). This file IS the `detail` module,
/// so an unqualified `gated_with_context(...)` call has no `detail::` text
/// in front of it and would deny under the guard's own real scan (verified
/// by execution while writing this function) — self-qualifying is the only
/// shape that is both correct Rust and a sanctioned construction site.
pub(crate) fn io_gated(
    kind: std::io::ErrorKind,
    context: &'static str,
    e: &impl GatedDetail,
) -> std::io::Error {
    std::io::Error::new(kind, crate::error::detail::gated_with_context(context, e))
}

/// Append a disclosed filesystem path after an already-gated value (#487).
///
/// `path` is the ALREADY-DISCLOSED class (allowlist Section 2, mirroring
/// `core/src/vault/mod.rs`'s `Io { source }` arm): anyone with read access
/// to the vault folder / state directory can already enumerate every path
/// directly, so echoing one here discloses nothing an attacker with folder
/// access doesn't already have. `e` must already be gated — this fn adds no
/// gating of its own for whatever `e` carries, it only appends the path.
pub(crate) fn gated_with_path(e: &impl GatedDetail, path: &Path) -> String {
    format!("{e}; state file path: {}", path.display())
}

/// Build a `std::io::Error` whose payload gates a `GatedDetail` value AND
/// appends a disclosed filesystem path (#487) — the two-runtime-value
/// sibling of [`io_gated`] for sites (like `repair::orchestration`'s §10
/// baseline read) whose diagnostic needs a path alongside the error. Layered
/// on `io_gated` itself (not a parallel hand-rolled `format!`): the
/// `{context}: {e}` half is gated exactly the same way, and layering is
/// what keeps `io_gated` a genuine, exercised production constructor rather
/// than a helper only its own unit test calls.
pub(crate) fn io_gated_with_path(
    kind: std::io::ErrorKind,
    context: &'static str,
    path: &Path,
    e: &impl GatedDetail,
) -> std::io::Error {
    let with_context = io_gated(kind, context, e);
    std::io::Error::new(
        kind,
        crate::error::detail::gated_with_path(&with_context, path),
    )
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
    fn io_gated_renders_context_and_display() {
        let inner = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let e = io_gated(std::io::ErrorKind::InvalidData, "read state", &inner);
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(e.to_string(), "read state: gone");
    }

    #[test]
    fn gated_with_path_appends_disclosed_path() {
        let e = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let msg = gated_with_path(&e, std::path::Path::new("/tmp/state/x.state.cbor"));
        assert_eq!(msg, "gone; state file path: /tmp/state/x.state.cbor");
    }

    #[test]
    fn io_gated_with_path_renders_context_display_and_path() {
        let inner = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let e = io_gated_with_path(
            std::io::ErrorKind::InvalidData,
            "read state",
            std::path::Path::new("/tmp/state/x.state.cbor"),
            &inner,
        );
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            e.to_string(),
            "read state: gone; state file path: /tmp/state/x.state.cbor"
        );
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
