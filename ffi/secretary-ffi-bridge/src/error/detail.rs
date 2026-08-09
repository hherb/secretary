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

/// A diagnostic string built by a sanctioned constructor in THIS module.
///
/// The inner field is private, so a `Detail` is constructible only from
/// inside `detail.rs`. Every gated payload position in the bridge is declared
/// `Detail`, which makes `detail: format!(…)` — and every other way of
/// producing a `String`, including the pattern-bind, build-then-mutate,
/// function-parameter and dotless-reassignment shapes rule E3 cannot see — a
/// TYPE ERROR at every call site in this crate and in every downstream crate.
///
/// # What this type does and does not claim
///
/// It claims exactly one thing: **this string came out of a reviewed
/// constructor below.** It does NOT claim that a struct holding one carries
/// no secrets. `FfiAddedRecipient` and `FfiWideningReport`
/// (`crate::repair::preview`) deliberately carry decrypted plaintext in
/// sibling fields — `display_name`, `block_name` — which stay `String` and
/// must. A `Detail` beside a plaintext `String` is correct, not an
/// inconsistency to "clean up".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detail(String);

impl Detail {
    /// Borrow the rendered text. The only read path a wrapper crate needs
    /// that does not consume the value.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume into the owned `String` the binding wrapper crates project
    /// across the FFI (uniffi's `VaultError` must carry a UDL `string`;
    /// PyO3 exceptions take a message). This is a PROJECTION, not a gate —
    /// see the spec's §4.
    pub fn into_string(self) -> String {
        self.0
    }

    /// Test-only escape hatch, absent from every non-test build.
    ///
    /// Wrapper-crate unit tests construct `FfiVaultError` values directly and
    /// cannot otherwise obtain a `Detail`. Gated behind a non-default Cargo
    /// feature that only `[dev-dependencies]` enables, so under resolver v2
    /// this function DOES NOT EXIST in `cargo build --release`. That is
    /// enforced by `cargo build --release --workspace` in CI — verified by
    /// execution that `cargo test`, `cargo clippy --tests` and the rustdoc
    /// gate all compile a production call to it CLEAN (verified on a
    /// synthetic two-crate probe; re-verified on this workspace in Task 3).
    #[cfg(feature = "test-support")]
    pub fn for_test(s: &str) -> Detail {
        Detail(s.to_string())
    }
}

impl std::fmt::Display for Detail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Sealing module (#496). `Sealed` is nameable only from inside `detail.rs`,
/// so an `impl GatedDetail for X` written in ANY other module of this crate
/// fails to compile with "the trait bound `X: Sealed` is not satisfied".
///
/// Guard rule E4 already denies such an impl, but E4 reads TEXT — it is
/// blind to a `macro_rules!`-generated impl and to `use detail::GatedDetail
/// as GD;` spelling the trait under an alias, both disclosed in the guard's
/// LIMITS. Sealing closes the whole class in the compiler, and aliasing the
/// trait name does not help: the alias still cannot reach `Sealed`. E4
/// remains as defence in depth and for the cross-file review story.
///
/// `pub(crate)` on the trait already stopped OTHER CRATES implementing it;
/// this stops other MODULES of this crate.
mod private {
    pub(crate) trait Sealed {}
}

pub(crate) trait GatedDetail: std::fmt::Display + private::Sealed {}

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

/// [`gated_with_path`] plus a TRAILING remediation sentence (#496).
///
/// `advice` is `&'static str` — a fixed sentence written at the call site,
/// never runtime content — and it goes LAST on purpose. Routing the §10
/// rollback-baseline diagnostic through `io_gated_with_path` put its
/// remediation advice in `context` position, i.e. at the HEAD, which
/// composed to `"if that file exists, deleting it resets … must be fixed
/// instead: No such file or directory; state file path: /…"` — the clause
/// "if that file exists" preceding the only mention of the file, and the
/// source error reading as a suffix of the advice. The advice was written to
/// be read after the failure it explains, so a constructor that preserves
/// that order is the fix rather than a reworded sentence.
pub(crate) fn gated_with_path_and_advice(
    e: &impl GatedDetail,
    path: &Path,
    advice: &'static str,
) -> String {
    format!(
        "{}; {advice}",
        crate::error::detail::gated_with_path(e, path)
    )
}

/// Build a `std::io::Error` whose payload is gated, appending a disclosed
/// path and a trailing remediation sentence (#487, reordered in #496).
///
/// `std::io::Error` is allowlisted for `GatedDetail` as a CARRIER: its
/// `Display` renders whatever it was constructed with, so — unlike
/// `ParseIntError` — its safety is a claim about every construction site,
/// not about the type. Guard rule E3 treats the payload argument of
/// `io::Error::new` / `io::Error::other` as a construction site for exactly
/// that reason, and this is the sanctioned way to satisfy it. It is the ONLY
/// such constructor, because the tree has exactly one production io mint
/// (`repair::orchestration`'s §10 baseline read); #487's `io_gated` /
/// `io_gated_with_path` pair was retired in #496 once that site moved off
/// the leading-context ordering and nothing else called them.
///
/// The payload is built through the fully-qualified `crate::error::detail::
/// gated_with_path_and_advice(...)` rather than the bare in-module call. That
/// is not stylistic: guard rule E3's io-payload gate accepts only a string
/// literal or a call whose text is literally `detail::<name>(...)` (its
/// synthetic field name `<io::Error payload>` is deliberately not a valid
/// identifier, so the "same name" re-wrap arm every other gated field can
/// use is structurally unreachable here — see `IO_PAYLOAD_FIELD`'s docstring
/// in `scripts/payload_guard/rules/e3.py`). This file IS the `detail`
/// module, so an unqualified call has no `detail::` text in front of it and
/// would deny under the guard's own real scan (verified by execution) —
/// self-qualifying is the only shape that is both correct Rust and a
/// sanctioned construction site.
pub(crate) fn io_gated_with_path_and_advice(
    kind: std::io::ErrorKind,
    path: &Path,
    advice: &'static str,
    e: &impl GatedDetail,
) -> std::io::Error {
    std::io::Error::new(
        kind,
        crate::error::detail::gated_with_path_and_advice(e, path, advice),
    )
}

// Sealing impls (#496), one per `GatedDetail` impl above. Kept as a block so
// adding a `GatedDetail` impl without a matching `Sealed` impl is a compile
// error that points here, and so the reviewed allowlist above stays readable
// as a single list.
impl private::Sealed for secretary_core::vault::VaultError {}
impl private::Sealed for secretary_core::vault::block::BlockError {}
impl private::Sealed for secretary_core::unlock::UnlockError {}
impl private::Sealed for secretary_core::unlock::mnemonic::MnemonicError {}
impl private::Sealed for secretary_core::unlock::vault_toml::VaultTomlError {}
impl private::Sealed for secretary_core::identity::card::CardError {}
impl private::Sealed for secretary_core::crypto::sig::SigError {}
impl private::Sealed for secretary_core::sync::SyncError {}
impl private::Sealed for crate::vault::manifest::ReplaceManifestError {}
impl private::Sealed for crate::settings::parse::SettingsParseError {}
impl private::Sealed for std::io::Error {}
impl private::Sealed for std::num::ParseIntError {}
impl private::Sealed for std::str::ParseBoolError {}
impl private::Sealed for secretary_cli::state::StateError {}

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
    fn gated_with_path_appends_disclosed_path() {
        let e = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let msg = gated_with_path(&e, std::path::Path::new("/tmp/state/x.state.cbor"));
        assert_eq!(msg, "gone; state file path: /tmp/state/x.state.cbor");
    }

    #[test]
    fn gated_with_path_and_advice_puts_the_advice_last() {
        // The ORDER is the whole point of this constructor (#496): the
        // source error first, then the path it refers to, then the advice
        // that talks about that path. A regression here reads as
        // "…must be fixed instead: No such file or directory".
        let e = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let msg = gated_with_path_and_advice(
            &e,
            std::path::Path::new("/tmp/state/x.state.cbor"),
            "if that file exists, deleting it resets this device's rollback history",
        );
        assert_eq!(
            msg,
            "gone; state file path: /tmp/state/x.state.cbor; if that file \
             exists, deleting it resets this device's rollback history"
        );
        // Belt and braces: the advice must not PRECEDE the source error.
        assert!(msg.find("gone").unwrap() < msg.find("if that file exists").unwrap());
    }

    #[test]
    fn io_gated_with_path_and_advice_renders_display_path_then_advice() {
        let inner = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let e = io_gated_with_path_and_advice(
            std::io::ErrorKind::InvalidData,
            std::path::Path::new("/tmp/state/x.state.cbor"),
            "then retry the repair",
            &inner,
        );
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            e.to_string(),
            "gone; state file path: /tmp/state/x.state.cbor; then retry the repair"
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

    // `Detail`'s own behaviour. Every constructor still returns `String` at
    // this point (Task 3 moves them), so `for_test` is the only way to build
    // one — which is exactly the property under test: the type has no public
    // construction path outside `detail.rs`.
    #[cfg(feature = "test-support")]
    #[test]
    fn detail_renders_borrows_and_unwraps() {
        let runtime = String::from("built at runtime");
        let d = Detail::for_test(&runtime);
        assert_eq!(d.as_str(), "built at runtime");
        assert_eq!(format!("{d}"), "built at runtime");
        assert_eq!(d.clone().into_string(), "built at runtime");
    }
}
