//! Vault creation: the third `pub fn` entry point on the bridge surface
//! (after `open_with_password` and `open_with_recovery`), and the first
//! **output-direction** secret-bearing operation. Defines two new opaque-
//! handle types ([`CreateVaultOutput`] and [`MnemonicOutput`]) for the
//! return-side `Sensitive<T>` materialization.
//!
//! # Why a separate handle for the mnemonic
//!
//! `secretary_core::unlock::create_vault` returns a [`CreatedVault`](secretary_core::unlock::CreatedVault)
//! containing — among other artifacts — a freshly-generated 24-word BIP-39
//! mnemonic wrapped as `Sensitive<...>` on the Rust side. That phrase MUST
//! reach the foreign caller exactly once so the user can write it down,
//! then disappear from the system.
//!
//! The three foreign languages all lack a `Sensitive<T>` analog:
//! - **Python** — `bytes` is immutable; `bytearray` is mutable but offers
//!   no destructor hook.
//! - **Swift** — `Data` is value-typed but unzeroized.
//! - **Kotlin** — `ByteArray` is reference-typed but unzeroized.
//!
//! So the bridge keeps the `Sensitive<...>` Rust-side, exposes a one-shot
//! [`MnemonicOutput::take_phrase`] accessor that copies the bytes out into
//! caller-owned heap (a fresh `Vec<u8>`), and drops the inner
//! [`Mnemonic`] immediately —
//! which zeroizes the `String` phrase + `Sensitive<[u8; 32]>` entropy. The
//! caller is responsible for zeroizing their copy after use, mirroring the
//! input-side caller-zeroize discipline from B.2 / B.3a but inverted in
//! direction.
//!
//! # Why a separate handle from `UnlockedIdentity`
//!
//! The mnemonic is a one-time-use secret consumed at vault-creation time;
//! the unlocked identity persists for the session. Coupling them
//! (`identity.recovery_phrase()` returning `Option<...>`) reads worse — a
//! long-lived handle with a dribble of secret state. Keeping them as
//! sister handles produced from the same `create_vault` call lets each
//! match its natural lifecycle: `MnemonicOutput` is one-shot then wiped,
//! `UnlockedIdentity` is used for vault operations until session end.
//!
//! # Why no foreign-side RNG / KDF-params knobs
//!
//! The bridge instantiates `OsRng` and `Argon2idParams::V1_DEFAULT`
//! directly. First-party clients always want the OS CSPRNG and the
//! conservative KDF default; tuning is a v2 design conversation, not an
//! FFI runtime parameter. With `V1_DEFAULT` hardcoded,
//! `core::UnlockError::WeakKdfParams` is structurally unreachable through
//! this surface — the existing defensive fold-into-`CorruptVault`
//! mapping in [`crate::error`] stays in place for forward-compat.
//!
//! Rationale: docs/superpowers/specs/2026-05-05-ffi-b3b-create-vault-design.md

use std::path::Path;
use std::sync::Mutex;

use rand_core::OsRng;
use secretary_core::crypto::kdf::Argon2idParams;
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::unlock::{self, mnemonic::Mnemonic};

use crate::error::{FfiUnlockError, FfiVaultError};
use crate::identity::UnlockedIdentity;
use crate::sync_helpers::lock_or_recover;

/// One-shot opaque handle wrapping a freshly-generated [`Mnemonic`].
///
/// The recovery phrase is `Sensitive<String>`-equivalent on the Rust side;
/// it cannot be projected directly through the FFI without copying out of
/// the `Sensitive<T>` boundary (no foreign language has a generic
/// `Sensitive<T>` analog). [`MnemonicOutput::take_phrase`] does that copy
/// explicitly, ONCE, then drops the inner `Mnemonic` so its `Drop` impl
/// zeroizes both the `String` phrase and the `Sensitive<[u8; 32]>` entropy.
///
/// The returned `Vec<u8>` is fresh caller-owned heap. Callers MUST
/// zeroize it after use; the bridge cannot enforce this from across the
/// FFI. The contract is documented at the foreign-language API level
/// (Python: `for i in range(len(buf)): buf[i] = 0`; Swift / Kotlin: see
/// language idioms in the spec).
///
/// # Lifecycle
///
/// - [`MnemonicOutput::take_phrase`] returns `Some(bytes)` once, then
///   `None` on every subsequent call (one-shot semantics, NOT an error).
///   The inner Mnemonic is consumed and zeroized after the first
///   successful call.
/// - [`MnemonicOutput::wipe`] is idempotent. It drops the inner Mnemonic
///   if still present, zeroizing its secret state.
/// - The Drop impl runs `wipe`-equivalent automatically via
///   `Mutex<Option<Mnemonic>>`'s standard drop chain.
pub struct MnemonicOutput {
    /// `Mutex<Option<...>>` provides one-shot take via `Option::take()`,
    /// idempotent wipe, thread-safe access, and non-throwing post-take
    /// semantics. The WHY of each property is at the function level
    /// (`take_phrase`, `wipe`).
    inner: Mutex<Option<Mnemonic>>,
}

impl MnemonicOutput {
    /// Wrap a freshly-generated `Mnemonic`. Crate-private: only
    /// [`create_vault`] constructs this.
    pub(crate) fn new(m: Mnemonic) -> Self {
        Self {
            inner: Mutex::new(Some(m)),
        }
    }

    /// Test-only constructor. Crate-public so the sibling
    /// secretary-ffi-uniffi crate's mod tests can build a wrapper without
    /// invoking the slow create_vault path. Hidden from rustdoc; not part
    /// of the supported public API.
    #[doc(hidden)]
    pub fn new_for_test(m: Mnemonic) -> Self {
        Self::new(m)
    }

    /// Take the recovery phrase as freshly-allocated UTF-8 bytes. ONE-SHOT —
    /// subsequent calls return `None`.
    ///
    /// On the first successful call, the inner `Mnemonic` is consumed and
    /// dropped here; its `Drop` impl zeroizes the `String` phrase and the
    /// `Sensitive<[u8; 32]>` entropy. The returned `Vec<u8>` was copied
    /// OUT of the about-to-be-zeroized `String` BEFORE the drop, so it
    /// survives intact for the caller to display, copy, and explicitly
    /// zeroize.
    ///
    /// `None` is the documented signal for "already consumed", not an
    /// error. The foreign call sites use `if let Some(phrase) = ...`
    /// (Swift), `phrase?.let { ... }` (Kotlin), or `phrase = ...; if
    /// phrase is None: ...` (Python).
    pub fn take_phrase(&self) -> Option<Vec<u8>> {
        let mut guard = lock_or_recover(&self.inner);
        let m = guard.take()?;
        // Copy bytes out BEFORE m drops; the Drop impl on Mnemonic will
        // zeroize the String buffer when m goes out of scope at the end
        // of this fn. The returned Vec<u8> is a fresh allocation, NOT
        // a slice into the zeroized buffer.
        let bytes = m.phrase().as_bytes().to_vec();
        // m drops here; Mnemonic's explicit Drop wipes phrase + entropy
        Some(bytes)
    }

    /// Idempotent explicit close. Drops the inner [`Mnemonic`] if still
    /// present, zeroizing its secret state. Safe to call multiple times;
    /// safe to call after [`MnemonicOutput::take_phrase`] returned
    /// `Some`.
    pub fn wipe(&self) {
        let _drop = lock_or_recover(&self.inner).take();
        // _drop goes out of scope here → Mnemonic drops → phrase + entropy
        // zeroized.
    }
}

impl std::fmt::Debug for MnemonicOutput {
    /// Redacted Debug: never leak the phrase through fmt. Mirrors the
    /// pattern in `crate::identity::UnlockedIdentity` and core's
    /// `Mnemonic`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let consumed = lock_or_recover(&self.inner).is_none();
        f.debug_struct("MnemonicOutput")
            .field("consumed_or_wiped", &consumed)
            .finish()
    }
}

/// Output of [`create_vault`]. Holds the on-disk byte artifacts plus two
/// opaque handles for the live identity and the one-shot recovery
/// mnemonic.
///
/// # Drop discipline
///
/// Fields drop in source order. Non-secret byte vectors drop first; the
/// two secret-bearing handles last (each zeroizing their own inner
/// state on drop). The order is observable but not load-bearing — neither
/// secret depends on the other for cleanup.
///
/// # Persistence
///
/// `vault_toml_bytes` and `identity_bundle_bytes` are non-secret byte
/// artifacts the foreign caller MUST persist atomically before
/// considering the vault created. The bridge does not perform file I/O;
/// matches the bytes-not-paths discipline of B.2 / B.3a's
/// `open_with_*`.
pub struct CreateVaultOutput {
    /// Vault metadata file contents, non-secret. Caller writes this to
    /// `<vault-dir>/vault.toml` atomically.
    pub vault_toml_bytes: Vec<u8>,
    /// Encrypted identity bundle file contents, non-secret. Caller writes
    /// this to `<vault-dir>/identity.bundle.enc` atomically.
    pub identity_bundle_bytes: Vec<u8>,
    /// Live opaque handle to the just-created `UnlockedIdentity`. Ready
    /// for vault operations immediately; no second `open_with_password`
    /// call is needed.
    pub identity: UnlockedIdentity,
    /// One-shot opaque handle wrapping the freshly-generated 24-word
    /// recovery mnemonic. Caller calls
    /// [`MnemonicOutput::take_phrase`] once, displays the phrase to
    /// the user, then zeroizes their copy and calls
    /// [`MnemonicOutput::wipe`].
    pub mnemonic: MnemonicOutput,
}

/// Create a fresh v1 vault using `OsRng` and `Argon2idParams::V1_DEFAULT`.
///
/// See [module docs](self) for why neither the RNG nor the KDF params
/// are foreign-callable knobs.
///
/// # Inputs
///
/// - `password` — UTF-8-encoded master password as raw bytes. The bridge
///   wraps this into `SecretBytes` (which zeroizes on drop). The caller
///   should still zeroize their input buffer after the call returns
///   (matches the B.2 password-input pattern).
/// - `display_name` — user-facing identity name (UTF-8 string). Stored
///   in the IdentityBundle as plaintext metadata.
/// - `created_at_ms` — wall-clock millisecond timestamp at vault
///   creation. Caller's responsibility to use a sane value (e.g.
///   `int(time.time() * 1000)` in Python).
///
/// # Returns
///
/// On success, a [`CreateVaultOutput`] with four fields:
/// - `vault_toml_bytes` and `identity_bundle_bytes` to persist atomically
/// - `identity` (live [`UnlockedIdentity`] handle, ready for vault ops)
/// - `mnemonic` ([`MnemonicOutput`] one-shot handle for the 24-word
///   recovery phrase)
///
/// # Errors
///
/// Returns [`FfiUnlockError`]; under the hardcoded `V1_DEFAULT` design,
/// the only reachable variant is [`FfiUnlockError::CorruptVault`], which
/// fires on extremely rare paths: Argon2id derivation failure (system OOM
/// / threading) or CBOR serialization failure of the in-memory identity
/// bundle. The `detail` string carries the original
/// `core::UnlockError`'s `Display` text.
pub fn create_vault(
    password: &[u8],
    display_name: &str,
    created_at_ms: u64,
) -> Result<CreateVaultOutput, FfiUnlockError> {
    let pw = SecretBytes::from(password);
    let mut rng = OsRng;
    let core_out = unlock::create_vault(
        &pw,
        display_name,
        created_at_ms,
        Argon2idParams::V1_DEFAULT,
        &mut rng,
    )?;

    let unlock::CreatedVault {
        vault_toml_bytes,
        identity_bundle_bytes,
        recovery_mnemonic,
        identity_block_key,
        identity,
    } = core_out;

    let unlocked = unlock::UnlockedIdentity {
        identity_block_key,
        identity,
    };

    Ok(CreateVaultOutput {
        vault_toml_bytes,
        identity_bundle_bytes,
        identity: UnlockedIdentity::new(unlocked),
        mnemonic: MnemonicOutput::new(recovery_mnemonic),
    })
}

/// Result of [`create_vault_in_folder`]: the new vault's `vault_uuid` plus the
/// one-shot recovery mnemonic. `vault_uuid` is recovered by decoding the
/// just-written `vault.toml` (the same re-parse `core::vault::create_vault`
/// does internally for the manifest header); it lets the platform key the
/// per-device `SyncState` and the remembered location without re-opening the
/// vault. Additive — the iOS / Python / Kotlin call sites destructure
/// `.mnemonic` exactly as before and may ignore `.vault_uuid`.
pub struct CreatedVaultInFolder {
    /// 16-byte vault identifier from the freshly-written `vault.toml`.
    pub vault_uuid: [u8; 16],
    /// One-shot opaque handle for the 24-word recovery phrase (unchanged semantics).
    pub mnemonic: MnemonicOutput,
}

impl std::fmt::Debug for CreatedVaultInFolder {
    /// Redacted Debug: vault_uuid is non-secret (it names the vault, not any
    /// key material), but mnemonic is always redacted via `MnemonicOutput`'s
    /// own `Debug` impl. Mirrors `MnemonicOutput`'s redacted-Debug pattern.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreatedVaultInFolder")
            .field("vault_uuid", &hex::encode(self.vault_uuid))
            .field("mnemonic", &self.mnemonic)
            .finish()
    }
}

/// Create a fresh v1 vault **on disk** in `folder`, writing all four
/// canonical files via `core::vault::create_vault`, and return the new vault's
/// `vault_uuid` alongside the one-shot recovery mnemonic.
///
/// This is the folder-writing sibling of [`create_vault`]. Where
/// `create_vault` returns identity-level byte artifacts for the caller to
/// persist (and pairs with the bytes-based `open_with_password`), this
/// function produces a **complete, browsable** vault — including
/// `manifest.cbor.enc` and `contacts/<owner-uuid>.card` — that opens through
/// the folder-based [`crate::open_vault_with_password`] /
/// [`crate::open_vault_with_recovery`].
///
/// `folder` MUST already exist as an empty directory; the platform layer
/// owns the mkdir / subfolder decision (mirroring core's
/// `ensure_empty_directory` contract). The function does NOT auto-open the
/// vault — the caller re-opens with the master password to browse, matching
/// the desktop "no auto-open, re-enter password" flow.
///
/// `OsRng` and `Argon2idParams::V1_DEFAULT` are hardcoded — no foreign
/// RNG/KDF knobs, same rationale as [`create_vault`].
///
/// # Errors
///
/// - [`FfiVaultError::VaultFolderNotEmpty`] — `folder` contains entries.
/// - [`FfiVaultError::FolderInvalid`] — `folder` is missing, unreadable, or
///   resolves to a file rather than a directory.
/// - [`FfiVaultError::CorruptVault`] — rare crypto/serialization failure.
pub fn create_vault_in_folder(
    folder: &Path,
    password: &[u8],
    display_name: &str,
    created_at_ms: u64,
) -> Result<CreatedVaultInFolder, FfiVaultError> {
    let pw = SecretBytes::from(password);
    let mut rng = OsRng;
    let mnemonic = secretary_core::vault::create_vault(
        folder,
        &pw,
        display_name,
        Argon2idParams::V1_DEFAULT,
        created_at_ms,
        &mut rng,
    )
    .map_err(FfiVaultError::from)?;

    // Recover vault_uuid from the canonical on-disk vault.toml we just wrote.
    // A read/decode failure here is an internal bug (we authored the file a
    // moment ago), so it folds to the rare-crypto CorruptVault arm rather than
    // a user-facing folder error.
    let toml = std::fs::read_to_string(folder.join("vault.toml")).map_err(|e| {
        FfiVaultError::CorruptVault {
            detail: format!("vault.toml unreadable post-create: {e}"),
        }
    })?;
    let vt = secretary_core::unlock::vault_toml::decode(&toml).map_err(|e| {
        FfiVaultError::CorruptVault {
            detail: format!("vault.toml undecodable post-create: {e}"),
        }
    })?;

    Ok(CreatedVaultInFolder {
        vault_uuid: vt.vault_uuid,
        mnemonic: MnemonicOutput::new(mnemonic),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    use secretary_core::unlock::mnemonic;

    /// Helper: build a `MnemonicOutput` from a deterministically-seeded
    /// `mnemonic::generate` call. Avoids the ~1s Argon2id cost of
    /// invoking `create_vault` itself; the three fast tests below
    /// exercise `MnemonicOutput`'s contract in isolation.
    fn fresh_mnemonic_output() -> MnemonicOutput {
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let m = mnemonic::generate(&mut rng);
        MnemonicOutput::new(m)
    }

    /// Helper: mint a fresh random password at test runtime. Literal
    /// password byte strings trip CodeQL's
    /// `rust/hard-coded-cryptographic-value` rule, so the create / open
    /// round-trips below generate the secret from `OsRng` and reuse the
    /// same bound value for both halves of the round-trip
    /// ([[feedback_test_crypto_random_not_hardcoded]]).
    fn random_password() -> Vec<u8> {
        use rand_core::RngCore;
        let mut pw = vec![0u8; 16];
        OsRng.fill_bytes(&mut pw);
        pw
    }

    #[test]
    fn mnemonic_output_take_phrase_returns_24_words() {
        let mo = fresh_mnemonic_output();
        let phrase = mo.take_phrase().expect("first call must return Some");
        let word_count = phrase.split(|&b| b == b' ').count();
        assert_eq!(
            word_count,
            24,
            "expected 24 words, got {word_count}: {:?}",
            std::str::from_utf8(&phrase).unwrap_or("<not utf-8>"),
        );
    }

    #[test]
    fn mnemonic_output_take_phrase_is_one_shot() {
        let mo = fresh_mnemonic_output();
        let first = mo.take_phrase();
        let second = mo.take_phrase();
        assert!(first.is_some(), "first call must return Some");
        assert!(second.is_none(), "second call must return None (one-shot)");
    }

    #[test]
    fn mnemonic_output_wipe_is_idempotent() {
        let mo = fresh_mnemonic_output();
        mo.wipe();
        mo.wipe(); // second call must not panic
        mo.wipe(); // third call must not panic
        assert!(
            mo.take_phrase().is_none(),
            "take_phrase after wipe must return None",
        );
    }

    #[test]
    fn create_vault_round_trip_with_password() {
        // Slow test: real Argon2idParams::V1_DEFAULT. ~1s for create
        // + ~1s for open. Justified because this is the only place that
        // exercises the bridge's create_vault end-to-end against a real
        // produced byte artifact.
        let out = create_vault(b"hunter2", "Round-Trip-Bob", 1_700_000_000_000)
            .expect("create_vault should succeed");
        assert_eq!(out.identity.display_name(), "Round-Trip-Bob");

        let opened = crate::open_with_password(
            &out.vault_toml_bytes,
            &out.identity_bundle_bytes,
            b"hunter2",
        )
        .expect("re-open with the same password must succeed");
        assert_eq!(opened.display_name(), "Round-Trip-Bob");
        assert_eq!(opened.user_uuid(), out.identity.user_uuid());
    }

    #[test]
    fn create_vault_round_trip_with_recovery() {
        // Slow test: same shape as the password round-trip but
        // exercises the recovery path end-to-end.
        let out = create_vault(b"unused-pw", "Round-Trip-Carol", 1_700_000_000_000)
            .expect("create_vault should succeed");
        let phrase = out
            .mnemonic
            .take_phrase()
            .expect("phrase must be available");

        let opened =
            crate::open_with_recovery(&out.vault_toml_bytes, &out.identity_bundle_bytes, &phrase)
                .expect("re-open with the just-taken phrase must succeed");
        assert_eq!(opened.display_name(), "Round-Trip-Carol");
    }

    #[test]
    fn create_vault_in_folder_writes_complete_openable_vault() {
        // Real Argon2idParams::V1_DEFAULT. Proves the folder-writing path
        // produces ALL FOUR canonical files (not just the 2 identity-level
        // byte artifacts the bytes-based create_vault returns) — the
        // folder-based open_vault_with_password validates the manifest
        // signature + owner card, so a successful open IS the proof the
        // manifest + contacts/<uuid>.card were written and are valid.
        let dir = tempfile::tempdir().expect("tempdir");
        let folder = dir.path();
        let pw = random_password();

        let out = create_vault_in_folder(folder, &pw, "Folder-Bob", 1_700_000_000_000)
            .expect("create_vault_in_folder should succeed");

        assert!(folder.join("vault.toml").is_file(), "vault.toml missing");
        assert!(
            folder.join("identity.bundle.enc").is_file(),
            "identity.bundle.enc missing",
        );
        assert!(
            folder.join("manifest.cbor.enc").is_file(),
            "manifest.cbor.enc missing",
        );
        assert!(folder.join("contacts").is_dir(), "contacts/ missing");

        // Folder-based password open must succeed → the vault is browsable.
        let opened = crate::open_vault_with_password(folder, &pw)
            .expect("folder open with the same password must succeed");
        assert_eq!(opened.identity.display_name(), "Folder-Bob");

        // The returned mnemonic opens the same vault via the recovery path.
        let phrase = out
            .mnemonic
            .take_phrase()
            .expect("phrase must be available");
        let opened2 = crate::open_vault_with_recovery(folder, &phrase)
            .expect("folder open with the just-taken phrase must succeed");
        assert_eq!(opened2.identity.display_name(), "Folder-Bob");
    }

    #[test]
    fn create_vault_in_folder_rejects_nonempty_folder() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("junk"), b"x").expect("seed junk file");
        let err = create_vault_in_folder(dir.path(), &random_password(), "X", 1_700_000_000_000)
            .expect_err("non-empty folder must error");
        assert!(
            matches!(err, FfiVaultError::VaultFolderNotEmpty),
            "non-empty folder must surface VaultFolderNotEmpty, got {err:?}",
        );
    }

    #[test]
    fn create_vault_in_folder_rejects_missing_folder() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("does-not-exist");
        let err = create_vault_in_folder(&missing, &random_password(), "X", 1_700_000_000_000)
            .expect_err("missing folder must error");
        assert!(
            matches!(err, FfiVaultError::FolderInvalid { .. }),
            "missing folder must surface FolderInvalid, got {err:?}",
        );
    }

    #[test]
    fn create_vault_in_folder_rejects_file_path() {
        // A path that resolves to a file (not a directory) is a wrong-path
        // mistake, not corruption: ensure_empty_directory surfaces
        // NotADirectory, which must map to the actionable FolderInvalid.
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("a-file");
        std::fs::write(&file, b"x").expect("seed file");
        let err = create_vault_in_folder(&file, &random_password(), "X", 1_700_000_000_000)
            .expect_err("file path must error");
        assert!(
            matches!(err, FfiVaultError::FolderInvalid { .. }),
            "file path must surface FolderInvalid, got {err:?}",
        );
    }

    #[test]
    fn create_vault_in_folder_returns_vault_uuid_matching_vault_toml() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = create_vault_in_folder(
            dir.path(),
            b"correct horse",
            "Test Vault",
            1_700_000_000_000,
        )
        .expect("create must succeed into an empty dir");

        // The returned uuid must equal vault.toml's vault_uuid (the authoritative on-disk value).
        let toml =
            std::fs::read_to_string(dir.path().join("vault.toml")).expect("vault.toml readable");
        let vt = secretary_core::unlock::vault_toml::decode(&toml).expect("vault.toml decodes");
        assert_eq!(
            out.vault_uuid, vt.vault_uuid,
            "returned uuid must match vault.toml"
        );
        assert_eq!(out.vault_uuid.len(), 16);
        assert_ne!(out.vault_uuid, [0u8; 16], "uuid must not be all-zero");

        // The mnemonic handle still yields a 24-word phrase exactly once.
        let phrase = out.mnemonic.take_phrase().expect("phrase available once");
        assert_eq!(phrase.split(|b| *b == b' ').count(), 24);
    }
}
