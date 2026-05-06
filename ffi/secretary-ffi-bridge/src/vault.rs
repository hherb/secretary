//! Folder-based vault entry points (B.4a). The first folder-IO surface on
//! the bridge — bytes-in unlock paths (B.2 / B.3a) and bytes-in
//! create_vault (B.3b) all stay unchanged.
//!
//! # IO model
//!
//! Foreign caller passes a folder path; Rust core reads `vault.toml`,
//! `identity.bundle.enc`, `manifest.cbor.enc`, and the owner contact card
//! from disk via `secretary_core::vault::open_vault`. This is a deliberate
//! transition from the bytes-in discipline: the §9 atomicity guarantee
//! depends on `tempfile::persist` for `rename(2)` semantics, and B.4c's
//! eventual `save_block` will need that contract owned by Rust core.
//! B.4a establishes the IO model that B.4b/c/d inherit.
//!
//! # Output handles
//!
//! Two opaque handles:
//! - [`UnlockedIdentity`] — re-used unchanged from B.2 / B.3a / B.3b.
//!   Wraps `core::IdentityBundle` (display_name, user_uuid, secret keys).
//! - [`OpenVaultManifest`] — NEW. Wraps the rest of `core::vault::OpenVault`:
//!   the IBK (Sensitive on the Rust side, kept for B.4b's read_block),
//!   the decrypted manifest body (block list + vault-level vector clock),
//!   the manifest envelope (kept for B.4c's re-sign), and the verified
//!   owner contact card (kept for B.4c/d signature operations; not yet
//!   exposed through accessors).
//!
//! # Error type
//!
//! Returns [`FfiVaultError`] (NEW; see [`crate::error`] module docs). Six
//! flat variants — 5 mirrored byte-identically from
//! [`FfiUnlockError`](crate::error::FfiUnlockError) and 1 new `FolderInvalid`
//! for IO problems. `local_highest_clock` is always `None`; rollback detection
//! deferred to Sub-project C.

use std::path::Path;
use std::sync::Mutex;

use secretary_core::crypto::secret::{SecretBytes, Sensitive};
use secretary_core::identity::card::ContactCard;
use secretary_core::vault::{Manifest, ManifestFile, Unlocker};
use zeroize::Zeroize as _;

use crate::error::FfiVaultError;
use crate::identity::UnlockedIdentity;
use crate::sync_helpers::lock_or_recover;

/// Read-only metadata projection of one [`secretary_core::vault::BlockEntry`].
/// All five fields are plaintext in the manifest already; no secret material
/// crosses through `BlockSummary`. The struct is `Clone`, `Debug`, and
/// projects directly to a Swift `struct` / Kotlin `data class` /
/// `#[pyclass(frozen)]` at the binding-flavor layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockSummary {
    /// 16-byte block UUID identifying the block file on disk.
    pub block_uuid: [u8; 16],
    /// User-visible block name. Plaintext within the encrypted manifest.
    pub block_name: String,
    /// Wall-clock millisecond timestamp at block creation.
    pub created_at_ms: u64,
    /// Wall-clock millisecond timestamp at last modification.
    pub last_modified_ms: u64,
    /// Contact UUIDs of each recipient (always includes owner). Plaintext
    /// within the encrypted manifest. Encoded in ascending lex order.
    pub recipient_uuids: Vec<[u8; 16]>,
}

/// Output of [`open_vault_with_password`] / [`open_vault_with_recovery`].
/// Holds two opaque handles — the live identity and the read-only manifest.
///
/// # Drop discipline
///
/// Fields drop in source order. Both handles zeroize their own inner state
/// on drop; the order is observable but not load-bearing.
///
/// Debug output is redacted via the fields' own Debug impls — no secret
/// material leaks through `{:?}`.
#[derive(Debug)]
pub struct OpenVaultOutput {
    /// Live opaque handle to the unlocked identity. Re-used unchanged from
    /// B.2 / B.3a / B.3b. Same `display_name()` / `user_uuid()` / `wipe()`
    /// accessors.
    pub identity: UnlockedIdentity,
    /// Opaque handle to the decrypted manifest. Holds the IBK, manifest
    /// body, manifest envelope, and verified owner card internally; B.4a
    /// exposes only read-only block-list accessors.
    pub manifest: OpenVaultManifest,
}

/// Internal state of [`OpenVaultManifest`]. Held inside `Mutex<Option<...>>`
/// so the wrapper can provide idempotent close + non-throwing post-close
/// accessors + thread-safe access. All four fields are kept for forward-
/// compat with B.4b (read_block needs the IBK), B.4c (save_block needs
/// the manifest envelope + owner card for re-signing), and B.4d
/// (share_block needs the owner card).
///
/// `pub(crate)` so that [`OpenVaultManifest::new`] (also `pub(crate)`) can
/// name the type without triggering the `private_interfaces` lint.
pub(crate) struct OpenVaultManifestInner {
    /// 32-byte Identity Block Key. Sensitive; zeroized on drop. Held for
    /// B.4b's `read_block` to use without re-opening the vault.
    #[allow(dead_code)] // B.4b will use this; intentional now for forward-compat
    identity_block_key: Sensitive<[u8; 32]>,
    /// Decrypted manifest body — block list, vault-level vector clock,
    /// kdf_params attestation, owner UUIDs.
    manifest: Manifest,
    /// On-disk manifest envelope (header + AEAD nonce + ct/tag + author
    /// fingerprint + §8 hybrid signature). Held for B.4c's `save_block`
    /// to re-sign on update without re-opening.
    #[allow(dead_code)] // B.4c will use this; intentional now for forward-compat
    manifest_file: ManifestFile,
    /// Owner's self-signed contact card, already self-verified during
    /// `core::open_vault`. Held internally for B.4c/d signature operations;
    /// **not** exposed through B.4a accessors (deferred to B.4d).
    #[allow(dead_code)] // B.4c/d will use this; intentional now for forward-compat
    owner_card: ContactCard,
}

/// Opaque handle to a successfully-opened vault's manifest.
///
/// # Lifecycle
///
/// [`OpenVaultManifest::wipe`] explicitly drops the wrapped state now —
/// zeroizes the `Sensitive<[u8; 32]>` IBK and source-order-drops the rest.
/// **Idempotent** — multiple calls do not panic. Subsequent accessor calls
/// on a closed handle return empty / zero defaults rather than panicking,
/// keeping the API non-throwing (parallel to [`UnlockedIdentity`]).
///
/// RAII is the safety net: when the foreign-side reference releases, the
/// Rust-side `Drop` cascade still runs.
pub struct OpenVaultManifest {
    inner: Mutex<Option<OpenVaultManifestInner>>,
}

/// Redacted Debug: never leak secret material through fmt.
impl std::fmt::Debug for OpenVaultManifest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let is_closed = lock_or_recover(&self.inner).is_none();
        f.debug_struct("OpenVaultManifest")
            .field("closed", &is_closed)
            .finish()
    }
}

impl OpenVaultManifest {
    /// Wrap a freshly-decoded manifest. Crate-private: only
    /// [`open_vault_with_password`] / [`open_vault_with_recovery`]
    /// construct this.
    pub(crate) fn new(inner: OpenVaultManifestInner) -> Self {
        Self {
            inner: Mutex::new(Some(inner)),
        }
    }

    /// 16-byte vault UUID from the manifest body. Returns `vec![0u8; 16]`
    /// if the handle has been wiped.
    pub fn vault_uuid(&self) -> Vec<u8> {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.manifest.vault_uuid.to_vec())
            .unwrap_or_else(|| vec![0u8; 16])
    }

    /// 16-byte owner user UUID from the manifest body. Returns
    /// `vec![0u8; 16]` if the handle has been wiped.
    pub fn owner_user_uuid(&self) -> Vec<u8> {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.manifest.owner_user_uuid.to_vec())
            .unwrap_or_else(|| vec![0u8; 16])
    }

    /// Number of blocks in the manifest. Returns `0` if wiped.
    pub fn block_count(&self) -> u64 {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| i.manifest.blocks.len() as u64)
            .unwrap_or(0)
    }

    /// All block summaries in the manifest's ascending-by-`block_uuid`
    /// order. Returns an empty `Vec` if wiped.
    pub fn block_summaries(&self) -> Vec<BlockSummary> {
        lock_or_recover(&self.inner)
            .as_ref()
            .map(|i| {
                i.manifest
                    .blocks
                    .iter()
                    .map(block_entry_to_summary)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Locate one block by its UUID. Returns `None` if wiped or if no
    /// matching block exists.
    pub fn find_block(&self, block_uuid: &[u8]) -> Option<BlockSummary> {
        if block_uuid.len() != 16 {
            return None;
        }
        let mut needle = [0u8; 16];
        needle.copy_from_slice(block_uuid);
        lock_or_recover(&self.inner).as_ref().and_then(|i| {
            i.manifest
                .blocks
                .iter()
                .find(|b| b.block_uuid == needle)
                .map(block_entry_to_summary)
        })
    }

    /// Drop the wrapped manifest now, zeroizing the IBK at exactly this
    /// moment. **Idempotent** — multiple calls do not panic.
    pub fn wipe(&self) {
        let _drop = lock_or_recover(&self.inner).take();
        // _drop goes out of scope here → OpenVaultManifestInner drops →
        // Sensitive<[u8; 32]> ZeroizeOnDrop runs on the IBK; ContactCard,
        // Manifest, ManifestFile drop in source order.
    }
}

/// Internal projection: `core::BlockEntry` → `BlockSummary` (drops
/// internal-only fields: `fingerprint`, `vector_clock_summary`, `suite_id`,
/// `unknown`).
fn block_entry_to_summary(b: &secretary_core::vault::BlockEntry) -> BlockSummary {
    BlockSummary {
        block_uuid: b.block_uuid,
        block_name: b.block_name.clone(),
        created_at_ms: b.created_at_ms,
        last_modified_ms: b.last_mod_ms,
        recipient_uuids: b.recipients.clone(),
    }
}

/// Open a vault folder using its master password. Reads `vault.toml`,
/// `identity.bundle.enc`, `manifest.cbor.enc`, and the owner contact card
/// from `folder`; performs full unlock + manifest decode + signature
/// verification. Returns two opaque handles: the live `UnlockedIdentity`
/// and the read-only `OpenVaultManifest`.
///
/// # Errors
///
/// Returns [`FfiVaultError`]; six possible variants. See module-level docs
/// on `crate::error` for the full surface.
pub fn open_vault_with_password(
    folder: &Path,
    password: &[u8],
) -> Result<OpenVaultOutput, FfiVaultError> {
    let pw = SecretBytes::new(password.to_vec());
    let core_out = secretary_core::vault::open_vault(folder, Unlocker::Password(&pw), None)?;
    Ok(split_core_open_vault(core_out))
    // pw drops here → SecretBytes ZeroizeOnDrop wipes our local copy.
    // The caller's foreign-side password buffer is THEIR concern.
}

/// Open a vault folder using its 24-word BIP-39 recovery phrase. Reads the
/// same set of files as [`open_vault_with_password`]. The mnemonic input is
/// UTF-8 bytes; the bridge runs `std::str::from_utf8` and surfaces
/// malformed-UTF-8 input as [`FfiVaultError::InvalidMnemonic`] with
/// `detail: "phrase contained invalid UTF-8"` — same shape as B.3a's
/// [`crate::open_with_recovery`].
///
/// # Errors
///
/// Returns [`FfiVaultError`]; six possible variants.
pub fn open_vault_with_recovery(
    folder: &Path,
    mnemonic_bytes: &[u8],
) -> Result<OpenVaultOutput, FfiVaultError> {
    let phrase =
        std::str::from_utf8(mnemonic_bytes).map_err(|_| FfiVaultError::InvalidMnemonic {
            detail: "phrase contained invalid UTF-8".to_string(),
        })?;
    let core_out = secretary_core::vault::open_vault(folder, Unlocker::Recovery(phrase), None)?;
    Ok(split_core_open_vault(core_out))
}

/// Split a `core::vault::OpenVault` into the two FFI handles.
///
/// `Sensitive<[u8; 32]>` does not implement `Clone`, so we copy the 32 raw
/// bytes out via `expose()` and mint a second `Sensitive` for the manifest
/// handle.  Both copies carry `ZeroizeOnDrop`; the intermediate stack array
/// is explicitly zeroized per `CLAUDE.md`'s stack-residue discipline.
fn split_core_open_vault(core_out: secretary_core::vault::OpenVault) -> OpenVaultOutput {
    let secretary_core::vault::OpenVault {
        identity_block_key,
        identity,
        owner_card,
        manifest,
        manifest_file,
    } = core_out;

    // Mint a second Sensitive copy for OpenVaultManifestInner.
    // identity_block_key.expose() returns &[u8; 32]; dereference copies the
    // 32-byte array onto the stack.  Sensitive::new moves that stack copy in,
    // but [u8; 32]: Copy so the stack slot is not cleared by the move.
    // Explicit zeroize per CLAUDE.md memory-hygiene-audit-internal §stack-residue.
    let mut ibk_bytes: [u8; 32] = *identity_block_key.expose();
    let ibk_for_manifest = Sensitive::new(ibk_bytes);
    ibk_bytes.zeroize();

    // UnlockedIdentity wraps the core unlock type (IBK + IdentityBundle).
    let unlocked_for_handle = secretary_core::unlock::UnlockedIdentity {
        identity_block_key,
        identity,
    };

    OpenVaultOutput {
        identity: UnlockedIdentity::new(unlocked_for_handle),
        manifest: OpenVaultManifest::new(OpenVaultManifestInner {
            identity_block_key: ibk_for_manifest,
            manifest,
            manifest_file,
            owner_card,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Path to the golden_vault_NNN folder. CARGO_MANIFEST_DIR is
    /// ffi/secretary-ffi-bridge/, so we walk up to core/tests/data/.
    fn fixture_folder(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../core/tests/data")
            .join(name)
    }

    /// Pinned password for golden_vault_001. Same KAT used by unlock.rs.
    const VAULT_001_PASSWORD: &[u8] = b"correct horse battery staple";
    /// Pinned password for golden_vault_002. Read from
    /// core/tests/data/golden_vault_002_inputs.json — adjust if that JSON
    /// changes. Unused in vault.rs tests today; kept for reference.
    #[allow(dead_code)]
    const VAULT_002_PASSWORD: &[u8] = b"correct horse battery staple two";
    /// Pinned BIP-39 phrases (parallel to unlock.rs). Source of truth:
    /// the `recovery_mnemonic_phrase` field in each fixture's inputs JSON,
    /// kept honest by the fixture builder's drift-detection assertion.
    const VAULT_001_PHRASE: &[u8] = b"wall annual clay zebra cost cricket choose light small neck mimic season fix situate love asset dismiss online island disease turkey grab dish that";
    const VAULT_002_PHRASE: &[u8] = b"debate pride tunnel elder caution media glass joke that rabbit mean write eager across furnace volume lawn cage decline fat path guess slogan hunt";

    const VAULT_001_OWNER_DISPLAY_NAME: &str = "Owner";
    const VAULT_001_OWNER_USER_UUID: &[u8] = &[
        0xbf, 0x08, 0xa3, 0x30, 0x0c, 0xd9, 0x94, 0xb8, 0x77, 0xe1, 0xa1, 0x5b, 0xaa, 0x28, 0xdf,
        0x35,
    ];

    #[test]
    fn open_vault_with_password_success_returns_two_handles() {
        let folder = fixture_folder("golden_vault_001");
        let out = open_vault_with_password(&folder, VAULT_001_PASSWORD)
            .expect("open should succeed against golden_vault_001");
        assert_eq!(out.identity.display_name(), VAULT_001_OWNER_DISPLAY_NAME);
        assert_eq!(out.identity.user_uuid(), VAULT_001_OWNER_USER_UUID);
        assert_eq!(
            out.manifest.owner_user_uuid(),
            VAULT_001_OWNER_USER_UUID,
            "manifest's owner_user_uuid must agree with identity's user_uuid",
        );
    }

    #[test]
    fn open_vault_with_recovery_success_matches_password_path() {
        let folder = fixture_folder("golden_vault_001");
        let out = open_vault_with_recovery(&folder, VAULT_001_PHRASE)
            .expect("recovery open should succeed against golden_vault_001");
        // Both unlock paths must converge on byte-identical secret state
        // (§3/§4 dual-KEK design), so identity values match the password
        // path's results in the previous test.
        assert_eq!(out.identity.display_name(), VAULT_001_OWNER_DISPLAY_NAME);
        assert_eq!(out.identity.user_uuid(), VAULT_001_OWNER_USER_UUID);
    }

    #[test]
    fn open_vault_with_password_wrong_password_returns_thinned_error() {
        let folder = fixture_folder("golden_vault_001");
        let err = open_vault_with_password(&folder, b"definitely the wrong password").unwrap_err();
        assert!(
            matches!(err, FfiVaultError::WrongPasswordOrCorrupt),
            "expected WrongPasswordOrCorrupt, got {err:?}",
        );
    }

    #[test]
    fn open_vault_with_recovery_wrong_phrase_returns_thinned_error() {
        let folder = fixture_folder("golden_vault_001");
        // Use vault_002's phrase against vault_001's folder — valid 24-word
        // phrase but wrong vault, so recovery_kek decap tag-fails.
        let err = open_vault_with_recovery(&folder, VAULT_002_PHRASE).unwrap_err();
        assert!(
            matches!(err, FfiVaultError::WrongMnemonicOrCorrupt),
            "expected WrongMnemonicOrCorrupt, got {err:?}",
        );
    }

    #[test]
    fn open_vault_with_recovery_invalid_phrase_returns_invalid_mnemonic() {
        let folder = fixture_folder("golden_vault_001");
        let err = open_vault_with_recovery(&folder, b"only three words").unwrap_err();
        let FfiVaultError::InvalidMnemonic { detail } = err else {
            panic!("expected InvalidMnemonic, got {err:?}");
        };
        assert!(
            detail.contains("got 3"),
            "detail did not carry word count: {detail}",
        );
    }

    #[test]
    fn open_vault_folder_does_not_exist_returns_folder_invalid() {
        let folder = fixture_folder("__nonexistent_folder_for_b4a_test__");
        let err = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap_err();
        let FfiVaultError::FolderInvalid { detail } = err else {
            panic!("expected FolderInvalid, got {err:?}");
        };
        // detail carries IO context + io::Error display; either substring
        // is sufficient — the underlying io::ErrorKind is NotFound.
        assert!(
            detail.to_lowercase().contains("vault.toml")
                || detail.to_lowercase().contains("no such file"),
            "FolderInvalid detail did not carry expected text: {detail}",
        );
    }

    #[test]
    fn open_vault_folder_missing_identity_bundle_returns_folder_invalid() {
        // Set up a temp folder containing only vault.toml from
        // golden_vault_001. The bridge / core open path reads vault.toml
        // first then identity.bundle.enc; we want the second read to
        // surface as FolderInvalid.
        use std::fs;
        let src = fixture_folder("golden_vault_001");
        let tmp = tempfile::TempDir::new().expect("tempdir");
        fs::copy(src.join("vault.toml"), tmp.path().join("vault.toml")).unwrap();
        // Deliberately do NOT copy identity.bundle.enc.

        let err = open_vault_with_password(tmp.path(), VAULT_001_PASSWORD).unwrap_err();
        let FfiVaultError::FolderInvalid { detail } = err else {
            panic!("expected FolderInvalid, got {err:?}");
        };
        assert!(
            detail.contains("identity.bundle.enc"),
            "FolderInvalid detail did not mention identity.bundle.enc: {detail}",
        );
    }

    #[test]
    fn block_summaries_returns_pinned_layout_for_v1() {
        // Pin the BlockSummary list against the golden_vault_001_inputs.json
        // `block_summaries` array. If this test fails, either the fixture
        // changed (re-pin the JSON via Task 2 Step 2's helper) or the
        // BlockSummary projection has drifted (fix block_entry_to_summary).
        let folder = fixture_folder("golden_vault_001");
        let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap();

        let summaries = out.manifest.block_summaries();
        let count = out.manifest.block_count();
        assert_eq!(
            summaries.len() as u64,
            count,
            "block_summaries() length must match block_count()",
        );

        // Read the pinned JSON for cross-checking.
        let json_path = fixture_folder("").join("golden_vault_001_inputs.json");
        let json_str = std::fs::read_to_string(&json_path).expect("inputs JSON");
        let pinned: serde_json::Value = serde_json::from_str(&json_str).expect("valid JSON");
        let pinned_summaries = pinned["block_summaries"]
            .as_array()
            .expect("block_summaries is an array — was Task 2 Step 3 completed?");

        assert_eq!(
            summaries.len(),
            pinned_summaries.len(),
            "BlockSummary count drift: code has {}, JSON pins {}",
            summaries.len(),
            pinned_summaries.len(),
        );

        for (actual, pinned) in summaries.iter().zip(pinned_summaries.iter()) {
            let pinned_uuid_hex = pinned["block_uuid"].as_str().expect("hex string");
            let actual_uuid_hex = hex::encode(actual.block_uuid);
            assert_eq!(actual_uuid_hex, pinned_uuid_hex, "block_uuid drift");
            assert_eq!(
                actual.block_name,
                pinned["block_name"].as_str().expect("string"),
                "block_name drift",
            );
            assert_eq!(
                actual.created_at_ms,
                pinned["created_at_ms"].as_u64().expect("u64"),
                "created_at_ms drift",
            );
            assert_eq!(
                actual.last_modified_ms,
                pinned["last_modified_ms"].as_u64().expect("u64"),
                "last_modified_ms drift",
            );
        }
    }

    #[test]
    fn open_vault_manifest_wipe_returns_empty_defaults() {
        let folder = fixture_folder("golden_vault_001");
        let out = open_vault_with_password(&folder, VAULT_001_PASSWORD).unwrap();
        out.manifest.wipe();
        // Post-wipe, every accessor returns the empty default. Same
        // contract as UnlockedIdentity post-close.
        assert_eq!(out.manifest.vault_uuid(), vec![0u8; 16]);
        assert_eq!(out.manifest.owner_user_uuid(), vec![0u8; 16]);
        assert_eq!(out.manifest.block_count(), 0);
        assert_eq!(out.manifest.block_summaries(), Vec::<BlockSummary>::new());
        assert_eq!(out.manifest.find_block(&[0u8; 16]), None);
        // Idempotent.
        out.manifest.wipe();
        out.manifest.wipe();
        assert_eq!(out.manifest.block_count(), 0);
    }
}
