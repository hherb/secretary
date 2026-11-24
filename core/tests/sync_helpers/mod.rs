//! Per-test temp-folder copies of golden_vault_001 with the manifest's
//! vector clock re-written to caller-supplied value(s). Used by the
//! end-to-end sync_once tests in sync.rs (single-manifest fixtures) and
//! the C.1.1a conflict-copy ingestion tests (N-manifest fixtures) so
//! each test asserts a specific outcome against the real open_vault
//! path.
//!
//! All multi-manifest helpers use distinct per-run random AEAD nonces per
//! envelope so the AEAD uniqueness invariant (never share key + nonce
//! across rewrites) holds even within a single tempdir. See the
//! "Atomic-write contract" section of CLAUDE.md for the rationale.
//!
//! The helpers live in submodules (#95) and are re-exported here by glob,
//! so a test binary still names each one as `sync_helpers::<item>`. The three
//! private items several submodules share are `pub(super)`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use rand::RngCore;
use secretary_core::crypto::secret::{SecretString, Sensitive};
use secretary_core::crypto::sig::{Ed25519Secret, MlDsa65Secret};
use secretary_core::identity::fingerprint::fingerprint;
use secretary_core::vault::{
    encode_manifest_file, open_vault, sign_manifest, ManifestHeader, Record, RecordField,
    RecordFieldValue, Unlocker, VectorClockEntry,
};
use zeroize::Zeroize as _;

use crate::fixtures;

const GOLDEN_VAULT_FOLDER: &str = "tests/data/golden_vault_001";
pub const MANIFEST_FILENAME: &str = "manifest.cbor.enc";

/// The merging device tests pass to `prepare_merge` when the test is not
/// about which device merges (#744). Distinct from every fixture device.
#[allow(dead_code)]
pub const TEST_MERGING_DEVICE: [u8; 16] = [0x5E; 16];
const AEAD_NONCE_LEN: usize = 24;

mod block;
mod block_encrypt;
mod block_manifest;
mod block_siblings;
mod concurrent_blocks;
mod manifests;
mod nonces;

pub use block::*;
pub use block_encrypt::*;
pub use block_manifest::*;
pub use block_siblings::*;
pub use concurrent_blocks::*;
pub use manifests::*;
pub use nonces::*;

#[cfg(test)]
mod helper_tests;
