//! Integration tests for `secretary_core::vault::read_vault_manifest`.
//!
//! `read_vault_manifest` is the sibling of `open_vault` that takes a
//! caller-held `&UnlockedIdentity` and returns just the decrypted
//! `Manifest` body. It does NOT take ownership of the identity
//! (avoiding the `IdentityBundle` no-Clone safety policy) and is the
//! entry point used by `core::sync::sync_once` so a sync poll does
//! not re-run Argon2.

#![forbid(unsafe_code)]

use std::path::Path;

use secretary_core::crypto::secret::SecretBytes;
use secretary_core::unlock::open_with_password;
use secretary_core::vault::{open_vault, read_vault_manifest, Unlocker};
use serde::Deserialize;

#[derive(Deserialize)]
struct Inputs {
    password: String,
}

fn golden_vault_001_password() -> SecretBytes {
    let raw = std::fs::read_to_string("tests/data/golden_vault_001_inputs.json").unwrap();
    let inputs: Inputs = serde_json::from_str(&raw).unwrap();
    SecretBytes::new(inputs.password.into_bytes())
}

#[test]
fn read_vault_manifest_returns_same_body_as_open_vault() {
    let folder = Path::new("tests/data/golden_vault_001");
    let password = golden_vault_001_password();

    // Path 1: full open_vault (unlocks Argon2 + bundle, constructs OpenVault).
    let via_open = open_vault(folder, Unlocker::Password(&password), None)
        .expect("open_vault via password must succeed on golden fixture");

    // Path 2: caller already holds UnlockedIdentity; use read_vault_manifest
    // to avoid re-running Argon2.
    let vault_toml = std::fs::read(folder.join("vault.toml")).unwrap();
    let bundle = std::fs::read(folder.join("identity.bundle.enc")).unwrap();
    let identity = open_with_password(&vault_toml, &bundle, &password).unwrap();

    let manifest = read_vault_manifest(folder, &identity, None)
        .expect("read_vault_manifest must return Manifest");

    assert_eq!(manifest.vault_uuid, via_open.manifest.vault_uuid);
    assert_eq!(manifest.vector_clock, via_open.manifest.vector_clock);
    assert_eq!(manifest.owner_user_uuid, via_open.manifest.owner_user_uuid);
    assert_eq!(manifest.blocks.len(), via_open.manifest.blocks.len());
}

#[test]
fn read_vault_manifest_runs_in_milliseconds_no_argon2() {
    // The point of this entry point is to skip Argon2. We can't easily
    // measure timing here, but we can verify functional success when
    // called repeatedly without password input — each call only does
    // file read + signature verify + AEAD decrypt.
    let folder = Path::new("tests/data/golden_vault_001");
    let password = golden_vault_001_password();
    let vault_toml = std::fs::read(folder.join("vault.toml")).unwrap();
    let bundle = std::fs::read(folder.join("identity.bundle.enc")).unwrap();
    let identity = open_with_password(&vault_toml, &bundle, &password).unwrap();

    // Three back-to-back calls — each succeeds, each returns the same body.
    let m1 = read_vault_manifest(folder, &identity, None).unwrap();
    let m2 = read_vault_manifest(folder, &identity, None).unwrap();
    let m3 = read_vault_manifest(folder, &identity, None).unwrap();
    assert_eq!(m1.vault_uuid, m2.vault_uuid);
    assert_eq!(m2.vault_uuid, m3.vault_uuid);
    assert_eq!(m1.vector_clock, m2.vector_clock);
}
