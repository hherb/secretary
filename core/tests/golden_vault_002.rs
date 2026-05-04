//! `golden_vault_002/` — sibling fixture for cross-vault FFI tests.
//!
//! Distinct vault_uuid + password from `golden_vault_001/`; otherwise built
//! by the same shared `common::fixture_builder` infrastructure. Used by
//! `secretary-ffi-bridge`'s integration tests and the foreign-side smoke
//! runners (Python pytest, Swift, Kotlin) to test the `VaultMismatch`
//! error path with a real second vault rather than a synthesized mutation.
//!
//! conformance.py intentionally stays at `golden_vault_001/` only — one
//! canonical fixture is sufficient for the spec-clean-room contract.
//! `golden_vault_002/` exists for FFI tests, not for spec verification.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

use secretary_core::unlock;

mod common;
use common::fixture_builder::{build_golden_vault, hex_encode, load_inputs};

// ---------------------------------------------------------------------------
// Vault-002-specific path helpers
// ---------------------------------------------------------------------------

fn fixture_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("data");
    p.push("golden_vault_002");
    p
}

fn inputs_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("data");
    p.push("golden_vault_002_inputs.json");
    p
}

// ---------------------------------------------------------------------------
// Generator: derive owner/alice/bob raw key bytes from pinned RNG seeds and
// dump as hex. Used ONCE (via `cargo test ... -- --ignored
// generate_golden_inputs_002 --nocapture`) to populate
// `golden_vault_002_inputs.json`.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "bootstrap helper; populate golden_vault_002_inputs.json via cargo test -- --ignored generate_golden_inputs_002 --nocapture"]
fn generate_golden_inputs_002() {
    fn dump(label: &str, seed: [u8; 32]) {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let display = match label {
            "owner" => "Owner-002",
            "alice" => "Alice-002",
            "bob" => "Bob-002",
            _ => "X-002",
        };
        let id = unlock::bundle::generate(display, 2_000_000_001_000, &mut rng);
        eprintln!("---- {label} ----");
        eprintln!("user_uuid:       {}", hex_encode(&id.user_uuid));
        eprintln!("x25519_sk:       {}", hex_encode(id.x25519_sk.expose()));
        eprintln!("x25519_pk:       {}", hex_encode(&id.x25519_pk));
        eprintln!("ml_kem_768_sk:   {}", hex_encode(id.ml_kem_768_sk.expose()));
        eprintln!("ml_kem_768_pk:   {}", hex_encode(&id.ml_kem_768_pk));
        eprintln!("ed25519_sk:      {}", hex_encode(id.ed25519_sk.expose()));
        eprintln!("ed25519_pk:      {}", hex_encode(&id.ed25519_pk));
        eprintln!("ml_dsa_65_seed:  {}", hex_encode(id.ml_dsa_65_sk.expose()));
        eprintln!("ml_dsa_65_pk:    {}", hex_encode(&id.ml_dsa_65_pk));
    }

    dump("owner", [0xB0; 32]);
    dump("alice", [0xB1; 32]);
    dump("bob", [0xB2; 32]);
}

// ---------------------------------------------------------------------------
// Materialize the on-disk fixture (run once after a deliberate format change)
// ---------------------------------------------------------------------------

#[test]
#[ignore = "writes fixture bytes to disk; run after a deliberate format change"]
fn materialize_golden_vault_002() {
    let inputs = load_inputs(&inputs_path());
    let files: BTreeMap<_, _> = build_golden_vault(&inputs);
    let root = fixture_root();
    for (rel, bytes) in &files {
        let abs = root.join(rel);
        if let Some(parent) = abs.parent() {
            std::fs::create_dir_all(parent).expect("mkdir");
        }
        std::fs::write(&abs, bytes).expect("write");
        eprintln!("wrote {} ({} bytes)", abs.display(), bytes.len());
    }
}

// ---------------------------------------------------------------------------
// Drift assertion: rebuild from JSON, compare to on-disk fixture
// ---------------------------------------------------------------------------

#[test]
fn golden_vault_002_pinned() {
    let inputs = load_inputs(&inputs_path());
    let freshly_built: BTreeMap<_, _> = build_golden_vault(&inputs);
    let root = fixture_root();
    for (rel, expected) in &freshly_built {
        let abs = root.join(rel);
        let on_disk = std::fs::read(&abs).unwrap_or_else(|e| panic!("read {abs:?}: {e}"));
        assert_eq!(
            &on_disk, expected,
            "fixture file diverged from rebuilt bytes: {abs:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Bootstrap dumper: prints freshly-built hex per file. Never auto-overwrites.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "diagnostic helper; dumps freshly-built bytes to stderr on drift"]
fn golden_vault_002_bootstrap_dump() {
    let inputs = load_inputs(&inputs_path());
    let files: BTreeMap<_, _> = build_golden_vault(&inputs);
    for (rel, bytes) in &files {
        eprintln!("---- {rel:?} ({} bytes) ----", bytes.len());
        eprintln!("{}", hex_encode(bytes));
    }
}

// ---------------------------------------------------------------------------
// End-to-end unlock: validity gate
// ---------------------------------------------------------------------------

#[test]
fn golden_vault_002_opens_with_password() {
    let inputs = load_inputs(&inputs_path());
    let root = fixture_root();
    let vault_toml = std::fs::read(root.join("vault.toml")).expect("read vault.toml");
    let bundle = std::fs::read(root.join("identity.bundle.enc")).expect("read bundle");
    let password = secretary_core::crypto::secret::SecretBytes::new(
        inputs.password.as_bytes().to_vec(),
    );
    let unlocked = unlock::open_with_password(&vault_toml, &bundle, &password)
        .expect("open_with_password golden_vault_002");
    assert_eq!(
        unlocked.identity.display_name, "Owner-002",
        "vault_002 owner display_name mismatch",
    );
}

// ---------------------------------------------------------------------------
// Cross-vault mismatch: pairing vault_002's bundle with vault_001's toml
// must produce VaultMismatch (not WrongPasswordOrCorrupt or panic).
// ---------------------------------------------------------------------------

#[test]
fn golden_vault_002_cross_vault_mismatch() {
    use secretary_core::unlock::UnlockError;

    let root_002 = fixture_root();
    let root_001 = {
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.push("tests");
        p.push("data");
        p.push("golden_vault_001");
        p
    };

    // vault_001's vault.toml + vault_002's identity.bundle.enc → VaultMismatch
    let vault_toml_001 = std::fs::read(root_001.join("vault.toml")).expect("read vault_001 vault.toml");
    let bundle_002 = std::fs::read(root_002.join("identity.bundle.enc")).expect("read vault_002 bundle");
    let inputs_002 = load_inputs(&inputs_path());
    let password_002 = secretary_core::crypto::secret::SecretBytes::new(
        inputs_002.password.as_bytes().to_vec(),
    );

    let err = unlock::open_with_password(&vault_toml_001, &bundle_002, &password_002)
        .expect_err("cross-vault pair must fail");
    assert!(
        matches!(err, UnlockError::VaultMismatch),
        "expected VaultMismatch, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Verify path helper functions compile and don't regress
// ---------------------------------------------------------------------------

#[allow(dead_code)]
fn _verify_path_helpers(_p: &Path) {}
