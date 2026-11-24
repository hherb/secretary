//! Per-run random AEAD nonces and rewrite seeds shared by every fixture.

use super::*;

/// Test-only source of a fresh, per-run random 24-byte value used below as an
/// AEAD nonce or a ChaCha20Rng rewrite-seed. Replaces the former hard-coded
/// byte-array literals: CodeQL's `rust/hard-coded-cryptographic-value`
/// (correctly) flags literal nonces, and these fixtures only require each value
/// to be *valid and mutually distinct* — never a fixed known-answer — which a
/// CSPRNG draw guarantees (collision probability 2^-192). Per the
/// `feedback_test_crypto_random_not_hardcoded` convention. Each `LazyLock` below
/// is drawn once per test process, so every reference to a given name observes
/// the same bytes within a run (preserving the old `const`'s single-value
/// semantics) while differing from every other name and from run to run.
fn rand_nonce() -> [u8; AEAD_NONCE_LEN] {
    let mut n = [0u8; AEAD_NONCE_LEN];
    rand::rng().fill_bytes(&mut n);
    n
}

/// Nonce for the canonical manifest written by helpers in this module. Tests
/// don't share AEAD key + nonce pairs across rewrites (see [`rand_nonce`]).
pub static CANONICAL_NONCE_A: LazyLock<[u8; AEAD_NONCE_LEN]> = LazyLock::new(rand_nonce);

/// Nonce for the first sibling manifest — distinct from [`CANONICAL_NONCE_A`]
/// so accidental nonce reuse can't hide in test failures (see [`rand_nonce`]).
pub static SIBLING_NONCE_B: LazyLock<[u8; AEAD_NONCE_LEN]> = LazyLock::new(rand_nonce);

/// Nonce for the second sibling manifest in N-way fixtures. Consumed by
/// [`fresh_vault_four_concurrent_manifests`] in C.1.1a integration tests
/// and by [`add_concurrent_block_sibling`] (#751).
#[allow(dead_code)]
pub static SIBLING_NONCE_C: LazyLock<[u8; AEAD_NONCE_LEN]> = LazyLock::new(rand_nonce);

/// Nonce for the third sibling manifest in N-way fixtures. Consumed by
/// [`fresh_vault_four_concurrent_manifests`] in C.1.1a integration tests.
#[allow(dead_code)]
pub static SIBLING_NONCE_D: LazyLock<[u8; AEAD_NONCE_LEN]> = LazyLock::new(rand_nonce);

/// Rewrite-seed for the first block rewrite in C.1.1b fixtures. Consumed as the
/// seed for a deterministic [`rand_chacha::ChaCha20Rng`] inside
/// [`rewrite_block_with_records`], so each rewrite derives a distinct Block
/// Content Key AND a distinct on-disk AEAD body nonce — no key+nonce collision
/// when multiple blocks are rewritten in the same test (see the
/// `AEAD-uniqueness` rationale in the module-level docstring and CLAUDE.md's
/// atomic-write section).
#[allow(dead_code)]
pub static BLOCK_NONCE_E: LazyLock<[u8; AEAD_NONCE_LEN]> = LazyLock::new(rand_nonce);

/// Rewrite-seed for the second block rewrite in C.1.1b fixtures — sibling block
/// envelopes in conflict-copy ingestion tests. Same ChaCha20Rng-seed semantics
/// as [`BLOCK_NONCE_E`], and distinct from it (see [`rand_nonce`]).
#[allow(dead_code)]
pub static BLOCK_NONCE_F: LazyLock<[u8; AEAD_NONCE_LEN]> = LazyLock::new(rand_nonce);

/// Rewrite-seed for a second sibling block envelope, written by
/// [`add_concurrent_block_sibling`] (#751). Same semantics as
/// [`BLOCK_NONCE_E`], and distinct from E and F (see [`rand_nonce`]).
#[allow(dead_code)]
pub static BLOCK_NONCE_G: LazyLock<[u8; AEAD_NONCE_LEN]> = LazyLock::new(rand_nonce);
