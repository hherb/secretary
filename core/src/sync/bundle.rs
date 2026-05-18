//! Authenticated bundle of the canonical vault manifest plus any
//! conflict-copy siblings, produced by `sync_once` on the Concurrent
//! dispatch arm. C.1.1b's merge layer consumes this bundle.
//!
//! See `docs/superpowers/specs/2026-05-18-c1-1a-conflict-copy-ingestion-design.md`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::vault::Manifest;

/// BLAKE3-256 hash of the on-disk canonical manifest envelope bytes.
///
/// Carried into [`crate::sync::SyncOutcome::ConcurrentDetected`] so the
/// C.1.1b commit path can detect a manifest-changed-between-prepare-
/// and-commit race (a TOCTOU close on the canonical manifest). Not a
/// secret value — pure positional identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestHash(pub [u8; 32]);

/// One side of a manifest — canonical or a single authenticated
/// conflict-copy. Holds the AEAD-decrypted body and the raw envelope
/// bytes; the latter is the freshness anchor for [`ManifestHash`] and
/// for per-copy hash diagnostics.
///
/// Zeroize semantics: the `raw_envelope_bytes` field is zeroized on
/// drop as defense-in-depth (the bytes are AEAD ciphertext plus
/// signatures and envelope framing — not secret per se, but cheap to
/// wipe). The `manifest` body field is `#[zeroize(skip)]` because
/// [`Manifest`] does not derive `Zeroize`; it holds structured
/// metadata (vector clocks, block summaries, trash entries) that is
/// not secret material, matching the precedent of
/// `crate::vault::OpenVault::manifest`. The `source_path` field is
/// also skipped — file paths are diagnostic, not secrets.
#[derive(Debug, Clone, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct ManifestSnapshot {
    #[zeroize(skip)]
    pub manifest: Manifest,
    pub raw_envelope_bytes: Vec<u8>,
    #[zeroize(skip)]
    pub source_path: PathBuf,
}

/// Encrypted bytes of one block file (canonical or conflict-copy).
///
/// Block content remains sealed inside the bundle — C.1.1b's
/// `prepare_merge` is responsible for AEAD-decrypting on demand. The
/// envelope bytes are still zeroized on drop as defense-in-depth: a
/// ciphertext is not plaintext, but key+nonce+ciphertext recovery
/// would be a more dangerous corpus to leak than necessary.
#[derive(Debug, Clone, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct BlockEnvelope {
    pub bytes: Vec<u8>,
    #[zeroize(skip)]
    pub source_path: PathBuf,
}

/// Authenticated conflict-copies for one block_uuid.
///
/// Only populated for blocks whose `vector_clock_summary` differs
/// between the canonical manifest and at least one conflict-copy
/// manifest. Blocks that aren't in this map are not in conflict and
/// the canonical envelope is the authoritative value.
#[derive(Debug, Clone, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct BlockDivergence {
    pub canonical_envelope: BlockEnvelope,
    pub copy_envelopes: Vec<BlockEnvelope>,
}

/// Top-level ingestion product. See spec §"Public API → `VaultBundle`".
///
/// Keyed by `block_uuid` (16 bytes). The `Zeroize` derive on the
/// outer struct works because every transitively-held field either
/// derives `Zeroize` or is annotated with `#[zeroize(skip)]`. The
/// `BTreeMap` field is skipped because the `zeroize` crate does not
/// provide a blanket `Zeroize` impl for `BTreeMap`; each
/// `BlockDivergence` value is independently zeroized on drop via its
/// own `ZeroizeOnDrop` impl when the map drops.
#[derive(Debug, Clone, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct VaultBundle {
    pub canonical: ManifestSnapshot,
    pub copies: Vec<ManifestSnapshot>,
    #[zeroize(skip)]
    pub diverging_blocks: BTreeMap<[u8; 16], BlockDivergence>,
}

/// Compute the BLAKE3-256 hash of the canonical manifest envelope
/// bytes. Used as the freshness anchor in
/// [`crate::sync::SyncOutcome::ConcurrentDetected`] so C.1.1b's
/// `commit_with_decisions` can verify the manifest hasn't changed
/// between prepare and commit (TOCTOU close).
///
/// Pure function. Inputs the on-disk envelope bytes exactly as read
/// (no canonicalisation); output is 32 bytes.
#[must_use]
pub fn compute_manifest_hash(envelope_bytes: &[u8]) -> ManifestHash {
    let digest = crate::crypto::hash::hash(envelope_bytes);
    ManifestHash(*digest.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_hash_eq_is_bytewise() {
        let a = ManifestHash([0x42; 32]);
        let b = ManifestHash([0x42; 32]);
        let c = ManifestHash([0x43; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn block_envelope_zeroize_clears_bytes() {
        let mut envelope = BlockEnvelope {
            bytes: vec![0xAB; 64],
            source_path: PathBuf::from("/tmp/block.cbor.enc"),
        };
        assert_eq!(envelope.bytes[0], 0xAB);
        envelope.zeroize();
        assert!(envelope.bytes.iter().all(|&b| b == 0), "bytes not zeroized");
    }

    #[test]
    fn compute_manifest_hash_matches_blake3_of_input_bytes() {
        let bytes = b"the quick brown fox jumps over the lazy dog";
        let got = compute_manifest_hash(bytes);
        let expected = crate::crypto::hash::hash(bytes);
        assert_eq!(got.0, *expected.as_bytes());
    }

    #[test]
    fn compute_manifest_hash_empty_input() {
        let got = compute_manifest_hash(b"");
        let expected = crate::crypto::hash::hash(b"");
        assert_eq!(got.0, *expected.as_bytes());
    }
}
