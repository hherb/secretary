//! Conflict-copy ingestion for C.1.1a.
//!
//! Cloud-folder sync products (Dropbox, iCloud, Syncthing, …) emit
//! conflict-copy files alongside the canonical manifest and block
//! files when two devices write concurrently. This module enumerates
//! such siblings, authenticates each candidate against the canonical
//! owner identity (1a-D4's five MUST rules), and packages the
//! authenticated set into a [`crate::sync::VaultBundle`] for the
//! C.1.1b merge layer to consume.
//!
//! Authentication is the security boundary — filename patterns are
//! NOT trusted (a malicious cloud host can write anything). Files
//! that fail any MUST rule are silently dropped (logged at
//! `tracing::debug!` for diagnostics; not surfaced to the user).
//!
//! See `docs/superpowers/specs/2026-05-18-c1-1a-conflict-copy-ingestion-design.md`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::crypto::aead::{AeadKey, AEAD_TAG_LEN};
use crate::crypto::sig::{Ed25519Public, MlDsa65Public};
use crate::identity::fingerprint::Fingerprint;
use crate::sync::bundle::{BlockDivergence, BlockEnvelope, ManifestSnapshot, VaultBundle};
use crate::vault::block::VectorClockEntry;
use crate::vault::orchestrators::MANIFEST_FILENAME;
use crate::vault::{
    clock_relation, decode_block_file, decode_manifest_file, decrypt_manifest_body,
    verify_block_signature, verify_manifest, ClockRelation, Manifest,
};

/// Attempt to decode + authenticate one candidate manifest envelope
/// against the canonical owner identity. Returns `Some(snapshot)` if
/// ALL FIVE 1a-D4 MUST rules hold; returns `None` otherwise (callers
/// silently ignore, per spec).
///
/// The five MUSTs:
///   1. Bytes decode as a `ManifestFile` envelope (CBOR + magic).
///   2. §8 hybrid signature (Ed25519 ∧ ML-DSA-65) verifies under the
///      canonical owner's public keys.
///   3. The envelope's signed header carries the same `vault_uuid` as
///      the canonical manifest.
///   4. The envelope's `author_fingerprint` matches the canonical
///      owner's contact-card fingerprint.
///   5. AEAD-decrypts with the unlocked Identity Block Key.
///
/// Plus one defensive §4.3 cross-check (body's `vault_uuid` matches
/// the signed header's) carried forward from `read_and_verify_manifest`.
///
/// On any failure, returns `None` and emits a `tracing::debug!` line
/// for forensic diagnostics. "Silent ignore" is only safe because all
/// five MUSTs hold; weakening any of them would open a CRDT-merge
/// poisoning path (spec §1a-D4).
///
/// Pure function — performs no I/O, no environment access.
#[must_use]
pub(crate) fn authenticate_manifest_envelope(
    candidate_bytes: &[u8],
    candidate_source_path: PathBuf,
    expected_vault_uuid: [u8; 16],
    expected_author_fp: Fingerprint,
    owner_ed25519_pk: &Ed25519Public,
    owner_ml_dsa_65_pk: &MlDsa65Public,
    ibk: &AeadKey,
) -> Option<ManifestSnapshot> {
    // Rule 1: decode envelope.
    let envelope = match decode_manifest_file(candidate_bytes) {
        Ok(env) => env,
        Err(err) => {
            tracing::debug!(
                path = %candidate_source_path.display(),
                error = %err,
                "conflict-copy rejected: manifest decode failed"
            );
            return None;
        }
    };

    // Rule 3: vault_uuid in signed header must match canonical.
    if envelope.header.vault_uuid != expected_vault_uuid {
        tracing::debug!(
            path = %candidate_source_path.display(),
            "conflict-copy rejected: vault_uuid mismatch"
        );
        return None;
    }

    // Rule 4: author_fingerprint must match canonical's owner.
    if envelope.author_fingerprint != expected_author_fp {
        tracing::debug!(
            path = %candidate_source_path.display(),
            "conflict-copy rejected: author_fingerprint mismatch"
        );
        return None;
    }

    // Rule 2: hybrid Ed25519 ∧ ML-DSA-65 signature must verify under
    // the canonical owner's keys. The verify call returns Err on EITHER
    // half failing — there is no OR-short-circuit; both halves must
    // hold (CLAUDE.md / docs/crypto-design.md §8).
    if let Err(err) = verify_manifest(&envelope, owner_ed25519_pk, owner_ml_dsa_65_pk) {
        tracing::debug!(
            path = %candidate_source_path.display(),
            error = %err,
            "conflict-copy rejected: hybrid signature verification failed"
        );
        return None;
    }

    // Rule 5: AEAD-decrypt the body with the unlocked Identity Block
    // Key. The IBK is authenticated by the unlock flow that produced
    // it; success here proves the conflict-copy was written by an
    // identity that knew the IBK and that the body bytes haven't been
    // tampered post-write.
    let mut ct_with_tag = Vec::with_capacity(envelope.aead_ct.len() + AEAD_TAG_LEN);
    ct_with_tag.extend_from_slice(&envelope.aead_ct);
    ct_with_tag.extend_from_slice(&envelope.aead_tag);
    let body =
        match decrypt_manifest_body(&envelope.header, &ct_with_tag, ibk, &envelope.aead_nonce) {
            Ok(b) => b,
            Err(err) => {
                // NOT only AEAD: `decrypt_manifest_body` calls
                // `decode_manifest`, so as of #572/#573 this arm also fires
                // for `NonCanonicalEncoding`, `DuplicateKey`,
                // `VectorClockDuplicateDevice`, `WrongType` and
                // `MissingField` — a peer whose encoder emits an array out
                // of its §4.2 sort order lands here, not on a key problem.
                // The message named AEAD alone until the #584 review, which
                // would send an operator after key/nonce corruption for an
                // encoder bug. The specific cause is in `error`.
                tracing::debug!(
                    path = %candidate_source_path.display(),
                    error = %err,
                    "conflict-copy rejected: manifest body decrypt or decode failed"
                );
                return None;
            }
        };

    // Defensive §4.3 cross-check: body's vault_uuid matches the signed
    // header's. The AAD bind would already catch a header tamper, but
    // the body-level field is independent and worth a final eq.
    if body.vault_uuid != envelope.header.vault_uuid {
        tracing::debug!(
            path = %candidate_source_path.display(),
            "conflict-copy rejected: body.vault_uuid != header.vault_uuid"
        );
        return None;
    }

    Some(ManifestSnapshot {
        manifest: body,
        raw_envelope_bytes: candidate_bytes.to_vec(),
        source_path: candidate_source_path,
    })
}

/// Enumerate files in `folder` that are candidate manifest
/// conflict-copies — i.e. files whose name STARTS with the canonical
/// manifest filename (`manifest.cbor.enc`) and is not identical to
/// it. Returns sorted by path for deterministic test output.
///
/// I/O failure (folder missing, permission denied) returns the
/// wrapped `std::io::Error`. Per-entry failures (e.g. transient
/// read-dir hiccups on a symlink loop) are silently skipped so one
/// poison entry can't deny-of-service the whole scan.
///
/// The `starts_with(MANIFEST_FILENAME)` filter covers all observed
/// cloud-sync naming conventions: Dropbox
/// `manifest.cbor.enc (conflicted copy …)`, iCloud
/// `manifest.cbor.enc 2`, Syncthing
/// `manifest.cbor.enc.sync-conflict-…`, etc. The filter is the
/// heuristic discovery hook — authentication is the security
/// boundary (spec §1a-D3).
pub(crate) fn enumerate_manifest_siblings(folder: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut out: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(folder)? {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };
        if name == MANIFEST_FILENAME {
            continue;
        }
        if !name.starts_with(MANIFEST_FILENAME) {
            continue;
        }
        out.push(path);
    }
    out.sort();
    Ok(out)
}

/// DoS bound for one candidate manifest envelope. Real-world
/// manifests on `golden_vault_001` are KB-scale; this 1 MiB ceiling
/// is ~1000× slack. Any file above this limit is silently skipped at
/// the scan layer — a malicious cloud-folder host can't pivot a
/// gigabyte file into the decoder.
const MAX_MANIFEST_SIZE: usize = 1024 * 1024;

/// DoS bound for one candidate block envelope. Block files carry
/// AEAD-encrypted record payloads plus a per-recipient KEM wrap
/// table; the 16 MiB ceiling is well above any reasonable single
/// block (record payloads are bounded by the §6 record schema; the
/// recipient table is capped at `u16::MAX` entries). Same rationale
/// as [`MAX_MANIFEST_SIZE`] — silent skip pre-decode.
const MAX_BLOCK_FILE_SIZE: usize = 16 * 1024 * 1024;

/// Compose [`enumerate_manifest_siblings`] +
/// [`authenticate_manifest_envelope`]: scan the vault folder for
/// sibling manifest files and return only those that authenticate.
///
/// Read I/O on individual sibling files is downgraded to a debug log
/// rather than a hard error so one un-readable entry can't fail the
/// whole scan. The initial `read_dir` failure IS propagated — a
/// missing folder is a programmer/integration error, not a runtime
/// silent-reject case.
///
/// Per-file authentication failures are silently dropped (spec
/// §1a-D3). The "silently ignore" disposition is only safe because
/// `authenticate_manifest_envelope` enforces all five §1a-D4 MUSTs.
pub(crate) fn ingest_manifest_copies(
    folder: &Path,
    canonical_vault_uuid: [u8; 16],
    canonical_owner_fp: Fingerprint,
    owner_ed25519_pk: &Ed25519Public,
    owner_ml_dsa_65_pk: &MlDsa65Public,
    ibk: &AeadKey,
) -> Result<Vec<ManifestSnapshot>, std::io::Error> {
    let sibling_paths = enumerate_manifest_siblings(folder)?;
    let mut copies: Vec<ManifestSnapshot> = Vec::with_capacity(sibling_paths.len());

    for path in sibling_paths {
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(err) => {
                tracing::debug!(
                    path = %path.display(),
                    error = %err,
                    "conflict-copy skipped: read error"
                );
                continue;
            }
        };
        if bytes.is_empty() || bytes.len() > MAX_MANIFEST_SIZE {
            tracing::debug!(
                path = %path.display(),
                size = bytes.len(),
                "conflict-copy skipped: size out of bounds"
            );
            continue;
        }
        if let Some(snapshot) = authenticate_manifest_envelope(
            &bytes,
            path.clone(),
            canonical_vault_uuid,
            canonical_owner_fp,
            owner_ed25519_pk,
            owner_ml_dsa_65_pk,
            ibk,
        ) {
            copies.push(snapshot);
        }
    }
    Ok(copies)
}

/// Attempt to decode + authenticate one candidate block envelope
/// against the canonical owner identity. Returns `Some(envelope)` if
/// ALL THREE block-side MUST rules hold; returns `None` otherwise.
///
/// Block-side authentication reduces to three MUSTs (vs. five for
/// manifests) — the manifest layer's vault_uuid binding and AEAD
/// decrypt are inherited transitively: a block_uuid only enters the
/// ingestion pipeline because its parent manifest already
/// authenticated and named it as a divergent block. The three
/// block-side rules:
///
///   1. Bytes decode as a `BlockFile` envelope.
///   2. The envelope's `author_fingerprint` matches the canonical
///      vault owner.
///   3. §8 hybrid Ed25519 ∧ ML-DSA-65 signature verifies under the
///      canonical owner's public keys.
///
/// The encrypted body is held verbatim inside [`BlockEnvelope.bytes`]
/// — C.1.1b's `prepare_merge` is responsible for AEAD-decrypting on
/// demand. Pure function — performs no I/O.
#[must_use]
pub(crate) fn authenticate_block_envelope(
    candidate_bytes: &[u8],
    candidate_source_path: PathBuf,
    expected_author_fp: Fingerprint,
    owner_ed25519_pk: &Ed25519Public,
    owner_ml_dsa_65_pk: &MlDsa65Public,
) -> Option<BlockEnvelope> {
    // Rule 1: decode envelope.
    let block_file = match decode_block_file(candidate_bytes) {
        Ok(bf) => bf,
        Err(err) => {
            tracing::debug!(
                path = %candidate_source_path.display(),
                error = %err,
                "block conflict-copy rejected: decode failed"
            );
            return None;
        }
    };

    // Rule 2: author_fingerprint matches canonical owner.
    if block_file.author_fingerprint != expected_author_fp {
        tracing::debug!(
            path = %candidate_source_path.display(),
            "block conflict-copy rejected: author_fingerprint mismatch"
        );
        return None;
    }

    // Rule 3: §8 hybrid signature verifies. verify_block_signature
    // returns Err on EITHER Ed25519 or ML-DSA-65 half failing.
    if let Err(err) = verify_block_signature(&block_file, owner_ed25519_pk, owner_ml_dsa_65_pk) {
        tracing::debug!(
            path = %candidate_source_path.display(),
            error = %err,
            "block conflict-copy rejected: hybrid signature verification failed"
        );
        return None;
    }

    Some(BlockEnvelope {
        bytes: candidate_bytes.to_vec(),
        source_path: candidate_source_path,
    })
}

/// For each block_uuid present in the canonical manifest, determine
/// whether any authenticated conflict-copy manifest carries a
/// divergent `vector_clock_summary` for the same block. If yes, read
/// the canonical block envelope, scan + authenticate sibling block
/// files for that block_uuid, and emit a [`BlockDivergence`].
///
/// "Divergent" means [`clock_relation`] returns anything other than
/// [`ClockRelation::Equal`] or [`ClockRelation::IncomingDominated`] —
/// i.e. either the copy strictly dominates (the copy has newer
/// per-device state that the canonical lacks), or the two are
/// concurrent (divergent histories). Non-divergent blocks are absent
/// from the returned map.
///
/// A block a copy lists and the canonical manifest lists in neither
/// `blocks` nor `trash` is new to this device and diverges too
/// (crypto-design §11.7): its own file is read, authenticated, as the
/// canonical envelope (see `new_blocks`).
///
/// I/O errors during the canonical-block read are downgraded to a
/// `tracing::warn!` and the block is skipped — a corrupt or missing
/// canonical block file is recoverable by skipping divergence for
/// that block (the C.1.1b merge layer handles fully-missing blocks
/// in its own pass). I/O errors during sibling enumeration ARE
/// propagated because they indicate a folder-level problem.
pub(crate) fn ingest_block_divergence(
    folder: &Path,
    canonical: &Manifest,
    copies: &[ManifestSnapshot],
    canonical_owner_fp: Fingerprint,
    owner_ed25519_pk: &Ed25519Public,
    owner_ml_dsa_65_pk: &MlDsa65Public,
) -> Result<BTreeMap<[u8; 16], BlockDivergence>, std::io::Error> {
    let mut out: BTreeMap<[u8; 16], BlockDivergence> = BTreeMap::new();

    for canonical_entry in &canonical.blocks {
        let block_uuid = canonical_entry.block_uuid;

        let mut diverges = false;
        for copy in copies {
            let copy_entry = match copy
                .manifest
                .blocks
                .iter()
                .find(|e| e.block_uuid == block_uuid)
            {
                Some(e) => e,
                None => continue,
            };
            if copy_version_is_uncovered(
                &canonical_entry.vector_clock_summary,
                &copy_entry.vector_clock_summary,
            ) {
                diverges = true;
                break;
            }
        }
        if !diverges {
            continue;
        }

        let canonical_block_path = canonical_block_path(folder, &block_uuid);
        let canonical_bytes = match std::fs::read(&canonical_block_path) {
            Ok(b) => b,
            Err(err) => {
                tracing::warn!(
                    path = %canonical_block_path.display(),
                    error = %err,
                    "canonical block file unreadable; skipping divergence ingest for this uuid"
                );
                continue;
            }
        };
        let canonical_envelope = BlockEnvelope {
            bytes: canonical_bytes,
            source_path: canonical_block_path,
        };

        let copy_envelopes = read_sibling_envelopes(
            folder,
            &block_uuid,
            canonical_owner_fp,
            owner_ed25519_pk,
            owner_ml_dsa_65_pk,
        )?;

        out.insert(
            block_uuid,
            BlockDivergence {
                canonical_envelope,
                copy_envelopes,
            },
        );
    }

    new_blocks::ingest_new_blocks(
        folder,
        canonical,
        copies,
        canonical_owner_fp,
        owner_ed25519_pk,
        owner_ml_dsa_65_pk,
        &mut out,
    )?;
    Ok(out)
}

/// Whether a copy's version of a block, at `copy_clock`, holds content the
/// canonical version at `canonical_clock` does not: true unless the two
/// clocks are equal or the canonical one dominates. A block diverges iff
/// some copy's version is uncovered, and a merge must read every uncovered
/// version (#781).
#[must_use]
pub(crate) fn copy_version_is_uncovered(
    canonical_clock: &[VectorClockEntry],
    copy_clock: &[VectorClockEntry],
) -> bool {
    !matches!(
        clock_relation(canonical_clock, copy_clock),
        ClockRelation::Equal | ClockRelation::IncomingDominated
    )
}

/// Extract sorted block UUIDs from the bundle's `diverging_blocks`
/// map — the set of blocks that need merging in C.1.1b's
/// `prepare_merge`. Pure function over the `BTreeMap` keys; the order
/// is already canonical-ascending because `BTreeMap::keys()` iterates
/// in sort order.
#[must_use]
pub(crate) fn compute_diff_plan(bundle: &VaultBundle) -> Vec<[u8; 16]> {
    bundle.diverging_blocks.keys().copied().collect()
}

/// Top-level conflict-copy ingestion: assemble a [`VaultBundle`] from
/// a vault folder plus a canonical (already-authenticated) manifest.
/// Called by [`crate::sync::sync_once`] only on the Concurrent
/// dispatch path. Returns canonical + 0..N authenticated copies +
/// per-block divergence in one structure.
///
/// All five §1a-D4 MUSTs run inside the manifest-level + block-level
/// authenticators; per-file failures silently drop (spec §1a-D3).
/// I/O errors at the folder-scan level propagate.
///
/// The argument count exceeds the default clippy limit; the
/// `#[allow(clippy::too_many_arguments)]` is justified because every
/// argument is independent pre-derived input (folder, manifest body,
/// envelope bytes, source path, owner fp, owner ed pk, owner pq pk,
/// IBK) and bundling them into an opaque context struct would just
/// move the complexity behind a single import.
#[allow(clippy::too_many_arguments)]
pub(crate) fn ingest_conflict_copies(
    folder: &Path,
    canonical: &Manifest,
    canonical_envelope_bytes: &[u8],
    canonical_source_path: PathBuf,
    canonical_owner_fp: Fingerprint,
    owner_ed25519_pk: &Ed25519Public,
    owner_ml_dsa_65_pk: &MlDsa65Public,
    ibk: &AeadKey,
) -> Result<VaultBundle, std::io::Error> {
    let copies = ingest_manifest_copies(
        folder,
        canonical.vault_uuid,
        canonical_owner_fp,
        owner_ed25519_pk,
        owner_ml_dsa_65_pk,
        ibk,
    )?;

    let diverging_blocks = ingest_block_divergence(
        folder,
        canonical,
        &copies,
        canonical_owner_fp,
        owner_ed25519_pk,
        owner_ml_dsa_65_pk,
    )?;

    Ok(VaultBundle {
        canonical: ManifestSnapshot {
            manifest: canonical.clone(),
            raw_envelope_bytes: canonical_envelope_bytes.to_vec(),
            source_path: canonical_source_path,
        },
        copies,
        diverging_blocks,
    })
}

/// Enumerate sibling files for `blocks/<uuid>.cbor.enc` in `folder`
/// — any file in the blocks subdirectory whose name starts with the
/// hyphenated UUID + `.cbor.enc` and is NOT exactly the canonical
/// filename. Returns sorted by path.
///
/// Reuses [`crate::vault::orchestrators::format_uuid_hyphenated`] +
/// [`crate::vault::orchestrators::BLOCKS_SUBDIR`] so the canonical
/// filename format stays pinned to the same source of truth as
/// `save_block` writes (vault-format.md §1).
///
/// Returns `Ok(Vec::new())` if the blocks subdirectory doesn't exist
/// (a fresh vault with no blocks yet is a legitimate state).
pub(crate) fn enumerate_block_siblings(
    folder: &Path,
    block_uuid: &[u8; 16],
) -> Result<Vec<PathBuf>, std::io::Error> {
    let canonical_stem = crate::vault::orchestrators::format_uuid_hyphenated(block_uuid)
        + crate::vault::orchestrators::BLOCK_FILE_EXTENSION;
    let blocks_dir = folder.join(crate::vault::orchestrators::BLOCKS_SUBDIR);

    if !blocks_dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut out: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(&blocks_dir)? {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };
        if name == canonical_stem {
            continue;
        }
        if !name.starts_with(&canonical_stem) {
            continue;
        }
        out.push(path);
    }
    out.sort();
    Ok(out)
}

mod block_files;
mod new_blocks;
use block_files::{canonical_block_path, read_sibling_envelopes};
pub(crate) use new_blocks::blocks_new_to_canonical;

#[cfg(test)]
mod tests;
