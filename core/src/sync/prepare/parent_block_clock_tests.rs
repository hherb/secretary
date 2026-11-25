//! Unit tests for `parent_block_clock` — proves the
//! fingerprint-matching pairing is sound across the cases that
//! positional-index pairing got wrong: copies missing this block,
//! copies referencing a different envelope for the same block_uuid,
//! and the orphan-envelope structural error.

use super::parent_block_clock;
use crate::crypto::hash::hash as blake3_hash;
use crate::sync::bundle::ManifestSnapshot;
use crate::vault::block::VectorClockEntry;
use crate::vault::{BlockEntry, KdfParamsRef, Manifest};
use std::path::PathBuf;

/// Empty-on-everything Manifest; tests populate `blocks` per case.
pub(crate) fn empty_manifest() -> Manifest {
    Manifest {
        manifest_version: 1,
        vault_uuid: [0u8; 16],
        format_version: 1,
        suite_id: 1,
        owner_user_uuid: [0u8; 16],
        vector_clock: vec![],
        blocks: vec![],
        trash: vec![],
        kdf_params: KdfParamsRef {
            memory_kib: 262_144,
            iterations: 3,
            parallelism: 1,
            salt: [0u8; 32],
        },
        unknown: std::collections::BTreeMap::new(),
    }
}

/// Wrap a manifest in a ManifestSnapshot with placeholder envelope
/// bytes and source_path — `parent_block_clock` only inspects
/// `manifest.blocks`.
pub(crate) fn snapshot(manifest: Manifest) -> ManifestSnapshot {
    ManifestSnapshot {
        manifest,
        raw_envelope_bytes: vec![],
        source_path: PathBuf::from("/dev/null"),
    }
}

pub(crate) fn block_entry(
    block_uuid: [u8; 16],
    fp: [u8; 32],
    clock: Vec<VectorClockEntry>,
) -> BlockEntry {
    BlockEntry {
        block_uuid,
        block_name: String::new(),
        fingerprint: fp,
        recipients: vec![],
        vector_clock_summary: clock,
        suite_id: 1,
        created_at_ms: 0,
        last_mod_ms: 0,
        unknown: std::collections::BTreeMap::new(),
    }
}

const UUID_A: [u8; 16] = [0xAA; 16];
const UUID_B: [u8; 16] = [0xBB; 16];

#[test]
fn returns_matching_manifests_clock_when_single_copy_matches() {
    let envelope = b"envelope-bytes-for-uuid-a".to_vec();
    let fp = *blake3_hash(&envelope).as_bytes();
    let clock = vec![VectorClockEntry {
        device_uuid: [0x11; 16],
        counter: 7,
    }];

    let mut m = empty_manifest();
    m.blocks.push(block_entry(UUID_A, fp, clock.clone()));

    let copies = vec![snapshot(m)];
    let got = parent_block_clock(&envelope, &UUID_A, &copies).expect("expected clock");
    assert_eq!(got, clock);
}

#[test]
fn returns_first_match_when_multiple_copies_share_fingerprint() {
    // Two manifest siblings both reference the same unchanged block
    // (same fingerprint, same clock summary). Either is a valid
    // parent; the helper returns the first match.
    let envelope = b"envelope-bytes-shared".to_vec();
    let fp = *blake3_hash(&envelope).as_bytes();
    let clock = vec![VectorClockEntry {
        device_uuid: [0x22; 16],
        counter: 3,
    }];

    let mut m1 = empty_manifest();
    m1.blocks.push(block_entry(UUID_A, fp, clock.clone()));
    let mut m2 = empty_manifest();
    m2.blocks.push(block_entry(UUID_A, fp, clock.clone()));

    let copies = vec![snapshot(m1), snapshot(m2)];
    let got = parent_block_clock(&envelope, &UUID_A, &copies).expect("expected clock");
    assert_eq!(got, clock);
}

#[test]
fn skips_copies_without_block_uuid_entry() {
    // copy[0] doesn't reference UUID_A at all; copy[1] does.
    // Positional-index pairing would have returned copy[0] (and
    // erroneously failed). Fingerprint pairing correctly finds
    // copy[1].
    let envelope = b"envelope-bytes-uuid-a".to_vec();
    let fp = *blake3_hash(&envelope).as_bytes();
    let clock_a = vec![VectorClockEntry {
        device_uuid: [0x33; 16],
        counter: 5,
    }];
    let other_fp = *blake3_hash(b"other-envelope").as_bytes();

    let mut m_other = empty_manifest();
    m_other.blocks.push(block_entry(
        UUID_B,
        other_fp,
        vec![VectorClockEntry {
            device_uuid: [0x44; 16],
            counter: 1,
        }],
    ));
    let mut m_target = empty_manifest();
    m_target
        .blocks
        .push(block_entry(UUID_A, fp, clock_a.clone()));

    let copies = vec![snapshot(m_other), snapshot(m_target)];
    let got = parent_block_clock(&envelope, &UUID_A, &copies).expect("expected clock");
    assert_eq!(got, clock_a);
}

#[test]
fn skips_copies_with_different_fingerprint_for_same_uuid() {
    // copy[0] references UUID_A but with a different envelope
    // fingerprint (e.g. an older block version); copy[1] is the
    // actual parent. Positional pairing would have grabbed copy[0]'s
    // (wrong) clock summary.
    let envelope = b"envelope-bytes-new".to_vec();
    let fp_new = *blake3_hash(&envelope).as_bytes();
    let fp_old = *blake3_hash(b"envelope-bytes-old").as_bytes();
    let clock_new = vec![VectorClockEntry {
        device_uuid: [0x55; 16],
        counter: 9,
    }];
    let clock_old = vec![VectorClockEntry {
        device_uuid: [0x66; 16],
        counter: 4,
    }];

    let mut m_old = empty_manifest();
    m_old.blocks.push(block_entry(UUID_A, fp_old, clock_old));
    let mut m_new = empty_manifest();
    m_new
        .blocks
        .push(block_entry(UUID_A, fp_new, clock_new.clone()));

    let copies = vec![snapshot(m_old), snapshot(m_new)];
    let got = parent_block_clock(&envelope, &UUID_A, &copies).expect("expected clock");
    assert_eq!(got, clock_new);
}

#[test]
fn errors_on_orphan_envelope_with_no_matching_manifest() {
    // The envelope authenticated (caller upstream) but no copy
    // manifest references it. Structural bundle error —
    // `parent_block_clock` returns InvalidArgument so the caller
    // can surface the issue rather than guess a clock.
    let envelope = b"orphan-envelope".to_vec();
    let fp_other = *blake3_hash(b"some-other-envelope").as_bytes();

    let mut m = empty_manifest();
    m.blocks.push(block_entry(
        UUID_A,
        fp_other,
        vec![VectorClockEntry {
            device_uuid: [0x77; 16],
            counter: 1,
        }],
    ));

    let copies = vec![snapshot(m)];
    let err = parent_block_clock(&envelope, &UUID_A, &copies).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("orphan block sibling"),
        "expected 'orphan block sibling' in error, got: {msg}"
    );
}

#[test]
fn errors_on_empty_copies() {
    let envelope = b"envelope".to_vec();
    let copies: Vec<ManifestSnapshot> = vec![];
    let err = parent_block_clock(&envelope, &UUID_A, &copies).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("orphan block sibling"),
        "expected 'orphan block sibling' in error, got: {msg}"
    );
}
