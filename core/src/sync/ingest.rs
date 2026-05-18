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

use std::path::{Path, PathBuf};

use crate::crypto::aead::AeadKey;
use crate::crypto::sig::{Ed25519Public, MlDsa65Public};
use crate::identity::fingerprint::Fingerprint;
use crate::sync::bundle::ManifestSnapshot;
use crate::vault::{decode_manifest_file, decrypt_manifest_body, verify_manifest};

/// The canonical manifest filename on disk. Conflict-copy siblings
/// are recognised by starting with this prefix and not matching it
/// exactly.
const CANONICAL_MANIFEST_FILENAME: &str = "manifest.cbor.enc";

/// Length of the AEAD tag appended to the manifest body ciphertext.
/// Mirrors the constant in `crate::vault::manifest`.
const AEAD_TAG_LEN: usize = 16;

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
///
/// `#[allow(dead_code)]` until Task 6's `ingest_manifest_copies`
/// wires this helper into the top-level scan; removed when the
/// integration arrives.
#[allow(dead_code)]
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
                tracing::debug!(
                    path = %candidate_source_path.display(),
                    error = %err,
                    "conflict-copy rejected: AEAD decrypt failed"
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
/// The `starts_with(CANONICAL_MANIFEST_FILENAME)` filter covers all
/// observed cloud-sync naming conventions: Dropbox
/// `manifest.cbor.enc (conflicted copy …)`, iCloud
/// `manifest.cbor.enc 2`, Syncthing
/// `manifest.cbor.enc.sync-conflict-…`, etc. The filter is the
/// heuristic discovery hook — authentication is the security
/// boundary (spec §1a-D3).
#[allow(dead_code)]
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
        if name == CANONICAL_MANIFEST_FILENAME {
            continue;
        }
        if !name.starts_with(CANONICAL_MANIFEST_FILENAME) {
            continue;
        }
        out.push(path);
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthesizes minimal owner public keys for the rejection-arm
    /// tests. Zero-byte ML-DSA-65 PK would fail length validation, so
    /// build one of the correct length; Ed25519 is fixed 32 bytes.
    fn dummy_owner_keys() -> (Ed25519Public, MlDsa65Public) {
        let ed_pk: Ed25519Public = [0u8; 32];
        // ML-DSA-65 public key is 1952 bytes per spec; from_bytes
        // accepts any byte sequence of that length.
        let pq_pk_bytes = vec![0u8; 1952];
        let pq_pk = MlDsa65Public::from_bytes(&pq_pk_bytes).expect("dummy pq pk length");
        (ed_pk, pq_pk)
    }

    fn dummy_ibk() -> AeadKey {
        AeadKey::new([0u8; 32])
    }

    #[test]
    fn authenticate_rejects_empty_bytes() {
        let (ed, pq) = dummy_owner_keys();
        let ibk = dummy_ibk();
        let result = authenticate_manifest_envelope(
            &[],
            PathBuf::from("/tmp/empty.cbor.enc"),
            [0u8; 16],
            [0u8; 16],
            &ed,
            &pq,
            &ibk,
        );
        assert!(result.is_none(), "empty bytes must not authenticate");
    }

    #[test]
    fn authenticate_rejects_garbage_bytes() {
        let (ed, pq) = dummy_owner_keys();
        let ibk = dummy_ibk();
        let result = authenticate_manifest_envelope(
            b"this is not a manifest envelope, just ASCII",
            PathBuf::from("/tmp/garbage.cbor.enc"),
            [0u8; 16],
            [0u8; 16],
            &ed,
            &pq,
            &ibk,
        );
        assert!(result.is_none(), "garbage bytes must not authenticate");
    }

    #[test]
    fn enumerate_manifest_siblings_returns_non_canonical_prefix_matches() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let folder = tmp.path();

        std::fs::write(folder.join("manifest.cbor.enc"), b"canonical").unwrap();
        std::fs::write(folder.join("manifest.cbor.enc.sibling-1"), b"sibling").unwrap();
        std::fs::write(
            folder.join("manifest.cbor.enc (conflicted copy 2026-05-15)"),
            b"dropbox-style",
        )
        .unwrap();
        std::fs::write(folder.join("vault.toml"), b"unrelated").unwrap();
        std::fs::write(folder.join("identity_bundle.cbor.enc"), b"also-unrelated").unwrap();

        let siblings = enumerate_manifest_siblings(folder).expect("scan");
        let names: Vec<String> = siblings
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();

        assert_eq!(siblings.len(), 2, "exactly 2 sibling matches");
        assert!(names.contains(&"manifest.cbor.enc.sibling-1".to_string()));
        assert!(names.contains(&"manifest.cbor.enc (conflicted copy 2026-05-15)".to_string()));
        assert!(!names.contains(&"manifest.cbor.enc".to_string()));
        assert!(!names.contains(&"vault.toml".to_string()));
        assert!(!names.contains(&"identity_bundle.cbor.enc".to_string()));
    }

    #[test]
    fn enumerate_manifest_siblings_returns_empty_on_canonical_only_folder() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let folder = tmp.path();
        std::fs::write(folder.join("manifest.cbor.enc"), b"canonical").unwrap();
        std::fs::write(folder.join("vault.toml"), b"vault-config").unwrap();

        let siblings = enumerate_manifest_siblings(folder).expect("scan");
        assert!(siblings.is_empty(), "no siblings expected");
    }

    #[test]
    fn enumerate_manifest_siblings_errors_when_folder_missing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let missing = tmp.path().join("does-not-exist");
        let result = enumerate_manifest_siblings(&missing);
        assert!(result.is_err(), "missing folder should yield io::Error");
    }

    #[test]
    fn authenticate_rejects_short_bytes_below_header_size() {
        let (ed, pq) = dummy_owner_keys();
        let ibk = dummy_ibk();
        // Manifest header is at least 42 bytes per docs/vault-format.md §4.1;
        // a 10-byte input can't possibly decode.
        let result = authenticate_manifest_envelope(
            &[0xCB, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            PathBuf::from("/tmp/short.cbor.enc"),
            [0u8; 16],
            [0u8; 16],
            &ed,
            &pq,
            &ibk,
        );
        assert!(result.is_none(), "short bytes must not authenticate");
    }
}
