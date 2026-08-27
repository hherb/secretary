//! Manifest hybrid signing / verification (§8) and §10 rollback resistance.

use std::collections::BTreeMap;

use crate::crypto::aead::{AeadKey, AeadNonce, AEAD_TAG_LEN};
use crate::crypto::sig::{
    self, Ed25519Public, Ed25519Secret, HybridSig, MlDsa65Public, MlDsa65Secret, SigError, SigRole,
};
use crate::identity::fingerprint::Fingerprint;

use super::signed_message_bytes;
use super::ManifestFile;
use crate::vault::manifest::{
    encode_manifest, encrypt_manifest_body, Manifest, ManifestError, ManifestHeader,
    VectorClockEntry,
};

/// Build a complete on-disk [`ManifestFile`] from `header`, plaintext
/// `body`, and signing keys. Steps mirror §4.1 / §8 step 6:
///
/// 1. Canonical-CBOR-encode `body` (§4.2).
/// 2. AEAD-encrypt under `ibk` with `nonce` and `header.encode()` AAD,
///    yielding `ct || tag`. Split into `aead_ct` (variable) and
///    `aead_tag` (16 bytes).
/// 3. Hybrid-sign the bytes from `magic` through `aead_tag` inclusive
///    via [`crate::crypto::sig::sign`] with [`SigRole::Manifest`]. The
///    role tag `"secretary-v1-manifest-sig"` is prepended *internally*
///    by [`crate::crypto::sig::sign`] — DO NOT prepend it here.
///
/// Returns the populated [`ManifestFile`]. Encoding it to the wire
/// form is the caller's job ([`encode_manifest_file`]).
///
/// [`encode_manifest_file`]: crate::vault::manifest::encode_manifest_file
pub fn sign_manifest(
    header: ManifestHeader,
    body: &Manifest,
    ibk: &AeadKey,
    nonce: &AeadNonce,
    author: Fingerprint,
    sk_ed: &Ed25519Secret,
    sk_pq: &MlDsa65Secret,
) -> Result<ManifestFile, ManifestError> {
    // Step 1: encode the manifest body to canonical CBOR. `body_bytes` is a
    // cleartext copy of every user-authored `block_name` in the vault, so it
    // must be wiped on every exit path (normal return, an early `?`, or an
    // unwinding panic), the same PROPERTY the `bundle_plaintext` pattern in
    // `unlock::create_vault_unchecked` establishes (#513, #357) — but no
    // longer the same MECHANISM. `bundle_plaintext` is still a caller-side
    // `SecretBytes::new(identity.to_canonical_cbor()?)`. `encode_manifest`
    // now returns `SecretBytes` directly (#558, #565): the wrap is
    // structural, part of the function's return type, rather than a
    // separate `SecretBytes::new(..)` call here that a future edit could
    // silently drop.
    let body_bytes = encode_manifest(body)?;

    // Step 2: AEAD-encrypt with header AAD.
    let ct_with_tag = encrypt_manifest_body(&header, &body_bytes, ibk, nonce)?;

    // Real runtime check, not `debug_assert!` — same reasoning
    // `canonical::legacy::encode_canonical_map` states at its own length
    // check: this crate's only `debug-assertions = true` is
    // `core/fuzz/Cargo.toml`, which is `exclude`d from the workspace, so a
    // `debug_assert!` here is a no-op in `cargo test --release`, in
    // `cargo build --release`, and in every shipped artifact. This site
    // carried one until the #575 review.
    //
    // Not defence against a plausible bug — `XChaCha20Poly1305::encrypt`
    // returns `pt.len() + AEAD_TAG_LEN` by construction. It guards the
    // SUBTRACTION on the next line: a short return would underflow
    // `split_at` to a huge `usize` and panic on the slice index below,
    // which is a worse failure mode than a typed error even though neither
    // is reachable today.
    if ct_with_tag.len() != body_bytes.expose().len() + AEAD_TAG_LEN {
        return Err(ManifestError::AeadFailure);
    }

    // Split (ct || tag) into aead_ct (variable) and aead_tag (16).
    let split_at = ct_with_tag.len() - AEAD_TAG_LEN;
    let aead_ct = ct_with_tag[..split_at].to_vec();
    let mut aead_tag = [0u8; AEAD_TAG_LEN];
    aead_tag.copy_from_slice(&ct_with_tag[split_at..]);

    // Step 3: compute the signed-range bytes from raw parts (no
    // placeholder ManifestFile dance), sign, and assemble the final
    // ManifestFile in one shot.
    let m = signed_message_bytes(&header, nonce, &aead_ct, &aead_tag)?;
    let hybrid =
        sig::sign(SigRole::Manifest, &m, sk_ed, sk_pq).map_err(ManifestError::SignInternal)?;
    Ok(ManifestFile {
        header,
        aead_nonce: *nonce,
        aead_ct,
        aead_tag,
        author_fingerprint: author,
        sig_ed: hybrid.sig_ed,
        sig_pq: hybrid.sig_pq,
    })
}

/// Verify the §8 hybrid signature on a complete [`ManifestFile`].
/// Does NOT decrypt the AEAD body — that's a separate concern via
/// [`decrypt_manifest_body`]. Position-specific error variants
/// distinguish "Ed25519 half rejected" from "ML-DSA-65 half rejected"
/// (see [`ManifestError::Ed25519SignatureInvalid`] /
/// [`ManifestError::MlDsa65SignatureInvalid`]); other failures (wrong
/// key length, etc.) surface as [`ManifestError::SignInternal`].
///
/// The role tag `"secretary-v1-manifest-sig"` is prepended internally
/// by [`crate::crypto::sig::verify`] — DO NOT prepend it here.
///
/// [`decrypt_manifest_body`]: crate::vault::manifest::decrypt_manifest_body
pub fn verify_manifest(
    file: &ManifestFile,
    pk_ed: &Ed25519Public,
    pk_pq: &MlDsa65Public,
) -> Result<(), ManifestError> {
    let m = signed_message_bytes(
        &file.header,
        &file.aead_nonce,
        &file.aead_ct,
        &file.aead_tag,
    )?;
    let hybrid = HybridSig {
        sig_ed: file.sig_ed,
        sig_pq: file.sig_pq.clone(),
    };
    sig::verify(SigRole::Manifest, &m, &hybrid, pk_ed, pk_pq).map_err(|e| match e {
        SigError::Ed25519VerifyFailed => ManifestError::Ed25519SignatureInvalid,
        SigError::MlDsa65VerifyFailed => ManifestError::MlDsa65SignatureInvalid,
        other => ManifestError::SignInternal(other),
    })
}

// ---------------------------------------------------------------------------
// §10 — Rollback resistance
// ---------------------------------------------------------------------------

/// Returns `true` iff `incoming` is *strictly dominated by* `local`,
/// per `docs/crypto-design.md` §10 ("Vector-clock rollback resistance").
///
/// Both inputs are interpreted as logical maps from `device_uuid` to
/// `counter`, regardless of slice order. Devices missing from a slice
/// are treated as having counter 0 — a device that has never bumped its
/// clock is indistinguishable from a device that is absent.
///
/// Decision rules (caller is the OS-keystore-backed orchestrator that
/// holds the per-vault "highest-seen" clock):
///
/// - **Equal** clocks → NOT a rollback. Returns `false`.
/// - **`incoming` dominates** (every counter ≥ local, at least one
///   strictly more — or `incoming` introduces a device with counter > 0
///   that `local` does not have) → NOT a rollback. Caller accepts and
///   updates highest-seen. Returns `false`.
/// - **`incoming` strictly dominated** (every counter ≤ local, at least
///   one strictly less — or `local` carries a device at counter > 0 that
///   `incoming` lacks) → rollback. Returns `true`.
/// - **Concurrent** (some incoming counters strictly higher, some
///   strictly lower) → NOT a rollback per se. Returns `false`. Caller
///   triggers merge (PR-C territory; not implemented here).
///
/// Duplicate device UUIDs in either input are NOT detected here —
/// callers must reject them earlier. [`decode_manifest`] (§4.2's
/// `vector_clock` array sort discipline) already does this on the
/// incoming side.
///
/// PR-C will replace this boolean with a richer `ClockRelation` enum
/// (Equal / IncomingDominates / IncomingDominated / Concurrent); for
/// PR-B the reject-on-rollback predicate is the only consumer.
///
/// [`decode_manifest`]: crate::vault::manifest::decode_manifest
pub fn is_rollback(local: &[VectorClockEntry], incoming: &[VectorClockEntry]) -> bool {
    // Build maps so we can compare component-wise regardless of slice
    // order. Use BTreeMap for deterministic union iteration (test
    // diagnostics stay reproducible) and to side-step any hash-DoS
    // concerns at zero perf cost on these tiny inputs.
    let local_map: BTreeMap<[u8; 16], u64> =
        local.iter().map(|e| (e.device_uuid, e.counter)).collect();
    let incoming_map: BTreeMap<[u8; 16], u64> = incoming
        .iter()
        .map(|e| (e.device_uuid, e.counter))
        .collect();

    let mut any_strictly_less = false;
    let mut any_strictly_more = false;

    // Iterate the union of device UUIDs, treating "absent" as counter 0.
    for uuid in local_map.keys().chain(incoming_map.keys()) {
        let l = local_map.get(uuid).copied().unwrap_or(0);
        let i = incoming_map.get(uuid).copied().unwrap_or(0);
        match i.cmp(&l) {
            std::cmp::Ordering::Less => any_strictly_less = true,
            std::cmp::Ordering::Greater => any_strictly_more = true,
            std::cmp::Ordering::Equal => {}
        }
    }

    any_strictly_less && !any_strictly_more
}
