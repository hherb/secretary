//! uniffi namespace fns projecting the bridge's crash-recovery
//! `repair_vault_with_*` trio (#374). Each mirrors its `open_*` /
//! `open_with_device_secret` counterpart one-for-one — same folder-path
//! UTF-8 validation, same credential-length checks, same zeroize
//! discipline — but calls `secretary_ffi_bridge::repair_vault_with_*`
//! instead of the plain open path. See `docs/vault-format.md` §10 and
//! `core/src/vault/repair.rs` for the crash-recovery semantics; repair is
//! never a weaker open. Each bridge repair fn loads the local §10 rollback
//! baseline and passes it to core `repair_vault`, which runs the §10
//! rollback check on the COMMITTED manifest clock BEFORE adopting, ticking,
//! or writing anything — so a rollback is refused fail-closed without
//! mutating the vault (see `ffi/secretary-ffi-bridge/src/repair/orchestration.rs`
//! module docs for why this must happen pre-write rather than via a
//! post-write `enforce_rollback_resistance` call).
//!
//! Task 7 (#374) projects the informed-consent surface upward: callers may
//! pass a `Vec<ApprovedWidening>` licensing specific consent-eligible
//! recipient-widening residue (an empty vec is the documented safe
//! zero-value, unchanged from Task 5's stopgap), and three new
//! `preview_repair_with_*` fns let a caller build that approval set from a
//! read-only, nothing-written-to-disk preview. Every `bytes` field of
//! every `ApprovedWidening` is length-validated here — 16 bytes for
//! `block_uuid`, 32 for `file_fingerprint`, 16 for each entry of
//! `added_recipients` — BEFORE the bridge call, per the established rule
//! that FFI input validation lives at the binding wrapper: the bridge's
//! `FfiApprovedWidening` trusts its caller (see
//! `ffi/secretary-ffi-bridge/src/repair/types.rs` module docs).

use zeroize::Zeroize;

use crate::errors::VaultError;
use crate::wrappers::repair::{ApprovedWidening, RepairPreview};
use crate::wrappers::vault::{OpenVaultManifest, OpenVaultOutput};

use super::{array32_from_vec, uuid_from_vec};

/// Convert a caller-supplied `Vec<ApprovedWidening>` into the bridge-side
/// `Vec<FfiApprovedWidening>`, length-validating every byte field first.
///
/// Field names in the returned [`VaultError::InvalidArgument`] detail are
/// indexed (`approvals[i].block_uuid`, `approvals[i].added_recipients[j]`)
/// so a caller with multiple approvals can tell which entry failed.
fn convert_approvals(
    approvals: Vec<ApprovedWidening>,
) -> Result<Vec<secretary_ffi_bridge::FfiApprovedWidening>, VaultError> {
    approvals
        .into_iter()
        .enumerate()
        .map(|(idx, w)| {
            let block_uuid = uuid_from_vec(&w.block_uuid, &format!("approvals[{idx}].block_uuid"))?;
            let file_fingerprint = array32_from_vec(
                &w.file_fingerprint,
                &format!("approvals[{idx}].file_fingerprint"),
            )?;
            let added_recipients = w
                .added_recipients
                .iter()
                .enumerate()
                .map(|(j, r)| uuid_from_vec(r, &format!("approvals[{idx}].added_recipients[{j}]")))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(secretary_ffi_bridge::FfiApprovedWidening {
                block_uuid,
                file_fingerprint,
                added_recipients,
            })
        })
        .collect()
}

/// Repair a crash-residue vault using its master password. uniffi-projected. (#374)
///
/// `folder_path` is the UTF-8-encoded filesystem path as bytes.
/// `device_uuid` must be exactly 16 bytes; otherwise returns
/// [`VaultError::InvalidArgument`]. `approvals` licenses consent-eligible
/// recipient-widening residue — see module docs for the per-field
/// validation; an empty vec is the safe zero-value (fail-closed on any
/// widening, matching pre-Task-7 behavior). `password` is zeroized
/// unconditionally on return.
///
/// # Errors
///
/// Returns [`VaultError`] on failure. [`VaultError::RepairRejected`] means
/// the on-disk residue failed one of the fail-closed adoption gates (hybrid
/// verify, header binding, clock freshness, or the recipient-widening
/// guard) — no change was written. [`VaultError::InvalidArgument`] means
/// `device_uuid` or one of `approvals`'s byte fields had the wrong length.
/// Other variants mirror [`super::open_vault_with_password`].
pub fn repair_with_password(
    folder_path: Vec<u8>,
    mut password: Vec<u8>,
    device_uuid: Vec<u8>,
    now_ms: u64,
    approvals: Vec<ApprovedWidening>,
) -> Result<OpenVaultOutput, VaultError> {
    // Validate approvals FIRST, before device_uuid / the fallible path
    // chain, so any early return here still zeroizes password.
    let approvals = match convert_approvals(approvals) {
        Ok(a) => a,
        Err(e) => {
            password.zeroize();
            return Err(e);
        }
    };

    // Length-check device_uuid BEFORE the fallible path chain so we can
    // zeroize password on this early-return arm too.
    let uuid_arr = match uuid_from_vec(&device_uuid, "device_uuid") {
        Ok(u) => u,
        Err(e) => {
            password.zeroize();
            return Err(e);
        }
    };

    // Compute the full result chain into a single binding so we can zeroize
    // the password BEFORE any `?`-propagation — mirrors open_vault_with_password.
    let result: Result<secretary_ffi_bridge::OpenVaultOutput, VaultError> =
        match std::str::from_utf8(&folder_path) {
            Ok(s) => {
                let path = std::path::PathBuf::from(s);
                secretary_ffi_bridge::repair_vault_with_password(
                    &path, &password, &uuid_arr, now_ms, &approvals,
                )
                .map_err(VaultError::from)
            }
            Err(_) => Err(VaultError::FolderInvalid {
                detail: "folder path contained invalid UTF-8".to_string(),
            }),
        };

    // Zeroize unconditionally — runs on both success and error paths.
    password.zeroize();

    let bridge_out = result?;
    Ok(OpenVaultOutput {
        identity: std::sync::Arc::new(crate::wrappers::identity::UnlockedIdentity(
            bridge_out.identity,
        )),
        manifest: std::sync::Arc::new(OpenVaultManifest(bridge_out.manifest)),
    })
}

/// Repair a crash-residue vault using its 24-word BIP-39 recovery phrase.
/// uniffi-projected. (#374)
///
/// `folder_path` is the UTF-8-encoded filesystem path as bytes. `mnemonic`
/// is the UTF-8-encoded phrase as bytes; the bridge's UTF-8 validation seam
/// surfaces malformed-UTF-8 input as [`VaultError::InvalidMnemonic`].
/// `device_uuid` must be exactly 16 bytes; otherwise returns
/// [`VaultError::InvalidArgument`]. `approvals` licenses consent-eligible
/// recipient-widening residue — see [`repair_with_password`] for the
/// per-field validation and the empty-vec safe zero-value. `mnemonic` is
/// zeroized unconditionally on return.
///
/// # Errors
///
/// Returns [`VaultError`] on failure. See [`repair_with_password`] for the
/// repair-specific error semantics.
pub fn repair_with_recovery(
    folder_path: Vec<u8>,
    mut mnemonic: Vec<u8>,
    device_uuid: Vec<u8>,
    now_ms: u64,
    approvals: Vec<ApprovedWidening>,
) -> Result<OpenVaultOutput, VaultError> {
    // Validate approvals FIRST, before device_uuid / the fallible path
    // chain, so any early return here still zeroizes mnemonic.
    let approvals = match convert_approvals(approvals) {
        Ok(a) => a,
        Err(e) => {
            mnemonic.zeroize();
            return Err(e);
        }
    };

    let uuid_arr = match uuid_from_vec(&device_uuid, "device_uuid") {
        Ok(u) => u,
        Err(e) => {
            mnemonic.zeroize();
            return Err(e);
        }
    };

    let result: Result<secretary_ffi_bridge::OpenVaultOutput, VaultError> =
        match std::str::from_utf8(&folder_path) {
            Ok(s) => {
                let path = std::path::PathBuf::from(s);
                secretary_ffi_bridge::repair_vault_with_recovery(
                    &path, &mnemonic, &uuid_arr, now_ms, &approvals,
                )
                .map_err(VaultError::from)
            }
            Err(_) => Err(VaultError::FolderInvalid {
                detail: "folder path contained invalid UTF-8".to_string(),
            }),
        };

    // Zeroize unconditionally — runs on both success and error paths.
    mnemonic.zeroize();

    let bridge_out = result?;
    Ok(OpenVaultOutput {
        identity: std::sync::Arc::new(crate::wrappers::identity::UnlockedIdentity(
            bridge_out.identity,
        )),
        manifest: std::sync::Arc::new(OpenVaultManifest(bridge_out.manifest)),
    })
}

/// Repair a crash-residue vault using a per-device wrap secret. uniffi-projected. (#374)
///
/// `folder_path` is the UTF-8-encoded filesystem path as bytes.
/// `device_uuid` must be exactly 16 bytes; `device_secret` must be exactly
/// 32 bytes. `approvals` licenses consent-eligible recipient-widening
/// residue — see [`repair_with_password`] for the per-field validation and
/// the empty-vec safe zero-value. All credential/approval fields are
/// validated before the bridge call; `device_secret` is zeroized on all
/// paths.
///
/// # Errors
///
/// - [`VaultError::InvalidArgument`] — `device_uuid` ≠ 16 bytes,
///   `device_secret` ≠ 32 bytes, or one of `approvals`'s byte fields had
///   the wrong length.
/// - [`VaultError::FolderInvalid`] — `folder_path` contains invalid UTF-8.
/// - other variants mirror [`repair_with_password`] and
///   [`super::open_with_device_secret`].
pub fn repair_with_device_secret(
    folder_path: Vec<u8>,
    device_uuid: Vec<u8>,
    mut device_secret: Vec<u8>,
    now_ms: u64,
    approvals: Vec<ApprovedWidening>,
) -> Result<OpenVaultOutput, VaultError> {
    // Validate approvals FIRST, before the length pre-checks / UTF-8
    // validation, so any early return here still zeroizes device_secret.
    let approvals = match convert_approvals(approvals) {
        Ok(a) => a,
        Err(e) => {
            device_secret.zeroize();
            return Err(e);
        }
    };

    // Length pre-checks BEFORE UTF-8 validation so we can zeroize
    // device_secret on all early-return paths — mirrors open_with_device_secret.
    if device_uuid.len() != 16 {
        device_secret.zeroize();
        return Err(VaultError::InvalidArgument {
            detail: format!("device_uuid must be 16 bytes, got {}", device_uuid.len()),
        });
    }
    if device_secret.len() != 32 {
        // Capture the length BEFORE zeroize(): `Vec::zeroize()` calls
        // `self.clear()` (zeroize crate's Vec impl), so reading
        // `device_secret.len()` after zeroizing would always report 0
        // rather than the actual wrong length.
        let got = device_secret.len();
        device_secret.zeroize();
        return Err(VaultError::InvalidArgument {
            detail: format!("device_secret must be 32 bytes, got {got}"),
        });
    }

    let uuid_arr: [u8; 16] = device_uuid
        .as_slice()
        .try_into()
        .expect("len checked above");
    // `mut` so the [u8; 32] stack copy is zeroized IN PLACE below. Binding it
    // immutably and later doing `let mut secret_arr = secret_arr;` would COPY
    // the array (`[u8; 32]: Copy`) into a fresh slot and wipe only the copy,
    // leaving this original slot's 32 plaintext bytes as stack residue.
    let mut secret_arr: [u8; 32] = device_secret
        .as_slice()
        .try_into()
        .expect("len checked above");

    let result: Result<secretary_ffi_bridge::OpenVaultOutput, VaultError> =
        match std::str::from_utf8(&folder_path) {
            Ok(s) => {
                let path = std::path::PathBuf::from(s);
                secretary_ffi_bridge::repair_vault_with_device_secret(
                    &path,
                    &uuid_arr,
                    &secret_arr,
                    now_ms,
                    &approvals,
                )
                .map_err(VaultError::from)
            }
            Err(_) => Err(VaultError::FolderInvalid {
                detail: "folder path contained invalid UTF-8".to_string(),
            }),
        };

    // Zeroize unconditionally — runs on both success and error paths.
    // secret_arr is [u8; 32] (Copy), so both the array and the source Vec
    // must be zeroized to prevent stack residue — same discipline as
    // open_with_device_secret / the bridge's derive_wrap_key pattern.
    secret_arr.zeroize();
    device_secret.zeroize();

    let bridge_out = result?;
    Ok(OpenVaultOutput {
        identity: std::sync::Arc::new(crate::wrappers::identity::UnlockedIdentity(
            bridge_out.identity,
        )),
        manifest: std::sync::Arc::new(OpenVaultManifest(bridge_out.manifest)),
    })
}

/// Preview a crash-residue vault opened by master password, without
/// writing anything. uniffi-projected. (#374 Task 7)
///
/// Mirrors [`repair_with_password`] minus `device_uuid`/`now_ms` — preview
/// never writes, so there is no device-clock tick and no manifest re-sign
/// to key by device or timestamp. Lets a caller build an informed-consent
/// prompt (recipient names + fingerprints) and derive an `ApprovedWidening`
/// set BEFORE calling [`repair_with_password`]. `password` is zeroized
/// unconditionally on return.
///
/// # Errors
///
/// Returns [`VaultError`] on failure. A vault whose residue `repair_vault`
/// could not adopt at all (e.g. a rollback plant, or a hard-rejected
/// shape) errors identically here — see the bridge crate's
/// `preview_repair_with_password` docs.
pub fn preview_repair_with_password(
    folder_path: Vec<u8>,
    mut password: Vec<u8>,
) -> Result<RepairPreview, VaultError> {
    let result: Result<secretary_ffi_bridge::FfiRepairPreview, VaultError> =
        match std::str::from_utf8(&folder_path) {
            Ok(s) => {
                let path = std::path::PathBuf::from(s);
                secretary_ffi_bridge::preview_repair_with_password(&path, &password)
                    .map_err(VaultError::from)
            }
            Err(_) => Err(VaultError::FolderInvalid {
                detail: "folder path contained invalid UTF-8".to_string(),
            }),
        };

    // Zeroize unconditionally — runs on both success and error paths.
    password.zeroize();

    let bridge_out = result?;
    Ok(RepairPreview::from(bridge_out))
}

/// Preview a crash-residue vault opened by its 24-word BIP-39 recovery
/// phrase, without writing anything. uniffi-projected. (#374 Task 7)
///
/// See [`preview_repair_with_password`] for the shared semantics.
/// `mnemonic` is zeroized unconditionally on return.
///
/// # Errors
///
/// Returns [`VaultError`] on failure. See [`preview_repair_with_password`].
pub fn preview_repair_with_recovery(
    folder_path: Vec<u8>,
    mut mnemonic: Vec<u8>,
) -> Result<RepairPreview, VaultError> {
    let result: Result<secretary_ffi_bridge::FfiRepairPreview, VaultError> =
        match std::str::from_utf8(&folder_path) {
            Ok(s) => {
                let path = std::path::PathBuf::from(s);
                secretary_ffi_bridge::preview_repair_with_recovery(&path, &mnemonic)
                    .map_err(VaultError::from)
            }
            Err(_) => Err(VaultError::FolderInvalid {
                detail: "folder path contained invalid UTF-8".to_string(),
            }),
        };

    // Zeroize unconditionally — runs on both success and error paths.
    mnemonic.zeroize();

    let bridge_out = result?;
    Ok(RepairPreview::from(bridge_out))
}

/// Preview a crash-residue vault opened by a per-device wrap secret,
/// without writing anything. uniffi-projected. (#374 Task 7)
///
/// See [`preview_repair_with_password`] for the shared semantics.
/// `device_uuid` must be exactly 16 bytes; `device_secret` must be exactly
/// 32 bytes; both are validated before the bridge call. `device_secret` is
/// zeroized on all paths.
///
/// # Errors
///
/// - [`VaultError::InvalidArgument`] — `device_uuid` ≠ 16 bytes or
///   `device_secret` ≠ 32 bytes.
/// - [`VaultError::FolderInvalid`] — `folder_path` contains invalid UTF-8.
/// - other variants mirror [`preview_repair_with_password`].
pub fn preview_repair_with_device_secret(
    folder_path: Vec<u8>,
    device_uuid: Vec<u8>,
    mut device_secret: Vec<u8>,
) -> Result<RepairPreview, VaultError> {
    // Length pre-checks BEFORE UTF-8 validation so we can zeroize
    // device_secret on all early-return paths — mirrors
    // repair_with_device_secret / open_with_device_secret.
    if device_uuid.len() != 16 {
        device_secret.zeroize();
        return Err(VaultError::InvalidArgument {
            detail: format!("device_uuid must be 16 bytes, got {}", device_uuid.len()),
        });
    }
    if device_secret.len() != 32 {
        // Capture the length BEFORE zeroize(): `Vec::zeroize()` calls
        // `self.clear()` (zeroize crate's Vec impl), so reading
        // `device_secret.len()` after zeroizing would always report 0
        // rather than the actual wrong length.
        let got = device_secret.len();
        device_secret.zeroize();
        return Err(VaultError::InvalidArgument {
            detail: format!("device_secret must be 32 bytes, got {got}"),
        });
    }

    let uuid_arr: [u8; 16] = device_uuid
        .as_slice()
        .try_into()
        .expect("len checked above");
    // `mut` so the [u8; 32] stack copy is zeroized IN PLACE below — see
    // repair_with_device_secret for why a re-binding `let mut` would leave
    // stack residue.
    let mut secret_arr: [u8; 32] = device_secret
        .as_slice()
        .try_into()
        .expect("len checked above");

    let result: Result<secretary_ffi_bridge::FfiRepairPreview, VaultError> =
        match std::str::from_utf8(&folder_path) {
            Ok(s) => {
                let path = std::path::PathBuf::from(s);
                secretary_ffi_bridge::preview_repair_with_device_secret(
                    &path,
                    &uuid_arr,
                    &secret_arr,
                )
                .map_err(VaultError::from)
            }
            Err(_) => Err(VaultError::FolderInvalid {
                detail: "folder path contained invalid UTF-8".to_string(),
            }),
        };

    // Zeroize unconditionally — runs on both success and error paths.
    secret_arr.zeroize();
    device_secret.zeroize();

    let bridge_out = result?;
    Ok(RepairPreview::from(bridge_out))
}

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------
    // #374 Task 7: approvals length-validation regression tests. Pin the
    // observable error contract (InvalidArgument, indexed field name in
    // the detail) so a future refactor that drops a validation step (or
    // reorders it after the credential is consumed) breaks a named test
    // rather than silently regressing. Mirrors the read_block /
    // open_vault_with_password invalid-input tests in namespace/mod.rs.
    // -------------------------------------------------------------------

    fn bad_approval_wrong_block_uuid() -> ApprovedWidening {
        ApprovedWidening {
            block_uuid: vec![0u8; 15], // wrong: must be 16
            file_fingerprint: vec![0u8; 32],
            added_recipients: vec![],
        }
    }

    fn bad_approval_wrong_file_fingerprint() -> ApprovedWidening {
        ApprovedWidening {
            block_uuid: vec![0u8; 16],
            file_fingerprint: vec![0u8; 31], // wrong: must be 32
            added_recipients: vec![],
        }
    }

    fn bad_approval_wrong_added_recipient() -> ApprovedWidening {
        ApprovedWidening {
            block_uuid: vec![0u8; 16],
            file_fingerprint: vec![0u8; 32],
            added_recipients: vec![vec![0u8; 17]], // wrong: must be 16
        }
    }

    #[test]
    fn convert_approvals_rejects_wrong_length_block_uuid() {
        match convert_approvals(vec![bad_approval_wrong_block_uuid()]) {
            Err(VaultError::InvalidArgument { detail }) => {
                assert!(
                    detail.contains("approvals[0].block_uuid")
                        && detail.contains("16 bytes")
                        && detail.contains("got 15"),
                    "detail did not name the failing field: {detail}"
                );
            }
            Err(other) => panic!("expected InvalidArgument, got {other:?}"),
            Ok(_) => panic!("expected Err for wrong-length block_uuid"),
        }
    }

    #[test]
    fn convert_approvals_rejects_wrong_length_file_fingerprint() {
        match convert_approvals(vec![bad_approval_wrong_file_fingerprint()]) {
            Err(VaultError::InvalidArgument { detail }) => {
                assert!(
                    detail.contains("approvals[0].file_fingerprint")
                        && detail.contains("32 bytes")
                        && detail.contains("got 31"),
                    "detail did not name the failing field: {detail}"
                );
            }
            Err(other) => panic!("expected InvalidArgument, got {other:?}"),
            Ok(_) => panic!("expected Err for wrong-length file_fingerprint"),
        }
    }

    #[test]
    fn convert_approvals_rejects_wrong_length_added_recipient() {
        match convert_approvals(vec![bad_approval_wrong_added_recipient()]) {
            Err(VaultError::InvalidArgument { detail }) => {
                assert!(
                    detail.contains("approvals[0].added_recipients[0]")
                        && detail.contains("16 bytes")
                        && detail.contains("got 17"),
                    "detail did not name the failing field: {detail}"
                );
            }
            Err(other) => panic!("expected InvalidArgument, got {other:?}"),
            Ok(_) => panic!("expected Err for wrong-length added_recipients entry"),
        }
    }

    #[test]
    fn convert_approvals_accepts_empty_vec() {
        // The documented safe zero-value: no approvals at all.
        assert!(convert_approvals(vec![]).unwrap().is_empty());
    }

    #[test]
    fn convert_approvals_accepts_well_formed_entry() {
        let good = ApprovedWidening {
            block_uuid: vec![1u8; 16],
            file_fingerprint: vec![2u8; 32],
            added_recipients: vec![vec![3u8; 16], vec![4u8; 16]],
        };
        let converted = convert_approvals(vec![good]).unwrap();
        assert_eq!(converted.len(), 1);
        assert_eq!(converted[0].block_uuid, [1u8; 16]);
        assert_eq!(converted[0].file_fingerprint, [2u8; 32]);
        assert_eq!(converted[0].added_recipients, vec![[3u8; 16], [4u8; 16]]);
    }

    #[test]
    fn repair_with_password_wrong_length_approval_returns_invalid_argument_before_touching_disk() {
        // A garbage folder_path proves approvals are validated BEFORE the
        // folder-path UTF-8 check / bridge call (see convert_approvals()
        // call site ordering in repair_with_password): if approvals
        // validation ran after the folder check, this would return
        // FolderInvalid instead of InvalidArgument.
        match repair_with_password(
            b"\xff\xfe".to_vec(),
            b"hunter2".to_vec(),
            vec![0u8; 16],
            1_700_000_000_000,
            vec![bad_approval_wrong_block_uuid()],
        ) {
            Err(VaultError::InvalidArgument { detail }) => {
                assert!(detail.contains("approvals[0].block_uuid"));
            }
            Err(other) => panic!("expected InvalidArgument, got {other:?}"),
            Ok(_) => panic!("expected Err for wrong-length approval"),
        }
    }

    #[test]
    fn repair_with_recovery_wrong_length_approval_returns_invalid_argument_before_touching_disk() {
        match repair_with_recovery(
            b"\xff\xfe".to_vec(),
            b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_vec(),
            vec![0u8; 16],
            1_700_000_000_000,
            vec![bad_approval_wrong_file_fingerprint()],
        ) {
            Err(VaultError::InvalidArgument { detail }) => {
                assert!(detail.contains("approvals[0].file_fingerprint"));
            }
            Err(other) => panic!("expected InvalidArgument, got {other:?}"),
            Ok(_) => panic!("expected Err for wrong-length approval"),
        }
    }

    #[test]
    fn repair_with_device_secret_wrong_length_approval_returns_invalid_argument_before_touching_disk(
    ) {
        match repair_with_device_secret(
            b"\xff\xfe".to_vec(),
            vec![0u8; 16],
            vec![0u8; 32],
            1_700_000_000_000,
            vec![bad_approval_wrong_added_recipient()],
        ) {
            Err(VaultError::InvalidArgument { detail }) => {
                assert!(detail.contains("approvals[0].added_recipients[0]"));
            }
            Err(other) => panic!("expected InvalidArgument, got {other:?}"),
            Ok(_) => panic!("expected Err for wrong-length approval"),
        }
    }

    #[test]
    fn preview_repair_with_device_secret_wrong_length_device_uuid_returns_invalid_argument() {
        match preview_repair_with_device_secret(b"\xff\xfe".to_vec(), vec![0u8; 15], vec![0u8; 32])
        {
            Err(VaultError::InvalidArgument { detail }) => {
                assert!(detail.contains("device_uuid") && detail.contains("15"));
            }
            Err(other) => panic!("expected InvalidArgument, got {other:?}"),
            Ok(_) => panic!("expected Err for wrong-length device_uuid"),
        }
    }

    #[test]
    fn preview_repair_with_device_secret_wrong_length_device_secret_returns_invalid_argument() {
        match preview_repair_with_device_secret(b"\xff\xfe".to_vec(), vec![0u8; 16], vec![0u8; 31])
        {
            Err(VaultError::InvalidArgument { detail }) => {
                assert!(detail.contains("device_secret") && detail.contains("31"));
            }
            Err(other) => panic!("expected InvalidArgument, got {other:?}"),
            Ok(_) => panic!("expected Err for wrong-length device_secret"),
        }
    }

    #[test]
    fn preview_repair_with_password_invalid_utf8_path_returns_folder_invalid() {
        match preview_repair_with_password(b"\xff\xfe".to_vec(), b"hunter2".to_vec()) {
            Err(VaultError::FolderInvalid { .. }) => {}
            Err(other) => panic!("expected FolderInvalid, got {other:?}"),
            Ok(_) => panic!("expected Err for invalid UTF-8 path"),
        }
    }

    #[test]
    fn preview_repair_with_recovery_invalid_utf8_path_returns_folder_invalid() {
        match preview_repair_with_recovery(
            b"\xff\xfe".to_vec(),
            b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_vec(),
        ) {
            Err(VaultError::FolderInvalid { .. }) => {}
            Err(other) => panic!("expected FolderInvalid, got {other:?}"),
            Ok(_) => panic!("expected Err for invalid UTF-8 path"),
        }
    }
}
