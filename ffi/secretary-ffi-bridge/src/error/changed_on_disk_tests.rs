//! Every bridge writer's error fold maps core `ManifestChangedOnDisk` to
//! `FfiVaultError::VaultChangedOnDisk` (#101). The platforms key their Reload /
//! "Sync, then try again" copy on that variant, so a fold that sent it to
//! `CorruptVault` would compile and silently show the wrong message. Only the
//! save path is covered end to end; this pins the other seven folds.

use secretary_core::vault::VaultError;

use crate::error::FfiVaultError;

type Fold = fn(VaultError) -> FfiVaultError;

#[test]
fn every_writer_fold_maps_manifest_changed_on_disk() {
    let folds: [(&str, Fold); 9] = [
        ("generic From", FfiVaultError::from),
        ("save", crate::save::orchestration::map_core_vault_error),
        (
            "share",
            crate::share::orchestration::map_core_vault_error_share,
        ),
        (
            "revoke",
            crate::revoke::orchestration::map_core_vault_error_revoke,
        ),
        (
            "trash",
            crate::trash::orchestration::map_core_vault_error_trash,
        ),
        (
            "restore",
            crate::restore::orchestration::map_core_vault_error_restore,
        ),
        (
            "purge",
            crate::purge::orchestration::map_core_vault_error_purge,
        ),
        (
            "empty_trash",
            crate::purge::orchestration::map_core_vault_error_empty_trash,
        ),
        (
            "retention",
            crate::retention::orchestration::map_core_vault_error_retention,
        ),
    ];
    for (name, fold) in folds {
        let got = fold(VaultError::ManifestChangedOnDisk);
        assert!(
            matches!(got, FfiVaultError::VaultChangedOnDisk),
            "{name} fold: got {got:?}"
        );
    }
}
