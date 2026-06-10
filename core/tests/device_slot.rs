//! Folder-level device-slot integration: enroll → open → revoke, multi-device,
//! and the read-only-fixture hygiene from [[feedback_smoke_test_temp_copy_golden_vault]].

use std::path::Path;

use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use secretary_core::crypto::kdf::Argon2idParams;
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::vault::device_slot::{
    add_device_slot, open_identity_with_device_secret, remove_device_slot,
};

/// v1-floor-bypassing Argon2id parameters. The production `vault::create_vault`
/// enforces the v1 floor (64 MiB), making tests take minutes. Tests use the
/// unchecked path so the round-trip stays in milliseconds.
fn fast_kdf() -> Argon2idParams {
    Argon2idParams::new(8, 1, 1)
}

/// Create the two vault files needed by the device-slot orchestrators on disk
/// in a fresh tempdir, using the unchecked (fast-KDF) unlock path. Returns the
/// tempdir handle and the password. The two on-disk files have the same byte
/// shape as a production vault; only the KDF strength is below the v1 floor.
fn make_vault(seed: u8) -> (tempfile::TempDir, SecretBytes) {
    let dir = tempfile::tempdir().unwrap();
    let password = SecretBytes::new(b"hunter2".to_vec());
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let created =
        secretary_core::unlock::create_vault_unchecked(&password, "Alice", 0, fast_kdf(), &mut rng)
            .expect("create_vault_unchecked");
    std::fs::write(dir.path().join("vault.toml"), &created.vault_toml_bytes)
        .expect("write vault.toml");
    std::fs::write(
        dir.path().join("identity.bundle.enc"),
        &created.identity_bundle_bytes,
    )
    .expect("write identity.bundle.enc");
    (dir, password)
}

#[test]
fn enroll_then_open_with_device_secret_roundtrips() {
    let (dir, password) = make_vault(1);
    let mut rng = ChaCha20Rng::from_seed([20u8; 32]);
    let enrolled = add_device_slot(dir.path(), &password, &mut rng).expect("enroll");

    // The wrap file exists under devices/.
    let wrap = dir.path().join("devices").join(format!(
        "{}.wrap",
        secretary_core::vault::format_uuid_hyphenated(&enrolled.device_uuid)
    ));
    assert!(wrap.exists(), "device wrap file should be written");

    // Opening with the returned secret yields the same identity as the password path.
    let opened = open_identity_with_device_secret(
        dir.path(),
        &enrolled.device_uuid,
        &enrolled.device_secret,
    )
    .expect("open by device secret");
    let by_pw = open_identity_with_password(dir.path(), &password);
    assert_eq!(
        opened.identity_block_key.expose(),
        by_pw.identity_block_key.expose()
    );
}

#[test]
fn revoke_then_open_fails_not_found() {
    let (dir, password) = make_vault(2);
    let mut rng = ChaCha20Rng::from_seed([21u8; 32]);
    let enrolled = add_device_slot(dir.path(), &password, &mut rng).expect("enroll");
    remove_device_slot(dir.path(), &enrolled.device_uuid).expect("revoke");
    let err = open_identity_with_device_secret(
        dir.path(),
        &enrolled.device_uuid,
        &enrolled.device_secret,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        secretary_core::vault::VaultError::DeviceSlotNotFound
    ));
}

#[test]
fn two_devices_open_independently() {
    let (dir, password) = make_vault(3);
    let mut rng = ChaCha20Rng::from_seed([22u8; 32]);
    let a = add_device_slot(dir.path(), &password, &mut rng).expect("enroll a");
    let b = add_device_slot(dir.path(), &password, &mut rng).expect("enroll b");
    assert_ne!(a.device_uuid, b.device_uuid);

    let oa =
        open_identity_with_device_secret(dir.path(), &a.device_uuid, &a.device_secret).unwrap();
    let ob =
        open_identity_with_device_secret(dir.path(), &b.device_uuid, &b.device_secret).unwrap();
    assert_eq!(
        oa.identity_block_key.expose(),
        ob.identity_block_key.expose()
    );

    // Revoking A leaves B working.
    remove_device_slot(dir.path(), &a.device_uuid).unwrap();
    assert!(
        open_identity_with_device_secret(dir.path(), &a.device_uuid, &a.device_secret).is_err()
    );
    assert!(open_identity_with_device_secret(dir.path(), &b.device_uuid, &b.device_secret).is_ok());
}

#[test]
fn enroll_with_wrong_password_writes_nothing() {
    let (dir, _password) = make_vault(4);
    let mut rng = ChaCha20Rng::from_seed([23u8; 32]);
    let bad = SecretBytes::new(b"wrong".to_vec());
    assert!(add_device_slot(dir.path(), &bad, &mut rng).is_err());
    let devices = dir.path().join("devices");
    let count = if devices.exists() {
        std::fs::read_dir(&devices).unwrap().count()
    } else {
        0
    };
    assert_eq!(count, 0, "no wrap file may be written on a failed enroll");
}

#[test]
fn open_with_valid_length_but_wrong_secret_surfaces_typed_error() {
    // A valid-LENGTH (32-byte) but wrong device secret must surface the typed
    // wrong-secret error through the folder layer — distinct from DeviceSlotNotFound.
    let (dir, password) = make_vault(5);
    let mut rng = ChaCha20Rng::from_seed([24u8; 32]);
    let enrolled = add_device_slot(dir.path(), &password, &mut rng).expect("enroll");
    let bad_secret = SecretBytes::new(vec![0xFFu8; 32]);
    let err = open_identity_with_device_secret(dir.path(), &enrolled.device_uuid, &bad_secret)
        .unwrap_err();
    assert!(matches!(
        err,
        secretary_core::vault::VaultError::Unlock(
            secretary_core::unlock::UnlockError::WrongDeviceSecretOrCorrupt
        )
    ));
}

#[test]
fn renamed_wrap_file_is_rejected_by_device_uuid_mismatch() {
    // vault-format §3a: header device_uuid must equal the filename's UUID.
    // Simulate a wrap file copied to a different device's filename: opening it
    // under that other device_uuid must be rejected (relabeled-file integrity),
    // even with the correct secret.
    let (dir, password) = make_vault(6);
    let mut rng = ChaCha20Rng::from_seed([25u8; 32]);
    let enrolled = add_device_slot(dir.path(), &password, &mut rng).expect("enroll");

    let devices = dir.path().join("devices");
    let real = devices.join(format!(
        "{}.wrap",
        secretary_core::vault::format_uuid_hyphenated(&enrolled.device_uuid)
    ));
    let bytes = std::fs::read(&real).expect("read enrolled wrap");
    // Copy the bytes (header device_uuid = the enrolled device) to a DIFFERENT
    // device's filename, then open under that other uuid.
    let other_uuid = [0x99u8; 16];
    let fake = devices.join(format!(
        "{}.wrap",
        secretary_core::vault::format_uuid_hyphenated(&other_uuid)
    ));
    std::fs::write(&fake, &bytes).expect("write relabeled wrap");

    let err = open_identity_with_device_secret(dir.path(), &other_uuid, &enrolled.device_secret)
        .unwrap_err();
    assert!(matches!(
        err,
        secretary_core::vault::VaultError::Unlock(
            secretary_core::unlock::UnlockError::DeviceUuidMismatch
        )
    ));
}

/// Local helper mirroring the password open path to get an UnlockedIdentity from a folder.
fn open_identity_with_password(
    folder: &Path,
    password: &SecretBytes,
) -> secretary_core::unlock::UnlockedIdentity {
    let vt = std::fs::read(folder.join("vault.toml")).unwrap();
    let ib = std::fs::read(folder.join("identity.bundle.enc")).unwrap();
    secretary_core::unlock::open_with_password(&vt, &ib, password).unwrap()
}
