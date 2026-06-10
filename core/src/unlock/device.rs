//! Pure (no-I/O) per-device wrap-slot crypto: wrap/unwrap the Identity Block
//! Key under a device KEK, and open a vault from a device secret. The byte
//! container is `device_file`; the KEK is `crypto::kdf::derive_device_kek`.
//! Folder-level enroll/open/revoke live in `crate::vault::device_slot`.
//! See `docs/crypto-design.md` §5a and `docs/vault-format.md` §3a.

use crate::crypto::aead::{decrypt, encrypt, AeadNonce};
use crate::crypto::kdf::{derive_device_kek, TAG_ID_WRAP_DEV};
use crate::crypto::secret::{SecretBytes, Sensitive};
use zeroize::Zeroize as _;

use super::compose_aad;
use super::decrypt_bundle_to_identity;
use super::device_file::{self, DeviceWrapFile, WRAP_CT_PLUS_TAG_LEN};
use super::vault_toml;
use super::{vault_toml_not_utf8, UnlockError, UnlockedIdentity};

/// Convert a boundary `SecretBytes` device secret into the fixed 32-byte form
/// the KEK derivation needs, copying then zeroizing the stack array. A
/// non-32-byte secret is a typed error (external callers in B.2/B.3 supply it).
fn secret_to_array(secret: &SecretBytes) -> Result<Sensitive<[u8; 32]>, UnlockError> {
    let exposed = secret.expose();
    if exposed.len() != 32 {
        return Err(UnlockError::MalformedDeviceSecret { len: exposed.len() });
    }
    let mut arr: [u8; 32] = exposed.try_into().expect("length checked above");
    let out = Sensitive::new(arr);
    arr.zeroize();
    Ok(out)
}

/// Wrap a 32-byte IBK under a device KEK derived from `device_secret` (§5a).
/// Pure and deterministic given `nonce`. The caller supplies the vault and
/// device UUIDs (both are bound into the file; `vault_uuid` is in the AEAD AAD).
pub fn wrap_device_slot(
    ibk: &Sensitive<[u8; 32]>,
    vault_uuid: [u8; 16],
    device_uuid: [u8; 16],
    device_secret: &Sensitive<[u8; 32]>,
    nonce: AeadNonce,
) -> DeviceWrapFile {
    let device_kek = derive_device_kek(device_secret);
    let aad = compose_aad(TAG_ID_WRAP_DEV, &vault_uuid);
    let ct_with_tag = encrypt(&device_kek, &nonce, &aad, ibk.expose())
        .expect("AEAD encrypt of 32-byte IBK is structurally infallible");
    let wrap_dev_ct_with_tag: [u8; WRAP_CT_PLUS_TAG_LEN] = ct_with_tag
        .as_slice()
        .try_into()
        .expect("32-byte plaintext + 16-byte tag = 48 bytes");
    DeviceWrapFile {
        vault_uuid,
        device_uuid,
        wrap_dev_nonce: nonce,
        wrap_dev_ct_with_tag,
    }
}

/// Recover the IBK from a device slot using `device_secret`. AEAD tag failure →
/// [`UnlockError::WrongDeviceSecretOrCorrupt`] (wrong secret, header tampering,
/// or corruption — indistinguishable to the cryptography, per §5a).
pub fn unwrap_device_slot(
    file: &DeviceWrapFile,
    device_secret: &Sensitive<[u8; 32]>,
) -> Result<Sensitive<[u8; 32]>, UnlockError> {
    let device_kek = derive_device_kek(device_secret);
    let aad = compose_aad(TAG_ID_WRAP_DEV, &file.vault_uuid);
    let ibk_bytes = decrypt(
        &device_kek,
        &file.wrap_dev_nonce,
        &aad,
        &file.wrap_dev_ct_with_tag,
    )
    .map_err(|_| UnlockError::WrongDeviceSecretOrCorrupt)?;
    let mut ibk_arr: [u8; 32] = ibk_bytes
        .expose()
        .try_into()
        .map_err(|_| UnlockError::CorruptVault)?;
    let ibk = Sensitive::new(ibk_arr);
    ibk_arr.zeroize();
    Ok(ibk)
}

/// Open a vault from a device secret (the §5a device-slot unlock path). Pure:
/// operates on the three files' bytes, mirroring `open_with_recovery`.
pub fn open_with_device_secret(
    vault_toml_bytes: &[u8],
    device_wrap_bytes: &[u8],
    identity_bundle_bytes: &[u8],
    device_secret: &SecretBytes,
) -> Result<UnlockedIdentity, UnlockError> {
    let vt_str = std::str::from_utf8(vault_toml_bytes).map_err(|_| vault_toml_not_utf8())?;
    let vt = vault_toml::decode(vt_str)?;
    let df = device_file::decode(device_wrap_bytes)?;
    // The device file must belong to this vault. (The identity bundle's own
    // vault_uuid is AEAD-checked when we decrypt the bundle below.)
    if df.vault_uuid != vt.vault_uuid {
        return Err(UnlockError::VaultMismatch);
    }
    let bf = super::bundle_file::decode(identity_bundle_bytes)?;
    if bf.vault_uuid != vt.vault_uuid || bf.created_at_ms != vt.created_at_ms {
        return Err(UnlockError::VaultMismatch);
    }

    let secret = secret_to_array(device_secret)?;
    let identity_block_key = unwrap_device_slot(&df, &secret)?;

    // Final stage: AEAD-decrypt bundle under IBK and CBOR-decode it.
    // Shared with open_with_password and open_with_recovery.
    decrypt_bundle_to_identity(
        identity_block_key,
        &bf.bundle_nonce,
        &bf.bundle_ct_with_tag,
        &vt.vault_uuid,
    )
}

/// Test-only helper: read just the `vault_uuid` out of an encoded identity
/// bundle, so unit tests can wire a wrap without re-plumbing the UUID.
#[cfg(test)]
pub(super) fn device_file_vault_uuid(identity_bundle_bytes: &[u8]) -> [u8; 16] {
    super::bundle_file::decode(identity_bundle_bytes)
        .expect("test bundle decodes")
        .vault_uuid
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aead::random_nonce;
    use crate::crypto::kdf::Argon2idParams;
    use crate::unlock::{create_vault_unchecked, open_with_password};
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    fn fresh_secret(seed: u8) -> Sensitive<[u8; 32]> {
        Sensitive::new([seed; 32])
    }

    #[test]
    fn wrap_then_unwrap_roundtrips_the_ibk() {
        let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
        let ibk = fresh_secret(0xAB);
        let secret = fresh_secret(0x5A);
        let file = wrap_device_slot(&ibk, [9u8; 16], [7u8; 16], &secret, random_nonce(&mut rng));
        let recovered = unwrap_device_slot(&file, &secret).expect("unwrap");
        assert_eq!(recovered.expose(), ibk.expose());
    }

    #[test]
    fn unwrap_with_wrong_secret_is_typed_error() {
        let mut rng = ChaCha20Rng::from_seed([4u8; 32]);
        let ibk = fresh_secret(0xCD);
        let file = wrap_device_slot(
            &ibk,
            [9u8; 16],
            [7u8; 16],
            &fresh_secret(0x01),
            random_nonce(&mut rng),
        );
        let err = unwrap_device_slot(&file, &fresh_secret(0x02)).unwrap_err();
        assert!(matches!(err, UnlockError::WrongDeviceSecretOrCorrupt));
    }

    #[test]
    fn unwrap_rejects_cross_vault_aad() {
        // A slot wrapped for vault A must not unwrap when its header says vault B
        // (the AAD binds vault_uuid; tampering the header breaks the tag).
        let mut rng = ChaCha20Rng::from_seed([5u8; 32]);
        let ibk = fresh_secret(0xEF);
        let secret = fresh_secret(0x5A);
        let mut file =
            wrap_device_slot(&ibk, [0xAA; 16], [7u8; 16], &secret, random_nonce(&mut rng));
        file.vault_uuid = [0xBB; 16]; // pretend it belongs to another vault
        let err = unwrap_device_slot(&file, &secret).unwrap_err();
        assert!(matches!(err, UnlockError::WrongDeviceSecretOrCorrupt));
    }

    #[test]
    fn open_with_device_secret_yields_same_identity_as_password() {
        let mut rng = ChaCha20Rng::from_seed([6u8; 32]);
        let password = SecretBytes::new(b"hunter2".to_vec());
        let v = create_vault_unchecked(
            &password,
            "Alice",
            0,
            Argon2idParams::new(8, 1, 1),
            &mut rng,
        )
        .unwrap();

        // Enroll a device by wrapping the just-created IBK.
        let secret = fresh_secret(0x77);
        let file = wrap_device_slot(
            &v.identity_block_key,
            // vault_uuid is the first 16 bytes the bundle file carries; read it back via
            // the password open path below for the cross-check. Here we re-decode it.
            super::device_file_vault_uuid(&v.identity_bundle_bytes),
            [0x42; 16],
            &secret,
            random_nonce(&mut rng),
        );
        let device_wrap_bytes = device_file::encode(&file);

        let secret_bytes = SecretBytes::new(secret.expose().to_vec());
        let by_dev = open_with_device_secret(
            &v.vault_toml_bytes,
            &device_wrap_bytes,
            &v.identity_bundle_bytes,
            &secret_bytes,
        )
        .expect("open with device secret");
        let by_pw =
            open_with_password(&v.vault_toml_bytes, &v.identity_bundle_bytes, &password).unwrap();
        assert_eq!(
            by_dev.identity_block_key.expose(),
            by_pw.identity_block_key.expose()
        );
        assert_eq!(by_dev.identity.user_uuid, by_pw.identity.user_uuid);
    }

    #[test]
    fn open_with_device_secret_rejects_vault_uuid_mismatch_in_device_wrap() {
        // Exercises the `df.vault_uuid != vt.vault_uuid` early check at the
        // open_with_device_secret level — distinct from the AEAD-level cross-vault
        // test (`unwrap_rejects_cross_vault_aad`), which verifies the inner
        // unwrap_device_slot path. Here we confirm the open-level check fires
        // BEFORE any IBK recovery attempt.
        let mut rng = ChaCha20Rng::from_seed([8u8; 32]);
        let password = SecretBytes::new(b"hunter2".to_vec());
        let v = create_vault_unchecked(
            &password,
            "Alice",
            0,
            Argon2idParams::new(8, 1, 1),
            &mut rng,
        )
        .unwrap();

        let secret = fresh_secret(0x77);
        let real_uuid = device_file_vault_uuid(&v.identity_bundle_bytes);
        let file = wrap_device_slot(
            &v.identity_block_key,
            real_uuid,
            [0x42; 16],
            &secret,
            random_nonce(&mut rng),
        );
        // Re-encode the file with a tampered vault_uuid so it claims to belong
        // to a different vault than vault.toml records.
        let mut tampered_file = file;
        tampered_file.vault_uuid = [0xFF; 16]; // different vault
        let device_wrap_bytes = device_file::encode(&tampered_file);

        let secret_bytes = SecretBytes::new(secret.expose().to_vec());
        let err = open_with_device_secret(
            &v.vault_toml_bytes,
            &device_wrap_bytes,
            &v.identity_bundle_bytes,
            &secret_bytes,
        )
        .unwrap_err();
        assert!(
            matches!(err, UnlockError::VaultMismatch),
            "expected VaultMismatch, got {err:?}"
        );
    }

    #[test]
    fn open_with_device_secret_rejects_wrong_length_secret() {
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let password = SecretBytes::new(b"hunter2".to_vec());
        let v = create_vault_unchecked(
            &password,
            "Alice",
            0,
            Argon2idParams::new(8, 1, 1),
            &mut rng,
        )
        .unwrap();
        let secret = fresh_secret(0x77);
        let file = wrap_device_slot(
            &v.identity_block_key,
            super::device_file_vault_uuid(&v.identity_bundle_bytes),
            [0x42; 16],
            &secret,
            random_nonce(&mut rng),
        );
        let device_wrap_bytes = device_file::encode(&file);
        let short = SecretBytes::new(vec![0u8; 31]);
        let err = open_with_device_secret(
            &v.vault_toml_bytes,
            &device_wrap_bytes,
            &v.identity_bundle_bytes,
            &short,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            UnlockError::MalformedDeviceSecret { len: 31 }
        ));
    }
}
