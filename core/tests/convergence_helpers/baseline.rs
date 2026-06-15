//! Fast on-disk vault builder for C.4 convergence tests. Wraps the
//! `make_fast_vault` pattern from `save_block.rs` in a named type so
//! later convergence tasks can compose it without re-implementing the
//! construction each time.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use rand_core::RngCore;

use secretary_core::crypto::kdf::Argon2idParams;
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::crypto::sig::{MlDsa65Secret, ED25519_SIG_LEN, ML_DSA_65_SIG_LEN};
use secretary_core::identity::card::{ContactCard, CARD_VERSION_V1};
use secretary_core::identity::fingerprint::fingerprint;
use secretary_core::unlock::{create_vault_unchecked, vault_toml};
use secretary_core::vault::{
    encode_manifest_file, format_uuid_hyphenated, open_vault, sign_manifest, KdfParamsRef,
    Manifest, ManifestHeader, Unlocker,
};
use secretary_core::version::{FORMAT_VERSION, SUITE_ID};

pub const BASELINE_PASSWORD: &[u8] = b"c4-convergence-test-password";
pub const BASELINE_CREATED_AT_MS: u64 = 1_714_060_800_000;
const BASELINE_SEED: u8 = 0xC4;

fn fast_kdf() -> Argon2idParams {
    Argon2idParams::new(8, 1, 1)
}

pub struct Baseline {
    _tmp: tempfile::TempDir,
    folder: PathBuf,
    password: SecretBytes,
}

impl Baseline {
    pub fn create() -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let folder = tmp.path().to_path_buf();
        let mut rng = ChaCha20Rng::from_seed([BASELINE_SEED; 32]);
        let password = SecretBytes::new(BASELINE_PASSWORD.to_vec());

        let created = create_vault_unchecked(
            &password,
            "C4 Convergence",
            BASELINE_CREATED_AT_MS,
            fast_kdf(),
            &mut rng,
        )
        .expect("create_vault_unchecked");

        let vt = vault_toml::decode(std::str::from_utf8(&created.vault_toml_bytes).unwrap())
            .expect("decode vault.toml");

        let pq_sk = MlDsa65Secret::from_bytes(created.identity.ml_dsa_65_sk.expose()).unwrap();
        let mut card = ContactCard {
            card_version: CARD_VERSION_V1,
            contact_uuid: created.identity.user_uuid,
            display_name: created.identity.display_name.clone(),
            x25519_pk: created.identity.x25519_pk,
            ml_kem_768_pk: created.identity.ml_kem_768_pk.clone(),
            ed25519_pk: created.identity.ed25519_pk,
            ml_dsa_65_pk: created.identity.ml_dsa_65_pk.clone(),
            created_at_ms: created.identity.created_at_ms,
            self_sig_ed: [0u8; ED25519_SIG_LEN],
            self_sig_pq: vec![0u8; ML_DSA_65_SIG_LEN],
        };
        card.sign(&created.identity.ed25519_sk, &pq_sk).unwrap();
        let owner_card_bytes = card.to_canonical_cbor().unwrap();
        let author_fp = fingerprint(&owner_card_bytes);

        let manifest_body = Manifest {
            manifest_version: 1,
            vault_uuid: vt.vault_uuid,
            format_version: FORMAT_VERSION,
            suite_id: SUITE_ID,
            owner_user_uuid: created.identity.user_uuid,
            vector_clock: Vec::new(),
            blocks: Vec::new(),
            trash: Vec::new(),
            kdf_params: KdfParamsRef {
                memory_kib: vt.kdf.memory_kib,
                iterations: vt.kdf.iterations,
                parallelism: vt.kdf.parallelism,
                salt: vt.kdf.salt,
            },
            unknown: BTreeMap::new(),
        };
        let header = ManifestHeader {
            vault_uuid: vt.vault_uuid,
            created_at_ms: BASELINE_CREATED_AT_MS,
            last_mod_ms: BASELINE_CREATED_AT_MS,
        };
        let mut nonce = [0u8; 24];
        rng.fill_bytes(&mut nonce);

        let mf = sign_manifest(
            header,
            &manifest_body,
            &created.identity_block_key,
            &nonce,
            author_fp,
            &created.identity.ed25519_sk,
            &pq_sk,
        )
        .unwrap();
        let mf_bytes = encode_manifest_file(&mf).unwrap();

        let owner_uuid_hex = format_uuid_hyphenated(&created.identity.user_uuid);
        let contacts_dir = folder.join("contacts");
        fs::create_dir_all(&contacts_dir).unwrap();
        fs::write(folder.join("vault.toml"), &created.vault_toml_bytes).unwrap();
        fs::write(
            folder.join("identity.bundle.enc"),
            &created.identity_bundle_bytes,
        )
        .unwrap();
        fs::write(
            contacts_dir.join(format!("{owner_uuid_hex}.card")),
            &owner_card_bytes,
        )
        .unwrap();
        fs::write(folder.join("manifest.cbor.enc"), &mf_bytes).unwrap();

        Self {
            _tmp: tmp,
            folder,
            password,
        }
    }

    /// Build a new baseline whose on-disk state is a deep copy of an
    /// already-edited device folder — used to seed a common-ancestor
    /// record both devices then edit. The password is unchanged.
    pub fn from_folder(src: &Path, password: SecretBytes) -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let folder = tmp.path().to_path_buf();
        crate::convergence_helpers::copy_dir_all(src, &folder).expect("copy seeded folder");
        Self {
            _tmp: tmp,
            folder,
            password,
        }
    }

    pub fn folder(&self) -> &Path {
        &self.folder
    }

    pub fn password(&self) -> &SecretBytes {
        &self.password
    }

    /// Opens the vault (a full cryptographic unlock via open_vault) and returns the decrypted
    /// manifest; the identity_block_key and other OpenVault fields are dropped (and zeroized)
    /// on return.
    pub fn open_manifest(&self) -> Manifest {
        let open = open_vault(&self.folder, Unlocker::Password(&self.password), None)
            .expect("open baseline");
        open.manifest
    }
}
