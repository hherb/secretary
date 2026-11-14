//! Stale-base guard on every manifest writer (#101, design spec §5.2).
//!
//! A session's in-memory `OpenVault` manifest goes stale when another open
//! (or the cloud client) writes a newer `manifest.cbor.enc`. Every writer
//! that takes an `OpenVault` must then refuse with
//! `VaultError::ManifestChangedOnDisk` BEFORE touching any file, so the
//! newer manifest is never silently reverted. Each refusal test asserts the
//! whole vault folder is byte-identical afterwards.

#![forbid(unsafe_code)]

mod stale_session_guard_helpers;

use std::fs;

use rand_core::OsRng;
use secretary_core::crypto::secret::Sensitive;
use secretary_core::crypto::sig::{Ed25519Secret, MlDsa65Secret};
use secretary_core::vault::{
    auto_purge_expired, decode_manifest_file, empty_trash, encode_manifest_file,
    format_uuid_hyphenated, purge_block, repair_vault, restore_block, revoke_block_recipient,
    share_block, trash_block, BlockUuid, DeviceUuid, OpenVault, RecipientUuid, RepairPolicy,
    Unlocker,
};
use secretary_test_utils::core_test_data_dir;
use stale_session_guard_helpers::{external_card, save, snapshot_tree, uuid, Fixture, T0};

/// Save one owner-only block through a throwaway handle and return its uuid.
fn seed_block(f: &Fixture) -> [u8; 16] {
    let mut h = f.open();
    let owner = h.owner_card.clone();
    let block = uuid();
    save(f.folder(), &mut h, block, &[owner], T0).unwrap();
    block
}

/// Save then trash one block through a throwaway handle.
fn seed_trashed_block(f: &Fixture) -> [u8; 16] {
    let block = seed_block(f);
    let mut h = f.open();
    trash_block(f.folder(), &mut h, block, uuid(), T0 + 1_000, &mut OsRng).unwrap();
    block
}

fn owner_signing_keys(open: &OpenVault) -> (Ed25519Secret, MlDsa65Secret) {
    let ed: Ed25519Secret = Sensitive::new(*open.identity.ed25519_sk.expose());
    let pq = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose()).unwrap();
    (ed, pq)
}

#[test]
fn stale_handle_save_block_is_refused_and_disk_untouched() {
    let f = Fixture::new();
    let (mut stale, _fresh) = f.stale_and_fresh();
    let before = snapshot_tree(f.folder());
    let owner = stale.owner_card.clone();
    let r = save(f.folder(), &mut stale, uuid(), &[owner], T0 + 6_000);
    f.assert_refused_untouched(&before, r);
}

#[test]
fn stale_share_block_is_refused() {
    let f = Fixture::new();
    let block = seed_block(&f);
    let (mut stale, _fresh) = f.stale_and_fresh();
    let before = snapshot_tree(f.folder());
    let owner = stale.owner_card.clone();
    let (ed, pq) = owner_signing_keys(&stale);
    let r = share_block(
        f.folder(),
        &mut stale,
        BlockUuid::new(block),
        &owner,
        &ed,
        &pq,
        std::slice::from_ref(&owner),
        &external_card("Alice"),
        DeviceUuid::new(uuid()),
        T0 + 6_000,
        &mut OsRng,
    );
    f.assert_refused_untouched(&before, r);
}

#[test]
fn stale_revoke_is_refused() {
    let f = Fixture::new();
    let alice = external_card("Alice");
    let block = uuid();
    {
        let mut h = f.open();
        let owner = h.owner_card.clone();
        save(f.folder(), &mut h, block, &[owner, alice.clone()], T0).unwrap();
    }
    let (mut stale, _fresh) = f.stale_and_fresh();
    let before = snapshot_tree(f.folder());
    let owner = stale.owner_card.clone();
    let (ed, pq) = owner_signing_keys(&stale);
    let r = revoke_block_recipient(
        f.folder(),
        &mut stale,
        BlockUuid::new(block),
        &owner,
        &ed,
        &pq,
        &[owner.clone(), alice.clone()],
        RecipientUuid::new(alice.contact_uuid),
        DeviceUuid::new(uuid()),
        T0 + 6_000,
        &mut OsRng,
    );
    f.assert_refused_untouched(&before, r);
}

#[test]
fn stale_trash_block_is_refused() {
    let f = Fixture::new();
    let block = seed_block(&f);
    let (mut stale, _fresh) = f.stale_and_fresh();
    let before = snapshot_tree(f.folder());
    let r = trash_block(
        f.folder(),
        &mut stale,
        block,
        uuid(),
        T0 + 6_000,
        &mut OsRng,
    );
    f.assert_refused_untouched(&before, r);
}

#[test]
fn stale_restore_block_is_refused() {
    let f = Fixture::new();
    let block = seed_trashed_block(&f);
    let (mut stale, _fresh) = f.stale_and_fresh();
    let before = snapshot_tree(f.folder());
    let r = restore_block(
        f.folder(),
        &mut stale,
        block,
        uuid(),
        T0 + 6_000,
        &mut OsRng,
    );
    f.assert_refused_untouched(&before, r);
}

#[test]
fn stale_purge_block_is_refused() {
    let f = Fixture::new();
    let block = seed_trashed_block(&f);
    let (mut stale, _fresh) = f.stale_and_fresh();
    let before = snapshot_tree(f.folder());
    let r = purge_block(
        f.folder(),
        &mut stale,
        block,
        uuid(),
        T0 + 6_000,
        &mut OsRng,
    );
    f.assert_refused_untouched(&before, r);
}

/// The idempotent re-purge branch writes no manifest but does delete
/// residual `trash/` files, so the guard must precede it too.
#[test]
fn stale_repurge_branch_deletes_nothing() {
    let f = Fixture::new();
    let block = seed_trashed_block(&f);
    {
        let mut h = f.open();
        purge_block(f.folder(), &mut h, block, uuid(), T0 + 2_000, &mut OsRng).unwrap();
    }
    let (mut stale, _fresh) = f.stale_and_fresh();
    // Crash residue the re-purge branch would otherwise clean up. Planted
    // after both opens, whose sweep would remove it.
    let residue = f.folder().join("trash").join(format!(
        "{}.cbor.enc.{}",
        format_uuid_hyphenated(&block),
        T0 + 1_000
    ));
    fs::write(&residue, b"residue").unwrap();
    let before = snapshot_tree(f.folder());
    let r = purge_block(
        f.folder(),
        &mut stale,
        block,
        uuid(),
        T0 + 6_000,
        &mut OsRng,
    );
    f.assert_refused_untouched(&before, r);
}

#[test]
fn stale_empty_trash_is_refused() {
    let f = Fixture::new();
    seed_trashed_block(&f);
    let (mut stale, _fresh) = f.stale_and_fresh();
    let before = snapshot_tree(f.folder());
    let r = empty_trash(f.folder(), &mut stale, uuid(), T0 + 6_000, &mut OsRng);
    f.assert_refused_untouched(&before, r);
}

#[test]
fn stale_auto_purge_is_refused() {
    let f = Fixture::new();
    seed_trashed_block(&f);
    let (mut stale, _fresh) = f.stale_and_fresh();
    let before = snapshot_tree(f.folder());
    // Window 1 ms, tombstoned at T0 + 1_000: expired at T0 + 6_000.
    let r = auto_purge_expired(f.folder(), &mut stale, 1, T0 + 6_000, uuid(), &mut OsRng);
    f.assert_refused_untouched(&before, r);
}

/// Seam: `repair_vault`'s `load_baseline` callback runs after repair has
/// read and verified the manifest and before it writes one. The callback
/// plays "another process" and lands the manifest a crashed save had lost.
#[test]
fn stale_repair_vault_is_refused() {
    let f = Fixture::new();
    let manifest_path = f.folder().join("manifest.cbor.enc");
    let block = uuid();
    let newer_manifest = {
        let mut h = f.open();
        let owner = h.owner_card.clone();
        save(f.folder(), &mut h, block, std::slice::from_ref(&owner), T0).unwrap();
        let v1 = fs::read(&manifest_path).unwrap();
        save(f.folder(), &mut h, block, &[owner], T0 + 1_000).unwrap();
        let v2 = fs::read(&manifest_path).unwrap();
        // Crash residue: the v2 block hit disk, the v2 manifest did not.
        fs::write(&manifest_path, &v1).unwrap();
        v2
    };

    let mut before = None;
    let r = repair_vault(
        f.folder(),
        Unlocker::Password(&f.pw),
        |_| {
            fs::write(&manifest_path, &newer_manifest).unwrap();
            before = Some(snapshot_tree(f.folder()));
            Ok(None)
        },
        uuid(),
        T0 + 6_000,
        &mut OsRng,
        RepairPolicy::FailClosed,
    );
    f.assert_refused_untouched(&before.expect("baseline callback ran"), r);
}

/// No false positive: a handle's own writes keep its envelope current.
#[test]
fn own_write_chain_is_never_refused() {
    let f = Fixture::new();
    let mut h = f.open();
    let owner = h.owner_card.clone();
    let (folder, device) = (f.folder(), uuid());
    let (a, b) = (uuid(), uuid());
    save(folder, &mut h, a, std::slice::from_ref(&owner), T0).unwrap();
    trash_block(folder, &mut h, a, device, T0 + 1, &mut OsRng).unwrap();
    restore_block(folder, &mut h, a, device, T0 + 2, &mut OsRng).unwrap();
    trash_block(folder, &mut h, a, device, T0 + 3, &mut OsRng).unwrap();
    purge_block(folder, &mut h, a, device, T0 + 4, &mut OsRng).unwrap();
    save(folder, &mut h, b, &[owner], T0 + 5).unwrap();
    trash_block(folder, &mut h, b, device, T0 + 6, &mut OsRng).unwrap();
    let report = empty_trash(folder, &mut h, device, T0 + 7, &mut OsRng).unwrap();
    assert_eq!(report.purged_count, 1, "empty_trash must have written");
}

/// The guard compares raw bytes against `encode_manifest_file(expected)`,
/// which is sound only if the envelope encoding round-trips exactly.
#[test]
fn manifest_envelope_round_trips_byte_identically() {
    let mut checked = 0;
    for entry in fs::read_dir(core_test_data_dir()).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !(path.is_dir() && name.starts_with("golden_vault_")) {
            continue;
        }
        let bytes = fs::read(path.join("manifest.cbor.enc")).unwrap();
        let reencoded = encode_manifest_file(&decode_manifest_file(&bytes).unwrap()).unwrap();
        assert_eq!(
            reencoded, bytes,
            "{name}: manifest envelope must round-trip"
        );
        checked += 1;
    }
    assert!(
        checked >= 2,
        "expected golden_vault_001 and _002, checked {checked}"
    );
}
