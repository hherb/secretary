//! #730: a `SilentMerge` pass (concurrent clocks, no block diverged) commits a
//! manifest-only merge, as crypto-design §10 requires of a concurrent clock.
//! Before the fix it saved the LUB clock without writing it, so the saved clock
//! strictly dominated the disk and this device's next pass, refresh and open
//! were all refused as a rollback.

use secretary_core::crypto::secret::SecretBytes;
use secretary_core::vault::{open_vault, Unlocker};
use tempfile::TempDir;

use super::tests::{has_block, seed_concurrent_state, session_and_other_writer, write_block};
use super::*;
use crate::test_support::{TEST_DEVICE_UUID, VAULT_001_PASSWORD};
use crate::vault::orchestration::enforce_rollback_resistance_in;
use crate::{sync_vault_in, sync_vault_with_session_in};

fn password() -> SecretBytes {
    SecretBytes::new(VAULT_001_PASSWORD.to_vec())
}

#[test]
fn a_password_silent_merge_leaves_the_device_able_to_sync_open_and_write() {
    let (tmp, session, other_block) = session_and_other_writer();
    let state_dir = TempDir::new().unwrap();
    seed_concurrent_state(state_dir.path(), &session);

    let first = sync_vault_in(
        state_dir.path(),
        tmp.path(),
        password(),
        TEST_DEVICE_UUID,
        2_000,
    )
    .expect("pass");
    assert_eq!(first, SyncOutcomeDto::SilentMerge);

    // Each of these was refused as a rollback before #730 was fixed.
    let repeat = sync_vault_in(
        state_dir.path(),
        tmp.path(),
        password(),
        TEST_DEVICE_UUID,
        3_000,
    )
    .expect("pass");
    assert_eq!(repeat, SyncOutcomeDto::NothingToDo);
    let core_out = open_vault(tmp.path(), Unlocker::Password(&password()), None).expect("open");
    enforce_rollback_resistance_in(state_dir.path(), &core_out).expect("next open's §10 check");
    refresh_manifest_in(state_dir.path(), &session.identity, &session.manifest).expect("refresh");

    assert!(has_block(&session, &other_block));
    write_block(&session).expect("write after the merge");
}

#[test]
fn a_session_silent_merge_is_followed_by_nothing_to_do() {
    let (_tmp, session, _other_block) = session_and_other_writer();
    let state_dir = TempDir::new().unwrap();
    seed_concurrent_state(state_dir.path(), &session);

    let first = sync_vault_with_session_in(
        state_dir.path(),
        &session.identity,
        &session.manifest,
        TEST_DEVICE_UUID,
        2_000,
    )
    .expect("pass");
    assert_eq!(first, SyncOutcomeDto::SilentMerge);
    let repeat = sync_vault_with_session_in(
        state_dir.path(),
        &session.identity,
        &session.manifest,
        TEST_DEVICE_UUID,
        3_000,
    )
    .expect("pass");
    assert_eq!(repeat, SyncOutcomeDto::NothingToDo);
    write_block(&session).expect("write after the merge");
}

/// The merge is written: the disk clock now carries the seeded state's entry
/// for a device the disk had never seen, and it equals the saved clock.
#[test]
fn a_silent_merge_writes_a_manifest_carrying_the_local_clock() {
    let (tmp, session, _other_block) = session_and_other_writer();
    let state_dir = TempDir::new().unwrap();
    seed_concurrent_state(state_dir.path(), &session);
    let vault_uuid: [u8; 16] = session.manifest.vault_uuid().try_into().unwrap();
    let seeded = secretary_cli::state::load(state_dir.path(), vault_uuid).expect("seeded state");

    sync_vault_in(
        state_dir.path(),
        tmp.path(),
        password(),
        TEST_DEVICE_UUID,
        2_000,
    )
    .expect("pass");

    let core_out = open_vault(tmp.path(), Unlocker::Password(&password()), None).expect("open");
    let disk = &core_out.manifest.vector_clock;
    for e in &seeded.highest_vector_clock_seen {
        assert!(
            disk.contains(e),
            "disk clock {disk:?} lacks seeded entry {e:?}"
        );
    }
    let saved = secretary_cli::state::load(state_dir.path(), vault_uuid).expect("saved state");
    assert_eq!(
        &saved.highest_vector_clock_seen, disk,
        "saved clock == disk clock"
    );
}

/// Both bridge entry points forward their `device_uuid` as the merging device:
/// the written clock gains a fresh entry for it (#744).
#[test]
fn a_silent_merge_ticks_the_callers_device_uuid() {
    let tick = |device: [u8; 16]| secretary_core::vault::VectorClockEntry {
        device_uuid: device,
        counter: 1,
    };

    let (tmp, session, _other_block) = session_and_other_writer();
    let state_dir = TempDir::new().unwrap();
    seed_concurrent_state(state_dir.path(), &session);
    let session_device = [0x71; 16];
    let outcome = sync_vault_with_session_in(
        state_dir.path(),
        &session.identity,
        &session.manifest,
        session_device,
        2_000,
    )
    .expect("session pass");
    assert_eq!(outcome, SyncOutcomeDto::SilentMerge);
    let disk = open_vault(tmp.path(), Unlocker::Password(&password()), None).expect("open");
    assert!(disk.manifest.vector_clock.contains(&tick(session_device)));

    let (tmp, session, _other_block) = session_and_other_writer();
    let state_dir = TempDir::new().unwrap();
    seed_concurrent_state(state_dir.path(), &session);
    let password_device = [0x72; 16];
    sync_vault_in(
        state_dir.path(),
        tmp.path(),
        password(),
        password_device,
        2_000,
    )
    .expect("password pass");
    let disk = open_vault(tmp.path(), Unlocker::Password(&password()), None).expect("open");
    assert!(disk.manifest.vector_clock.contains(&tick(password_device)));
}
