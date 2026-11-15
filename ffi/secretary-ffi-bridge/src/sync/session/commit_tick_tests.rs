//! #744: both commit-decisions entry points forward the caller's
//! `device_uuid` as the merging device, on the manifest and block clocks.

use std::path::Path;

use secretary_core::crypto::secret::SecretBytes;
use secretary_core::vault::{open_vault, Unlocker, VectorClockEntry};

use super::tests::open_fixture;
use super::*;
use crate::test_support::VAULT_001_PASSWORD;
use crate::{sync_commit_decisions_in, sync_vault_in};

/// Both commit-decisions entry points forward their `device_uuid` as the
/// merging device: the written manifest clock and a merged block's clock gain
/// an entry for it (#744). Distinct devices per entry point, so a swap reds.
#[test]
fn a_commit_decisions_merge_ticks_the_callers_device_uuid() {
    fn keep_all(vetoes: &[crate::VetoDto]) -> Vec<VetoDecisionDto> {
        vetoes
            .iter()
            .map(|v| VetoDecisionDto {
                record_uuid_hex: v.record_uuid_hex.clone(),
                keep_local: true,
            })
            .collect()
    }
    fn assert_ticked(vault: &Path, device: [u8; 16]) {
        let pw = SecretBytes::new(VAULT_001_PASSWORD.to_vec());
        let disk = open_vault(vault, Unlocker::Password(&pw), None).expect("open");
        let tick = VectorClockEntry {
            device_uuid: device,
            counter: 1,
        };
        assert!(disk.manifest.vector_clock.contains(&tick), "manifest tick");
        assert!(
            disk.manifest
                .blocks
                .iter()
                .any(|b| b.vector_clock_summary.contains(&tick)),
            "block tick"
        );
    }

    let session_device = [0x73; 16];
    let (vault_tmp, state_tmp, out) = open_fixture("sync_conflict_fixture");
    let SyncOutcomeDto::ConflictsPending {
        vetoes,
        manifest_hash,
        ..
    } = sync_vault_with_session_in(
        state_tmp.path(),
        &out.identity,
        &out.manifest,
        session_device,
        1,
    )
    .expect("inspect pass")
    else {
        panic!("expected ConflictsPending");
    };
    sync_commit_decisions_with_session_in(
        state_tmp.path(),
        &out.identity,
        &out.manifest,
        keep_all(&vetoes),
        manifest_hash,
        session_device,
        2,
    )
    .expect("session commit");
    assert_ticked(vault_tmp.path(), session_device);

    let password_device = [0x74; 16];
    let (vault_tmp, state_tmp, _out) = open_fixture("sync_conflict_fixture");
    let pw = || SecretBytes::new(VAULT_001_PASSWORD.to_vec());
    let SyncOutcomeDto::ConflictsPending {
        vetoes,
        manifest_hash,
        ..
    } = sync_vault_in(state_tmp.path(), vault_tmp.path(), pw(), password_device, 1)
        .expect("inspect pass")
    else {
        panic!("expected ConflictsPending");
    };
    sync_commit_decisions_in(
        state_tmp.path(),
        vault_tmp.path(),
        pw(),
        keep_all(&vetoes),
        manifest_hash,
        password_device,
        2,
    )
    .expect("password commit");
    assert_ticked(vault_tmp.path(), password_device);
}
