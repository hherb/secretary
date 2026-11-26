use super::tombstone_veto_set;
use crate::crypto::secret::SecretString;
use crate::sync::draft::BlockId;
use crate::vault::record::{Record, RecordField, RecordFieldValue};
use std::collections::BTreeMap;

/// Construct a test [`Record`] with explicit tombstone state. All
/// other fields take placeholder defaults — `tombstone_veto_set`
/// only inspects `record_uuid`, `last_mod_ms`, `tombstone`,
/// `tombstoned_at_ms`, and (via `last_modifier_device`) `fields`.
fn rec(uuid: u8, last_mod_ms: u64, tombstone: bool, tombstoned_at_ms: u64) -> Record {
    Record {
        record_uuid: [uuid; 16],
        record_type: "kv".into(),
        fields: BTreeMap::new(),
        tags: Vec::new(),
        created_at_ms: 0,
        last_mod_ms,
        tombstone,
        tombstoned_at_ms,
        unknown: BTreeMap::new(),
    }
}

/// Construct a tombstoned peer [`Record`] carrying a single
/// placeholder field with the supplied `field_device` as its
/// `device_uuid`. Used to exercise the `last_modifier_device`
/// happy path (`max_by_key(|f| f.last_mod)` returns `Some`).
fn peer_with_field(
    uuid: u8,
    last_mod_ms: u64,
    tombstoned_at_ms: u64,
    field_device: [u8; 16],
) -> Record {
    let mut fields = BTreeMap::new();
    fields.insert(
        "username".to_string(),
        RecordField {
            value: RecordFieldValue::Text(SecretString::new(String::new())),
            last_mod: last_mod_ms,
            device_uuid: field_device,
            unknown: BTreeMap::new(),
        },
    );
    Record {
        record_uuid: [uuid; 16],
        record_type: "kv".into(),
        fields,
        tags: Vec::new(),
        created_at_ms: 0,
        last_mod_ms,
        tombstone: true,
        tombstoned_at_ms,
        unknown: BTreeMap::new(),
    }
}

/// Block-uuid placeholder used by every veto-set assertion. The
/// value is opaque — `tombstone_veto_set` only forwards it into
/// the returned `RecordTombstoneVeto.block_id`.
const TEST_BLOCK_UUID: BlockId = [0xBB; 16];

#[test]
fn no_peers_no_veto() {
    let local = rec(1, 100, false, 0);
    assert!(tombstone_veto_set(&local, TEST_BLOCK_UUID, &[]).is_none());
}

#[test]
fn peer_live_no_veto() {
    let local = rec(1, 100, false, 0);
    let peer = rec(1, 200, false, 0);
    assert!(tombstone_veto_set(&local, TEST_BLOCK_UUID, &[&peer]).is_none());
}

#[test]
fn peer_tombstoned_before_local_edit_no_veto() {
    // local edited at t=100; peer tombstoned at t=50. Local
    // last_mod_ms (100) > peer.tombstoned_at_ms (50). LWW already
    // wins; no veto needed.
    let local = rec(1, 100, false, 0);
    let peer = rec(1, 50, true, 50);
    assert!(tombstone_veto_set(&local, TEST_BLOCK_UUID, &[&peer]).is_none());
}

#[test]
fn peer_tombstoned_at_same_instant_as_local_edit_no_veto() {
    // Boundary: strict-later predicate. Equality goes silent.
    let local = rec(1, 100, false, 0);
    let peer = rec(1, 100, true, 100);
    assert!(tombstone_veto_set(&local, TEST_BLOCK_UUID, &[&peer]).is_none());
}

#[test]
fn peer_tombstoned_after_local_edit_vetoes() {
    let local = rec(1, 100, false, 0);
    let peer = rec(1, 200, true, 200);
    let veto = tombstone_veto_set(&local, TEST_BLOCK_UUID, &[&peer]).expect("expected veto");
    assert_eq!(veto.record_id, [1; 16]);
    assert_eq!(veto.block_id, TEST_BLOCK_UUID);
    assert_eq!(veto.disk_tombstone_at_ms, 200);
}

#[test]
fn local_tombstoned_no_veto_regardless_of_peer() {
    let local = rec(1, 100, true, 100);
    let peer = rec(1, 200, true, 200);
    assert!(tombstone_veto_set(&local, TEST_BLOCK_UUID, &[&peer]).is_none());
}

#[test]
fn multiple_peers_latest_wins() {
    let local = rec(1, 100, false, 0);
    let peer_a = rec(1, 200, true, 200);
    let peer_b = rec(1, 300, true, 300);
    let veto =
        tombstone_veto_set(&local, TEST_BLOCK_UUID, &[&peer_a, &peer_b]).expect("expected veto");
    assert_eq!(veto.disk_tombstone_at_ms, 300);
}

/// `last_modifier_device` returns the `device_uuid` of the field
/// with the maximum `last_mod`. When the peer record has a single
/// field, that field's `device_uuid` is propagated unchanged into
/// the returned veto's `disk_tombstoner_device`. Closes the gap
/// that the empty-fields tests leave (they always exercise the
/// `None` branch and the all-zero sentinel).
#[test]
fn veto_propagates_peer_field_device() {
    let local = rec(1, 100, false, 0);
    let peer = peer_with_field(1, 200, 200, [0x42; 16]);
    let veto = tombstone_veto_set(&local, TEST_BLOCK_UUID, &[&peer]).expect("expected veto");
    assert_eq!(veto.disk_tombstone_at_ms, 200);
    assert_eq!(veto.disk_tombstoner_device, [0x42; 16]);
}

/// On tied `tombstoned_at_ms` across peers, the veto carries the
/// lexicographically smallest `device_uuid`. The result is
/// independent of slice iteration order — running the helper on
/// both peer orderings yields the same veto.
#[test]
fn tied_timestamps_smallest_device_wins() {
    let local = rec(1, 100, false, 0);
    let peer_high = peer_with_field(1, 200, 200, [0xFF; 16]);
    let peer_low = peer_with_field(1, 200, 200, [0x01; 16]);

    let v1 = tombstone_veto_set(&local, TEST_BLOCK_UUID, &[&peer_high, &peer_low])
        .expect("expected veto");
    let v2 = tombstone_veto_set(&local, TEST_BLOCK_UUID, &[&peer_low, &peer_high])
        .expect("expected veto");

    assert_eq!(v1.disk_tombstone_at_ms, 200);
    assert_eq!(v1.disk_tombstoner_device, [0x01; 16]);
    assert_eq!(v2.disk_tombstone_at_ms, 200);
    assert_eq!(v2.disk_tombstoner_device, [0x01; 16]);
}

#[test]
fn merge_trash_lists_is_wired_into_prepare_merge_shape() {
    // Compile-level guard: the fold helper is reachable from this module
    // and produces a sorted union. Full integration coverage is in
    // core/tests/ (Task 7). It does not pin prepare_merge's wiring, which
    // goes through `trash_collision::resolved_trash`; the integration tests
    // in sync_trash_merge.rs and sync_trash_vs_live.rs do.
    use crate::vault::manifest::TrashEntry;
    use crate::vault::trash_merge::merge_trash_lists;
    use std::collections::BTreeMap;
    let a = TrashEntry {
        block_uuid: [2; 16],
        tombstoned_at_ms: 1,
        tombstoned_by: [0; 16],
        fingerprint: None,
        purged_at_ms: None,
        unknown: BTreeMap::new(),
    };
    let b = TrashEntry {
        block_uuid: [1; 16],
        tombstoned_at_ms: 1,
        tombstoned_by: [0; 16],
        fingerprint: None,
        purged_at_ms: Some(9),
        unknown: BTreeMap::new(),
    };
    let merged = merge_trash_lists(&[&[a][..], &[b][..]]);
    assert_eq!(merged.len(), 2);
    assert_eq!(merged[0].block_uuid, [1; 16]);
    assert_eq!(merged[0].purged_at_ms, Some(9));
}
