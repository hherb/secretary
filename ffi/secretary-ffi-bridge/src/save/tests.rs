//! `save_block` over an EXISTING block (#766): an update must carry forward
//! everything the foreign caller cannot see, exactly as the edit primitives
//! do. Constructed via `core` because the bridge input types intentionally
//! cannot mint `unknown` keys or versions above v1.

use std::collections::BTreeMap;

use secretary_core::crypto::secret::SecretString;
use secretary_core::vault::block::BlockPlaintext;
use secretary_core::vault::record::{Record, RecordField, RecordFieldValue, UnknownValue};

use super::{save_block, BlockInput, FieldInput, FieldInputValue, RecordInput};
use crate::record::orchestration::decrypt_block_plaintext;
use crate::test_support::open_writable_golden_001;

const ORIG_DEVICE: [u8; 16] = [0x07; 16];
const SAVE_DEVICE: [u8; 16] = [0x09; 16];
const SEED_MS: u64 = 1_000;
const TOMBSTONED_MS: u64 = 1_500;
const SAVE_MS: u64 = 2_000;
/// Distinct from v1 and from each other, so a swap or a v1 reset is caught.
const LATER_BLOCK_VERSION: u32 = 2;
const LATER_SCHEMA_VERSION: u32 = 3;

const BLOCK: [u8; 16] = [0x61; 16];
const LIVE: [u8; 16] = [0x62; 16];
const DEAD: [u8; 16] = [0x63; 16];
const NEW: [u8; 16] = [0x64; 16];

/// A single CBOR int (0x01) is a valid canonical-CBOR unknown value.
fn unknown_map(key: &str) -> BTreeMap<String, UnknownValue> {
    let v = UnknownValue::from_canonical_cbor(&[0x01]).expect("canonical cbor unknown");
    BTreeMap::from([(key.to_string(), v)])
}

fn text_field(text: &str, unknown: BTreeMap<String, UnknownValue>) -> RecordField {
    RecordField {
        value: RecordFieldValue::Text(SecretString::from(text)),
        last_mod: SEED_MS,
        device_uuid: ORIG_DEVICE,
        unknown,
    }
}

fn text_input(name: &str, text: &str) -> FieldInput {
    FieldInput {
        name: name.to_string(),
        value: FieldInputValue::Text(SecretString::from(text)),
    }
}

/// A later client's block: versions above v1, `unknown` at all three levels,
/// one live record and one tombstoned record.
fn seed_plaintext() -> BlockPlaintext {
    let live = Record {
        record_uuid: LIVE,
        record_type: "login".to_string(),
        fields: BTreeMap::from([
            (
                "keep".to_string(),
                text_field("same", unknown_map("x_keep")),
            ),
            (
                "change".to_string(),
                text_field("v0", unknown_map("x_change")),
            ),
        ]),
        tags: vec![],
        created_at_ms: SEED_MS,
        last_mod_ms: SEED_MS,
        tombstone: false,
        tombstoned_at_ms: 0,
        unknown: unknown_map("x_rec"),
    };
    let dead = Record {
        record_uuid: DEAD,
        record_type: "login".to_string(),
        fields: BTreeMap::new(),
        tags: vec![],
        created_at_ms: SEED_MS,
        last_mod_ms: TOMBSTONED_MS,
        tombstone: true,
        tombstoned_at_ms: TOMBSTONED_MS,
        unknown: BTreeMap::new(),
    };
    BlockPlaintext {
        block_version: LATER_BLOCK_VERSION,
        block_uuid: BLOCK,
        block_name: "Later".to_string(),
        schema_version: LATER_SCHEMA_VERSION,
        records: vec![live, dead],
        unknown: unknown_map("x_block"),
    }
}

fn record_input(record_uuid: [u8; 16], fields: Vec<FieldInput>) -> RecordInput {
    RecordInput {
        record_uuid,
        record_type: "login".to_string(),
        tags: vec![],
        fields,
    }
}

#[test]
fn an_update_carries_forward_what_the_caller_cannot_see() {
    let (_tmp, opened) = open_writable_golden_001();
    crate::edit::save_plaintext(
        &opened.identity,
        &opened.manifest,
        seed_plaintext(),
        ORIG_DEVICE,
        SEED_MS,
    )
    .expect("seed a later client's block");

    let input = BlockInput {
        block_uuid: BLOCK,
        block_name: "Later".to_string(),
        records: vec![
            record_input(
                LIVE,
                vec![text_input("keep", "same"), text_input("change", "v1")],
            ),
            record_input(DEAD, vec![text_input("back", "again")]),
            record_input(NEW, vec![text_input("fresh", "x")]),
        ],
    };
    save_block(
        &opened.identity,
        &opened.manifest,
        input,
        SAVE_DEVICE,
        SAVE_MS,
    )
    .expect("save_block over the existing block");

    let after =
        decrypt_block_plaintext(&opened.identity, &opened.manifest, &BLOCK).expect("decrypt");
    let rec = |uuid: [u8; 16]| {
        after
            .records
            .iter()
            .find(|r| r.record_uuid == uuid)
            .expect("record present")
    };

    // Block level.
    assert_eq!(
        (after.block_version, after.schema_version),
        (LATER_BLOCK_VERSION, LATER_SCHEMA_VERSION),
        "an update must keep the block's versions, not reset them to v1"
    );
    assert!(after.unknown.contains_key("x_block"), "block-level unknown");

    // An existing live record.
    let live = rec(LIVE);
    assert!(live.unknown.contains_key("x_rec"), "record-level unknown");
    assert_eq!(live.created_at_ms, SEED_MS, "created_at_ms preserved");
    assert_eq!(live.last_mod_ms, SAVE_MS, "last_mod_ms bumped");
    let keep = &live.fields["keep"];
    assert!(
        keep.unknown.contains_key("x_keep"),
        "unchanged field unknown"
    );
    assert_eq!(
        (keep.last_mod, keep.device_uuid),
        (SEED_MS, ORIG_DEVICE),
        "an unchanged field keeps its clock, so it cannot clobber a concurrent edit"
    );
    let change = &live.fields["change"];
    assert!(
        change.unknown.contains_key("x_change"),
        "changed field unknown"
    );
    assert_eq!(
        (change.last_mod, change.device_uuid),
        (SAVE_MS, SAVE_DEVICE)
    );

    // A tombstoned record the caller resurrects keeps its death clock.
    let dead = rec(DEAD);
    assert!(!dead.tombstone, "saved record is live");
    assert_eq!(
        dead.tombstoned_at_ms, TOMBSTONED_MS,
        "death clock preserved"
    );
    assert_eq!(dead.created_at_ms, SEED_MS);

    // A record new to the block starts fresh.
    let new = rec(NEW);
    assert_eq!(new.created_at_ms, SAVE_MS);
    assert!(new.unknown.is_empty());
    assert_eq!(new.fields["fresh"].last_mod, SAVE_MS);
}

/// An update reads the existing block to carry its hidden state forward, so
/// a block it cannot read and verify must be REFUSED, not silently replaced
/// by a v1 copy with every unknown dropped (the #766 downgrade, by another
/// route). The block file is left exactly as it was.
#[test]
fn an_update_over_an_unreadable_block_is_refused() {
    let (tmp, opened) = open_writable_golden_001();
    crate::edit::save_plaintext(
        &opened.identity,
        &opened.manifest,
        seed_plaintext(),
        ORIG_DEVICE,
        SEED_MS,
    )
    .expect("seed a later client's block");
    let path = tmp.path().join("blocks").join(format!(
        "{}.cbor.enc",
        crate::record::orchestration::uuid_hyphenated(&BLOCK)
    ));
    let mut tampered = std::fs::read(&path).expect("read block file");
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    std::fs::write(&path, &tampered).expect("tamper block file");

    let input = BlockInput {
        block_uuid: BLOCK,
        block_name: "Later".to_string(),
        records: vec![record_input(LIVE, vec![text_input("keep", "same")])],
    };
    let err = save_block(
        &opened.identity,
        &opened.manifest,
        input,
        SAVE_DEVICE,
        SAVE_MS,
    )
    .expect_err("an update over an unreadable block must fail");
    assert!(
        matches!(err, crate::error::FfiVaultError::CorruptVault { .. }),
        "expected CorruptVault, got {err:?}"
    );
    assert_eq!(
        std::fs::read(&path).expect("re-read block file"),
        tampered,
        "the unreadable block must not be overwritten"
    );
}
