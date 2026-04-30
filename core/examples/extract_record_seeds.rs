//! Regenerate `core/fuzz/seeds/record/*.cbor` — canonical-CBOR-encoded
//! `Record` values used as fuzz seeds. Run with:
//!
//!     cargo run --release --example extract_record_seeds
//!
//! Idempotent. Safe to re-run after Record schema changes.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use secretary_core::vault::record::{self, Record, RecordField, RecordFieldValue};

const REC_UUID_LOGIN: [u8; 16] = *b"record-uuid-kat1";
const REC_UUID_NOTE: [u8; 16] = *b"record-uuid-kat2";
const REC_UUID_KEY: [u8; 16] = *b"record-uuid-kat3";
const DEVICE_UUID: [u8; 16] = *b"device-uuid-kat1";

fn build_login_record() -> Record {
    let mut fields = BTreeMap::new();
    fields.insert(
        "username".to_string(),
        RecordField {
            value: RecordFieldValue::Text("alice".to_string()),
            last_mod: 1714060800000,
            device_uuid: DEVICE_UUID,
            unknown: BTreeMap::new(),
        },
    );
    fields.insert(
        "totp_seed".to_string(),
        RecordField {
            value: RecordFieldValue::Bytes(vec![
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            ]),
            last_mod: 1714060800000,
            device_uuid: DEVICE_UUID,
            unknown: BTreeMap::new(),
        },
    );

    Record {
        record_uuid: REC_UUID_LOGIN,
        record_type: "login".to_string(),
        fields,
        tags: vec![],
        created_at_ms: 1714060800000,
        last_mod_ms: 1714060800000,
        tombstone: false,
        tombstoned_at_ms: 0,
        unknown: BTreeMap::new(),
    }
}

fn build_secure_note_record() -> Record {
    let mut fields = BTreeMap::new();
    fields.insert(
        "body".to_string(),
        RecordField {
            value: RecordFieldValue::Text(
                "two-factor backup codes\n12345678\n23456789".to_string(),
            ),
            last_mod: 1714060801000,
            device_uuid: DEVICE_UUID,
            unknown: BTreeMap::new(),
        },
    );

    Record {
        record_uuid: REC_UUID_NOTE,
        record_type: "secure_note".to_string(),
        fields,
        tags: vec!["personal".to_string()],
        created_at_ms: 1714060801000,
        last_mod_ms: 1714060801000,
        tombstone: false,
        tombstoned_at_ms: 0,
        unknown: BTreeMap::new(),
    }
}

fn build_api_key_record() -> Record {
    let mut fields = BTreeMap::new();
    fields.insert(
        "key".to_string(),
        RecordField {
            value: RecordFieldValue::Text("sk_test_DEADBEEFCAFEBABE".to_string()),
            last_mod: 1714060802000,
            device_uuid: DEVICE_UUID,
            unknown: BTreeMap::new(),
        },
    );
    fields.insert(
        "endpoint".to_string(),
        RecordField {
            value: RecordFieldValue::Text("https://api.example.test".to_string()),
            last_mod: 1714060802000,
            device_uuid: DEVICE_UUID,
            unknown: BTreeMap::new(),
        },
    );

    Record {
        record_uuid: REC_UUID_KEY,
        record_type: "api_key".to_string(),
        fields,
        tags: vec!["work".to_string(), "ci".to_string()],
        created_at_ms: 1714060802000,
        last_mod_ms: 1714060802000,
        tombstone: false,
        tombstoned_at_ms: 0,
        unknown: BTreeMap::new(),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir: PathBuf = ["core", "fuzz", "seeds", "record"].iter().collect();
    fs::create_dir_all(&out_dir)?;

    let login = build_login_record();
    let note = build_secure_note_record();
    let api_key = build_api_key_record();

    fs::write(out_dir.join("login.cbor"), record::encode(&login)?)?;
    fs::write(out_dir.join("secure_note.cbor"), record::encode(&note)?)?;
    fs::write(out_dir.join("api_key.cbor"), record::encode(&api_key)?)?;

    println!("wrote 3 record seeds to {}", out_dir.display());
    Ok(())
}
