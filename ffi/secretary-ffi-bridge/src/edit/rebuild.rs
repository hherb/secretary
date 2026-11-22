//! [`rebuild_record`]: the ONE place a caller's [`RecordContent`] becomes a
//! native [`Record`]. `edit_record`, `append_record` and the whole-block
//! `save_block` all build records here, so what an update carries forward
//! from the prior copy cannot drift between them (#766 was `save_block`
//! carrying forward nothing).

use std::collections::BTreeMap;

use secretary_core::vault::record::{Record, RecordField};

use super::RecordContent;

/// Build the record `record_uuid` from `content`, carrying forward from
/// `prior` (the record's current copy, if it has one) everything the caller
/// cannot see or did not change.
///
/// With `prior`: `created_at_ms`, `tombstoned_at_ms` (the death clock, so a
/// resurrection keeps it), the record-level `unknown`, and, per field
/// matched by name, the field's `unknown`. A field whose value is
/// byte-identical to the prior one also keeps its `last_mod` and
/// `device_uuid`: core's field merge is last-write-wins on `last_mod`, so
/// bumping an untouched field would let this copy clobber a concurrent edit
/// of that field on another device. A field absent from `content` is dropped
/// (the user removed it). The result is live, with `last_mod_ms = now_ms`.
///
/// Without `prior`: a fresh record, every clock `now_ms`, every `unknown`
/// empty, `tombstoned_at_ms = 0`.
pub(crate) fn rebuild_record(
    prior: Option<&Record>,
    record_uuid: [u8; 16],
    content: RecordContent,
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Record {
    let mut fields: BTreeMap<String, RecordField> = BTreeMap::new();
    for f in content.fields {
        let value = f.value.into_core_value();
        let prior_field = prior.and_then(|p| p.fields.get(&f.name));
        // `RecordFieldValue`'s `==` is constant-time (its `SecretString` /
        // `SecretBytes` payloads compare via `subtle::ConstantTimeEq`), so the
        // unchanged-value gate adds no value-dependent timing side channel.
        let (last_mod, field_device_uuid, unknown) = match prior_field {
            Some(p) if p.value == value => (p.last_mod, p.device_uuid, p.unknown.clone()),
            Some(p) => (now_ms, device_uuid, p.unknown.clone()),
            None => (now_ms, device_uuid, BTreeMap::new()),
        };
        fields.insert(
            f.name,
            RecordField {
                value,
                last_mod,
                device_uuid: field_device_uuid,
                unknown,
            },
        );
    }
    Record {
        record_uuid,
        record_type: content.record_type,
        fields,
        tags: content.tags,
        created_at_ms: prior.map_or(now_ms, |p| p.created_at_ms),
        last_mod_ms: now_ms,
        tombstone: false,
        tombstoned_at_ms: prior.map_or(0, |p| p.tombstoned_at_ms),
        unknown: prior.map_or_else(BTreeMap::new, |p| p.unknown.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use secretary_core::crypto::secret::SecretString;
    use secretary_core::vault::record::{RecordFieldValue, UnknownValue};

    use crate::save::input::{FieldInput, FieldInputValue};

    const PRIOR_DEVICE: [u8; 16] = [0x07; 16];
    const NOW_DEVICE: [u8; 16] = [0x09; 16];
    const PRIOR_MS: u64 = 1_000;
    const DEATH_MS: u64 = 1_500;
    const NOW_MS: u64 = 2_000;
    const UUID: [u8; 16] = [0x11; 16];

    fn content(fields: &[(&str, &str)]) -> RecordContent {
        RecordContent {
            record_type: "login".to_string(),
            tags: vec!["t".to_string()],
            fields: fields
                .iter()
                .map(|(n, v)| FieldInput {
                    name: n.to_string(),
                    value: FieldInputValue::Text(SecretString::from(*v)),
                })
                .collect(),
        }
    }

    fn unknown(key: &str) -> BTreeMap<String, UnknownValue> {
        let v = UnknownValue::from_canonical_cbor(&[0x01]).expect("canonical cbor");
        BTreeMap::from([(key.to_string(), v)])
    }

    fn prior() -> Record {
        let field = |text: &str, key: &str| RecordField {
            value: RecordFieldValue::Text(SecretString::from(text)),
            last_mod: PRIOR_MS,
            device_uuid: PRIOR_DEVICE,
            unknown: unknown(key),
        };
        Record {
            record_uuid: UUID,
            record_type: "old".to_string(),
            fields: BTreeMap::from([
                ("same".to_string(), field("a", "x_same")),
                ("changed".to_string(), field("b", "x_changed")),
                ("dropped".to_string(), field("c", "x_dropped")),
            ]),
            tags: vec![],
            created_at_ms: PRIOR_MS,
            last_mod_ms: DEATH_MS,
            tombstone: true,
            tombstoned_at_ms: DEATH_MS,
            unknown: unknown("x_rec"),
        }
    }

    #[test]
    fn without_a_prior_copy_the_record_is_fresh() {
        let r = rebuild_record(None, UUID, content(&[("f", "v")]), NOW_DEVICE, NOW_MS);
        assert_eq!(r.record_uuid, UUID);
        assert_eq!((r.created_at_ms, r.last_mod_ms), (NOW_MS, NOW_MS));
        assert!(!r.tombstone);
        assert_eq!(r.tombstoned_at_ms, 0);
        assert!(r.unknown.is_empty());
        let f = &r.fields["f"];
        assert_eq!((f.last_mod, f.device_uuid), (NOW_MS, NOW_DEVICE));
        assert!(f.unknown.is_empty());
        assert_eq!(r.tags, vec!["t".to_string()]);
    }

    #[test]
    fn with_a_prior_copy_the_hidden_state_is_carried_forward() {
        let p = prior();
        let r = rebuild_record(
            Some(&p),
            UUID,
            content(&[("same", "a"), ("changed", "B"), ("added", "n")]),
            NOW_DEVICE,
            NOW_MS,
        );
        assert_eq!(r.record_type, "login", "the caller's type wins");
        assert_eq!(r.created_at_ms, PRIOR_MS);
        assert_eq!(r.last_mod_ms, NOW_MS);
        assert!(!r.tombstone, "a saved record is live");
        assert_eq!(r.tombstoned_at_ms, DEATH_MS, "the death clock survives");
        assert!(r.unknown.contains_key("x_rec"));

        let same = &r.fields["same"];
        assert_eq!((same.last_mod, same.device_uuid), (PRIOR_MS, PRIOR_DEVICE));
        assert!(same.unknown.contains_key("x_same"));

        let changed = &r.fields["changed"];
        assert_eq!(
            (changed.last_mod, changed.device_uuid),
            (NOW_MS, NOW_DEVICE)
        );
        assert!(changed.unknown.contains_key("x_changed"));

        let added = &r.fields["added"];
        assert_eq!((added.last_mod, added.device_uuid), (NOW_MS, NOW_DEVICE));
        assert!(added.unknown.is_empty());

        assert!(
            !r.fields.contains_key("dropped"),
            "an omitted field is dropped"
        );
    }
}
