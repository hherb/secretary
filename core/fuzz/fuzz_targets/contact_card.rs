#![no_main]
use libfuzzer_sys::fuzz_target;
use secretary_core::identity::card::ContactCard;

fuzz_target!(|data: &[u8]| {
    // External roundtrip oracle: from_canonical_cbor must equal
    // to_canonical_cbor(from_canonical_cbor(input)) for any input the
    // decoder accepts. ContactCard::from_canonical_cbor enforces strict
    // canonical form internally; the external check here is defense-in-depth
    // — it catches any future regression that weakens the canonical-input gate.
    if let Ok(card) = ContactCard::from_canonical_cbor(data) {
        let reencoded = card
            .to_canonical_cbor()
            .expect("to_canonical_cbor after successful decode must not fail");
        assert_eq!(
            reencoded.as_slice(),
            data,
            "contact_card decode→encode roundtrip mismatch"
        );
    }
});
