#![no_main]
use libfuzzer_sys::fuzz_target;
use secretary_core::vault::record::{self, RecordFieldValue};

fuzz_target!(|data: &[u8]| {
    // External roundtrip oracle: decode must equal `encode(decode(input))`
    // for any input the decoder accepts. record::decode already enforces
    // this internally (canonical re-encode-and-compare); the external check
    // here is defense-in-depth — if the internal canonicality gate is ever
    // weakened, this target catches the regression.
    if let Ok(parsed) = record::decode(data) {
        let reencoded =
            record::encode(&parsed).expect("encode after successful decode must not fail");
        assert_eq!(
            reencoded.as_slice(),
            data,
            "record decode→encode roundtrip mismatch"
        );

        // Defense-in-depth (B.4b Task 5): every successfully-decoded
        // `RecordFieldValue::Text` must wrap a valid-UTF-8 SecretString.
        // The structural guarantee is in place today (CBOR `tstr` per
        // RFC 8949 §3.1 + ciborium's `Value::Text` enforcement +
        // parse_record_field's `Value::Text(s) → SecretString::new(s)`
        // path), so this assertion can never fire with the current
        // decode path. It serves as a tripwire if a future refactor
        // ever weakens the decode path to allow direct SecretString
        // construction from non-validated bytes — the FFI's
        // FieldHandle::expose_text() returns `Option<String>` (not
        // `Result<Option<String>, _>`) and would silently surface
        // invalid UTF-8 to the foreign caller without this fuzz check.
        // Note: `SecretString::expose()` returns `&str` today, so the
        // runtime check below is currently a tautology — the real
        // enforcement is the Rust type system. The assertion becomes a
        // live runtime check only if a future refactor changes the
        // field's wrapper to return `&[u8]` instead of `&str`.
        for (_name, field) in &parsed.fields {
            if let RecordFieldValue::Text(secret_string) = &field.value {
                let bytes = secret_string.expose().as_bytes();
                assert!(
                    std::str::from_utf8(bytes).is_ok(),
                    "RecordFieldValue::Text contained invalid UTF-8 — \
                     decode-path UTF-8 enforcement may have regressed",
                );
            }
        }
    }
});
