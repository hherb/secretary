#![no_main]
use libfuzzer_sys::fuzz_target;
use secretary_core::vault::record;

fuzz_target!(|data: &[u8]| {
    // External roundtrip oracle: decode must equal `encode(decode(input))`
    // for any input the decoder accepts. record::decode already enforces
    // this internally (canonical re-encode-and-compare); the external check
    // here is defense-in-depth — if the internal canonicality gate is ever
    // weakened, this target catches the regression.
    if let Ok(parsed) = record::decode(data) {
        let reencoded = record::encode(&parsed)
            .expect("encode after successful decode must not fail");
        assert_eq!(
            reencoded.as_slice(),
            data,
            "record decode→encode roundtrip mismatch"
        );
    }
});
