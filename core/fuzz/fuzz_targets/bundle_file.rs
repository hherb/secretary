#![no_main]
use libfuzzer_sys::fuzz_target;
use secretary_core::unlock::bundle_file;

fuzz_target!(|data: &[u8]| {
    // External roundtrip oracle: bundle_file::decode must equal
    // bundle_file::encode(bundle_file::decode(input)) for any input the
    // decoder accepts. The bundle file format has a strict canonical
    // representation; the external check here is defense-in-depth — it
    // catches any future regression that weakens the canonical-input gate.
    if let Ok(parsed) = bundle_file::decode(data) {
        let reencoded = bundle_file::encode(&parsed);
        assert_eq!(
            reencoded.as_slice(),
            data,
            "bundle_file decode→encode roundtrip mismatch"
        );
    }
});
