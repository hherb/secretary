#![no_main]
use libfuzzer_sys::fuzz_target;
use secretary_core::unlock::bundle_file;

fuzz_target!(|data: &[u8]| {
    // External roundtrip oracle: bundle_file::decode must equal
    // bundle_file::encode(bundle_file::decode(input)) for any input the
    // decoder accepts. The bundle file is a fixed-width big-endian binary
    // format with explicit trailing-byte rejection, so any successfully-
    // decoded input round-trips by construction. This external check is
    // defense-in-depth — it catches future regressions in the encode/decode
    // pair (e.g. a new variable-length field added on one side only).
    if let Ok(parsed) = bundle_file::decode(data) {
        let reencoded = bundle_file::encode(&parsed);
        assert_eq!(
            reencoded.as_slice(),
            data,
            "bundle_file decode→encode roundtrip mismatch"
        );
    }
});
