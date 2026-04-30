#![no_main]
use libfuzzer_sys::fuzz_target;
use secretary_core::vault::manifest;

fuzz_target!(|data: &[u8]| {
    // External roundtrip oracle: decode_manifest_file must equal
    // encode_manifest_file(decode_manifest_file(input)) for any input the
    // decoder accepts. The manifest file is binary-framed CBOR; the
    // file-level decoder does not perform a strict re-encode gate, so this
    // assertion catches both encoder/decoder asymmetries AND inputs that
    // decode silently despite being non-canonical (e.g. CBOR with map keys
    // out of canonical order, indefinite-length items, or non-shortest-form
    // length prefixes).
    if let Ok(parsed) = manifest::decode_manifest_file(data) {
        let reencoded = manifest::encode_manifest_file(&parsed)
            .expect("encode after successful decode must not fail");
        assert_eq!(
            reencoded.as_slice(),
            data,
            "manifest_file decode→encode roundtrip mismatch"
        );
    }
});
