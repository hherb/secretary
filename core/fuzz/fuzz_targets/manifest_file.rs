#![no_main]
use libfuzzer_sys::fuzz_target;
use secretary_core::vault::manifest;

fuzz_target!(|data: &[u8]| {
    // External roundtrip oracle: decode_manifest_file must equal
    // encode_manifest_file(decode_manifest_file(input)) for any input the
    // decoder accepts. The manifest file is binary-framed (§4.1): a fixed
    // header, AEAD nonce + length-prefixed ciphertext + tag, owner
    // fingerprint, and trailing hybrid signature. The CBOR manifest payload
    // is encrypted inside aead_ct and never visited by this decoder, so
    // this assertion catches encoder/decoder asymmetries in the binary
    // frame fields (length-prefix width, signature byte ordering,
    // fingerprint encoding) — not CBOR canonicality, which is opaque here.
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
