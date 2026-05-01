#![no_main]
use libfuzzer_sys::fuzz_target;
use secretary_core::vault::block;

fuzz_target!(|data: &[u8]| {
    // External roundtrip oracle: decode_block_file must equal
    // encode_block_file(decode_block_file(input)) for any input the decoder
    // accepts. The block file is binary-framed (§6.1 header, §6.2 recipient
    // table, AEAD body, trailing hybrid signature suffix). The §6.3 CBOR
    // plaintext is encrypted inside aead_ct and never visited by this
    // decoder, so this assertion catches encoder/decoder asymmetries in the
    // binary frame and recipient table — recipient-entry length, sort
    // order, length-prefix width, signature suffix layout — not CBOR
    // canonicality, which is opaque here.
    if let Ok(parsed) = block::decode_block_file(data) {
        let reencoded = block::encode_block_file(&parsed)
            .expect("encode after successful decode must not fail");
        assert_eq!(
            reencoded.as_slice(),
            data,
            "block_file decode→encode roundtrip mismatch"
        );
    }
});
