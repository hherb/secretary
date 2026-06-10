#![no_main]
use libfuzzer_sys::fuzz_target;
use secretary_core::unlock::device_file;

fuzz_target!(|data: &[u8]| {
    if let Ok(parsed) = device_file::decode(data) {
        assert_eq!(
            device_file::encode(&parsed).as_slice(),
            data,
            "device_file decode->encode roundtrip mismatch"
        );
    }
});
