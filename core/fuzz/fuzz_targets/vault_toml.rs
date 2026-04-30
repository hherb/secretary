#![no_main]
use libfuzzer_sys::fuzz_target;
use secretary_core::unlock::vault_toml;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = vault_toml::decode(s);
    }
});
