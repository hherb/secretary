#![no_main]
use libfuzzer_sys::fuzz_target;
use secretary_core::unlock::vault_toml;

fuzz_target!(|data: &[u8]| {
    // vault_toml::decode takes &str; non-UTF-8 inputs are structurally
    // invalid and have no decode path, so silently filtering them is
    // correct (not a crash-suppressing oracle).
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = vault_toml::decode(s);
    }
});
