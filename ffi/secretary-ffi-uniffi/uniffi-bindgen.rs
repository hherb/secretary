//! In-crate uniffi-bindgen binary.
//!
//! Invoked via `cargo run --bin uniffi-bindgen -- generate ...` to emit
//! Swift / Kotlin / Python bindings from the compiled cdylib. Locking
//! bindgen to the crate's `uniffi` dep version prevents the version-
//! skew bugs you hit when contributors `cargo install uniffi-bindgen-cli`
//! at different points in time.

fn main() {
    uniffi::uniffi_bindgen_main()
}
