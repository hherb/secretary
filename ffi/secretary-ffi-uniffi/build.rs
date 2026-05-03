//! UDL → Rust scaffolding generator.
//!
//! Reads `src/secretary.udl` and emits `<namespace>.uniffi.rs` to
//! `OUT_DIR`. The generated file is consumed by the
//! `uniffi::include_scaffolding!("secretary")` macro in `lib.rs`.
//! Cargo re-runs this script whenever the UDL changes (cargo's default
//! rerun-if-changed for the build script's read inputs).

fn main() {
    uniffi::generate_scaffolding("src/secretary.udl")
        .expect("uniffi scaffolding generation failed");
}
