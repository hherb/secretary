//! Library surface for the secretary-desktop binary.
//!
//! Tauri 2's `[[bin]]` target builds a separate compilation unit from the
//! `[lib]` target — integration tests in `tests/*.rs` link against the
//! library, not the binary. The modules live here (as `pub mod`) so both
//! the binary (`src/main.rs`) and the integration tests can reach them.
//!
//! `main.rs` itself is the Tauri entry point and pulls modules via
//! `use secretary_desktop::*` rather than re-declaring `mod ...` (which
//! would compile each module twice — once in the lib, once in the bin —
//! and produce duplicate-symbol type-identity mismatches at the integration
//! test boundary).

pub mod auto_lock;
pub mod commands;
pub mod constants;
pub mod dtos;
pub mod errors;
pub mod session;
pub mod settings;
pub mod timer;
