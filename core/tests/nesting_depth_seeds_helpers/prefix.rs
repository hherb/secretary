//! The file-name prefix `nesting_depth_seeds.rs` owns under
//! `core/fuzz/seeds/{record,manifest_body}/`.
//!
//! Its own file so `rule_token_seeds.rs`, whose census claims every labelled
//! file under `record/`, can exclude exactly this prefix by NAMING it. Both
//! test targets compile this one declaration (the second through `#[path]`),
//! so the two generators cannot drift onto two ideas of who owns a file.

pub const SEED_PREFIX: &str = "nesting__";
