//! The file-name prefix this generator owns in `manifest_body/`.
//!
//! Its own file so another test binary can `#[path]`-share it if it ever
//! needs to EXCLUDE this family, the way `rule_token_seeds.rs` shares
//! `nesting_depth_seeds_helpers/prefix.rs`. Nothing does today.
pub const SEED_PREFIX: &str = "wellformed__";
