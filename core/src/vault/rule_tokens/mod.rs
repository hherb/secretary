//! `rule_token()` for [`RecordError`](super::record::RecordError) and
//! [`BlockError`](super::block::BlockError) (#641): which rule a rejecting
//! record or block-file decoder is reporting, as the language-neutral token
//! `core/tests/differential_replay.rs` compares against `conformance.py`.
//!
//! **Why `RuleToken` itself is not here.** It lives in
//! `vault::manifest::token`, where #634 introduced it for the manifest body,
//! and #648 owns the decision about its public home. Moving it now would break
//! its public path and every citation of it for no gain in this slice.
//!
//! **Why not in `record.rs` / `block.rs`.** Both are over 3,000 lines. An
//! inherent `impl` may live anywhere in the crate, so the two impls sit in
//! their own small files beside a second, independent declaration of each
//! mapping in `tests/`.

mod block;
mod record;

#[cfg(test)]
mod tests;
