//! `rule_token()` for [`RecordError`](super::record::RecordError),
//! [`BlockError`](super::block::BlockError) (#641) and
//! [`CardError`](crate::identity::card::CardError) (#641): which rule a
//! rejecting record, block-file or contact-card decoder is reporting, as the
//! language-neutral token `core/tests/differential_replay.rs` compares
//! against `conformance.py`.
//!
//! **Why `RuleToken` itself is not here.** It lives in
//! `vault::manifest::token`, where #634 introduced it for the manifest body,
//! and #648 owns the decision about its public home. Moving it now would break
//! its public path and every citation of it for no gain in this slice.
//!
//! **Why not in `record.rs` / `block.rs` / `identity/card.rs`.**
//! `record.rs` and `block.rs` are each over 3,000 lines, which is the reason
//! for those two. `identity/card.rs` is not — it is under 1,500 lines
//! (measured at this writing; re-measure rather than quoting), nowhere near
//! that threshold — so its `impl` sits here for a different reason:
//! consistency with its two siblings' placement, not size. An inherent
//! `impl` may live anywhere in the crate, so all three impls sit in their
//! own small files beside a second, independent declaration of each mapping
//! in `tests/`.

mod block;
mod card;
mod record;

#[cfg(test)]
mod tests;
