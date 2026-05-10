//! Property-based test for `share_block`: starting from a freshly-saved
//! owner-only block, sharing sequentially with N freshly-minted recipient
//! identities produces a manifest entry whose `recipient_uuids` contains
//! the owner + every recipient.
//!
//! Lives in its own integration-test bin so its case-budget is independent
//! of the failure-mode tests in the sibling `share_block.rs` bin.

mod share_block_helpers;

use secretary_core::unlock::bundle::IdentityBundle;
use secretary_ffi_bridge::share_block;

use share_block_helpers::{
    fresh_writable_vault, mint_external_card, save_one_record_block, DEVICE_UUID, NEW_BLOCK_UUID,
    NEW_RECORD_UUID, NOW_MS_BASE,
};

/// Cases held low because each case opens a fresh writable vault (Argon2id
/// at vault-creation strength, ~1s per case). 16 cases ≈ 16s of test time;
/// raise once the vault-open cost is amortizable across cases (issue #38).
const PROPTEST_CASES: u32 = 16;

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(PROPTEST_CASES))]

    /// Property: starting from a freshly-saved owner-only block, sharing
    /// sequentially with N freshly-minted recipient identities produces a
    /// manifest entry whose `recipient_uuids` contains the owner + every
    /// recipient. Exercises the share orchestration's atomicity: each
    /// share's existing_recipient_cards list grows by one element, and
    /// every iteration must succeed without rolling back the prior shares.
    #[test]
    fn share_block_to_n_recipients_grows_recipient_list_atomically(
        n in 1usize..=4usize,
        seed in proptest::prelude::any::<[u8; 4]>(),
    ) {
        let (_tmp, identity, manifest) = fresh_writable_vault();
        save_one_record_block(
            &identity,
            &manifest,
            NEW_BLOCK_UUID,
            NEW_RECORD_UUID,
            "k",
            "v",
            NOW_MS_BASE,
        );

        // Mint N recipient identities with deterministic-but-distinct seeds.
        // Seed-mix uses the proptest-supplied `seed` plus the recipient
        // index so every case generates fresh UUIDs.
        let recipients: Vec<(IdentityBundle, Vec<u8>)> = (0..n)
            .map(|i| mint_external_card(seed[0].wrapping_add(i as u8), &format!("R{i}")))
            .collect();

        // existing_recipient_cards grows by one element per iteration.
        let mut existing: Vec<Vec<u8>> = vec![manifest
            .owner_card_bytes()
            .expect("encode succeeds on a verified card")
            .expect("owner card present")];
        for (i, (_bundle, card_bytes)) in recipients.iter().enumerate() {
            share_block(
                &identity,
                &manifest,
                NEW_BLOCK_UUID,
                &existing,
                card_bytes,
                DEVICE_UUID,
                NOW_MS_BASE + 1_000 + (i as u64) * 1_000,
            )
            .map_err(|e| {
                proptest::test_runner::TestCaseError::fail(format!(
                    "share #{i} failed: {e:?}",
                ))
            })?;
            existing.push(card_bytes.clone());
        }

        // Manifest entry must list owner + every recipient (1 + n total).
        let post = manifest
            .find_block(&NEW_BLOCK_UUID)
            .expect("block findable after share");
        proptest::prop_assert_eq!(
            post.recipient_uuids.len(),
            1 + n,
            "expected {} recipients on manifest entry, got {}",
            1 + n,
            post.recipient_uuids.len(),
        );
        for (bundle, _) in &recipients {
            proptest::prop_assert!(
                post.recipient_uuids.contains(&bundle.user_uuid),
                "recipient {} missing from post-share manifest entry",
                hex::encode(bundle.user_uuid),
            );
        }
    }
}
