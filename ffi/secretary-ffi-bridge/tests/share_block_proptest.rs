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
    fresh_writable_vault, mint_external_card_from_seed32, save_one_record_block, DEVICE_UUID,
    NEW_BLOCK_UUID, NEW_RECORD_UUID, NOW_MS_BASE,
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
        // Each recipient's 32-byte ChaCha seed carries the proptest-supplied
        // `seed` in bytes 0..4 and the recipient index in byte 4 (over a
        // zero-filled tail), so recipients within a case are distinct (byte 4)
        // and vary across cases (bytes 0..4). The zero-filled tail also keeps
        // every recipient seed NON-all-equal-byte, which guarantees it cannot
        // alias any FIXTURE_CONTACT_MINT_SEEDS `[k; 32]` identity already in the
        // vault's contacts/ — without that, a drawn `seed` of 0xA0/0xA1/0xA2
        // would re-mint the owner/Alice/Bob and trip share_block's TOFU guard
        // (ContactAlreadyExists) — the n=1 seed=0xA0 case pinned in this bin's
        // .proptest-regressions file.
        let recipients: Vec<(IdentityBundle, Vec<u8>)> = (0..n)
            .map(|i| {
                let mut rng_seed = [0u8; 32];
                rng_seed[..4].copy_from_slice(&seed);
                rng_seed[4] = i as u8;
                mint_external_card_from_seed32(rng_seed, &format!("R{i}"))
            })
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

/// Deterministic regression for the fixture-seed collision the proptest above
/// used to flake on (`.proptest-regressions` is gitignored repo-wide, so the
/// guard lives here as a committed test). A proptest `seed` whose byte 0 equals
/// a `FIXTURE_CONTACT_MINT_SEEDS` value — e.g. the owner's `0xA0` — must NOT
/// re-mint that fixture contact and trip `share_block`'s TOFU non-overwrite
/// guard (`ContactAlreadyExists`). This pins the disjoint-by-construction
/// recipient seeding: a future "simplification" back to an all-equal-byte seed
/// (`[k; 32]`) fails loudly here instead of intermittently in CI.
#[test]
fn share_block_recipient_seed_aliasing_a_fixture_mint_byte_does_not_collide() {
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

    // Worst case from the regression: drawn seed byte 0 == 0xA0 (the golden
    // owner's mint seed byte), built exactly as the proptest builds it.
    let mut rng_seed = [0u8; 32];
    rng_seed[0] = 0xA0;
    let (recipient, card_bytes) = mint_external_card_from_seed32(rng_seed, "R0");

    let existing: Vec<Vec<u8>> = vec![manifest
        .owner_card_bytes()
        .expect("encode succeeds on a verified card")
        .expect("owner card present")];
    share_block(
        &identity,
        &manifest,
        NEW_BLOCK_UUID,
        &existing,
        &card_bytes,
        DEVICE_UUID,
        NOW_MS_BASE + 1_000,
    )
    .expect("sharing to a non-aliasing recipient must succeed (no TOFU collision)");

    let post = manifest
        .find_block(&NEW_BLOCK_UUID)
        .expect("block findable after share");
    assert!(
        post.recipient_uuids.contains(&recipient.user_uuid),
        "recipient {} missing from post-share manifest entry",
        hex::encode(recipient.user_uuid),
    );
}
