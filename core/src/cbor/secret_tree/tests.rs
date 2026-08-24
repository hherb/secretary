use super::*;

/// A tree with a secret at every depth and in every container arm —
/// including `Tag` (fix round 1, controller finding I2): `nested_secret_tree`
/// previously contained no `Tag` at all, and `harvest` had no `Tag` arm
/// either, so a payload hidden inside one could survive a wipe with every
/// existing assertion still green. Demonstrated by mutation: with the `Tag`
/// arm deleted from `wipe_value` (falling through to the wildcard), a
/// `Map -> Array -> Tag -> Map -> Text` secret survived intact and a
/// Tag-blind `harvest` reported zero survivors either way.
///
/// A bare `Value::Tag` is never produced by this crate's OWN canonical
/// encoder (`reject_floats_and_tags` refuses one in any tree that reaches
/// it), but `SecretValueTree::new` accepts any hand-built `Value` — in
/// particular the raw output of `ciborium::de::from_reader` on a corrupt or
/// adversarial vault file, before that rejection runs. `wipe_value` must
/// still reach a secret hidden inside a tag on that path, which is exactly
/// why `wipe_value` already has a `Tag` arm; this fixture is what proves it.
fn nested_secret_tree() -> Value {
    Value::Map(vec![
        (Value::Text("top_bytes".into()), Value::Bytes(vec![0xAA; 8])),
        (
            Value::Text("top_text".into()),
            Value::Text("top-secret".into()),
        ),
        (
            Value::Text("nested_map".into()),
            Value::Map(vec![(
                Value::Text("inner".into()),
                Value::Bytes(vec![0xBB; 8]),
            )]),
        ),
        (
            Value::Text("nested_array".into()),
            Value::Array(vec![
                Value::Text("in-array".into()),
                Value::Bytes(vec![0xCC; 8]),
                Value::Map(vec![(
                    Value::Text("deep".into()),
                    Value::Text("deep-secret".into()),
                )]),
                Value::Tag(
                    6,
                    Box::new(Value::Map(vec![(
                        Value::Text("tag_inner".into()),
                        Value::Text("tag-secret".into()),
                    )])),
                ),
            ]),
        ),
    ])
}

/// Collect every `Bytes`/`Text` payload in the tree, so a test can assert
/// on what survived a wipe. Recurses into `Tag` (fix round 1, I2) for the
/// same reason `wipe_value` does — a payload hidden inside one must be
/// observable to a test, or the `Tag` arm above is unpinned.
fn harvest(v: &Value, out: &mut Vec<Vec<u8>>) {
    match v {
        Value::Bytes(b) => out.push(b.clone()),
        Value::Text(t) => out.push(t.as_bytes().to_vec()),
        Value::Array(items) => items.iter().for_each(|i| harvest(i, out)),
        Value::Map(entries) => entries.iter().for_each(|(k, val)| {
            harvest(k, out);
            harvest(val, out);
        }),
        Value::Tag(_, inner) => harvest(inner, out),
        _ => {}
    }
}

#[test]
fn wipe_reaches_every_depth_and_every_container_arm() {
    let mut tree = SecretValueTree::new(nested_secret_tree());

    let mut before = Vec::new();
    harvest(tree.as_value(), &mut before);
    assert!(
        before.iter().any(|b| b == b"top-secret"),
        "fixture did not contain the payload the test is about"
    );
    assert!(
        before.iter().any(|b| b == b"top_text"),
        "fixture did not contain the KEY the test is about"
    );
    assert!(
        before.iter().any(|b| b == b"tag-secret"),
        "fixture did not contain the Tag-wrapped payload the test is about"
    );

    tree.wipe_for_test();

    let mut after = Vec::new();
    harvest(tree.as_value(), &mut after);
    assert!(
        !after.iter().any(|b| b == b"top-secret"),
        "top-level Text survived the wipe"
    );
    assert!(
        !after.iter().any(|b| b == b"deep-secret"),
        "Text nested inside Array->Map survived the wipe"
    );
    assert!(
        !after.iter().any(|b| b.contains(&0xBB)),
        "Bytes nested inside Map survived the wipe"
    );
    assert!(
        !after.iter().any(|b| b.contains(&0xCC)),
        "Bytes nested inside Array survived the wipe"
    );
    // Controller finding I1: map KEYS are plaintext too (`record.fields`
    // keys are user-authored field names inside an encrypted record, #474)
    // and were entirely unpinned — deleting `wipe_value(k);` from the
    // `Value::Map` arm left every existing assertion here green, because
    // none of them ever looked for a key. `top_text` is the key of the
    // `top-secret` entry above; it must be gone too.
    assert!(
        !after.iter().any(|b| b == b"top_text"),
        "a Map KEY survived the wipe"
    );
    // Controller finding I2: the fixture previously had no `Tag` at all and
    // `harvest` could not see into one either, so a secret hidden inside a
    // `Tag` could survive with zero observable failure. Both are fixed
    // above; this closes the loop.
    assert!(
        !after.iter().any(|b| b == b"tag-secret"),
        "Text nested inside a Tag survived the wipe"
    );
}

/// `Drop` is the security claim — it is what covers an unwind and every
/// `?` early return. Deleting `impl Drop` must FAIL a test.
///
/// This is the #546 precedent: deleting `impl Drop for ZeroizingEntries`
/// left all 25 bundle tests green, and the only thing that noticed was an
/// incidental `dead_code` lint that evaporates as soon as the wipe gains
/// a second caller.
#[test]
fn drop_invokes_the_wipe() {
    let before = wipe_calls();
    {
        let _tree = SecretValueTree::new(nested_secret_tree());
    }
    assert_eq!(
        wipe_calls(),
        before + 1,
        "scope exit did not wipe — is `impl Drop for SecretValueTree` still there?"
    );
}

/// `ciborium::Value` is `#[non_exhaustive]` from this crate's
/// perspective (it is defined in an external crate), so every match on
/// it here is forced to carry a wildcard arm. That has a real, asymmetric
/// consequence for what this test can and cannot prove:
///
/// - It genuinely fails to COMPILE if a named variant below is removed
///   or renamed by a future `ciborium` release — each arm names the
///   variant directly, so the match stops compiling the moment one of
///   them no longer exists.
/// - It does **not** detect an ADDED variant. The forced wildcard arm
///   silently accepts anything not named above; a human deciding whether
///   `wipe_value` needs a new arm has to notice the addition some other
///   way (an upstream changelog, a `cargo update` diff) — nothing in this
///   file derives it from the match, and no compile-time introspection over
///   a foreign `#[non_exhaustive]` enum is available in stable Rust to
///   build one. Do not read `assert_named_variants_still_exist` below as a
///   working tripwire against additions; it isn't one.
#[test]
fn every_ciborium_value_variant_is_accounted_for() {
    let all = [
        Value::Integer(0u64.into()),
        Value::Bytes(vec![1]),
        Value::Float(0.0),
        Value::Text("t".into()),
        Value::Bool(true),
        Value::Null,
        Value::Tag(0, Box::new(Value::Null)),
        Value::Array(vec![]),
        Value::Map(vec![]),
    ];
    // Wiping each in isolation must not panic and must terminate.
    for v in all {
        let mut t = SecretValueTree::new(v);
        t.wipe_for_test();
    }
    // Fix round 1, MINOR finding: this used to end with
    // `assert_eq!(secretary_core_value_variant_count(), 9, "...")`, comparing
    // a function's return value against a literal `9` when that function
    // ALWAYS returned the literal `9` — an assertion that can never fire,
    // whose failure message described a *compile* error (a removed/renamed
    // variant) that would never let this line run in the first place.
    // Deleted the dead runtime assertion; kept the thing that actually does
    // the work below.
    assert_named_variants_still_exist();
}

/// Exhaustively NAMES every variant this version of `ciborium::Value` has.
/// This is the entire tripwire for a REMOVED or RENAMED variant: each arm
/// names a variant directly, so the match fails to COMPILE — not to run —
/// the moment one no longer exists. There is deliberately no runtime
/// assertion here; see the test above for what this can and cannot prove
/// (in particular, it proves nothing about an ADDED variant).
fn assert_named_variants_still_exist() {
    let probe = Value::Null;
    match &probe {
        Value::Integer(_) => {}
        Value::Bytes(_) => {}
        Value::Float(_) => {}
        Value::Text(_) => {}
        Value::Bool(_) => {}
        Value::Null => {}
        Value::Tag(_, _) => {}
        Value::Array(_) => {}
        Value::Map(_) => {}
        _ => {}
    }
}

/// A wipe must be distinguishable from a `clear()`. The #546 review found
/// an assertion of the form `all(|b| b == 0)` on a vec that `Zeroize`
/// EMPTIES, which passes vacuously and cannot tell the two apart.
///
/// Stated limit: neither form can distinguish them for a `Vec`, because
/// safe Rust cannot read spare capacity. What this test CAN prove is that
/// the payload is no longer present, which is the property that matters
/// and which a no-op `Drop` fails.
#[test]
fn wipe_is_not_vacuous() {
    let secret = b"a-distinctive-payload".to_vec();
    let mut tree = SecretValueTree::new(Value::Bytes(secret.clone()));

    let mut before = Vec::new();
    harvest(tree.as_value(), &mut before);
    assert_eq!(before, vec![secret.clone()], "fixture setup");

    tree.wipe_for_test();

    let mut after = Vec::new();
    harvest(tree.as_value(), &mut after);
    assert!(
        !after.contains(&secret),
        "payload still present after wipe — the wipe is a no-op"
    );
}

// --- SecretEntries (#547 / #548, audit C-4) ----------------------------
//
// History, not current state: at Task 3, `SecretEntries` had no production
// caller (Task 7 gave it one — `unlock::bundle::from_canonical_cbor`), and
// the whole `secret_tree` module was `#[cfg(test)]`-gated at that point
// (controller ruling R12), so it existed ONLY in a `--tests` build; within
// that build, `new` / `len` / `is_empty` / `as_slice` / `take_next` still
// needed a genuine caller or they were `dead_code` in THIS compilation, and
// per this branch's R4 ruling an uncalled item gets deleted rather than
// `#[allow]`-ed.
//
// As of Task 7, the module is unconditionally compiled and so is
// `SecretEntries` itself — `new` / `is_empty` / `as_slice` / `take_next` all
// have real production callers now. Only `len` remains `#[cfg(test)]`-only
// (`unlock::bundle`'s production caller never needs it; see that method's
// own doc in `mod.rs`). The tests below still exist to exercise the real
// contract, not merely to silence a lint — that reasoning didn't change,
// only which items need it for that reason.

/// Three distinguishable entries, used to check `take_next`'s ordering
/// and `SecretEntries`'s wipe-on-drop.
fn three_entries() -> Vec<(Value, Value)> {
    vec![
        (Value::Text("k0".into()), Value::Text("secret-zero".into())),
        (Value::Text("k1".into()), Value::Bytes(vec![0xD0; 4])),
        (Value::Text("k2".into()), Value::Text("secret-two".into())),
    ]
}

#[test]
fn secret_entries_len_and_as_slice_reflect_construction() {
    let entries = SecretEntries::new(three_entries());
    assert_eq!(entries.len(), 3);
    assert!(!entries.is_empty());
    assert_eq!(entries.as_slice().len(), 3);
    assert_eq!(entries.as_slice()[0].0, Value::Text("k0".into()));
}

#[test]
fn secret_entries_take_next_drains_front_to_back_then_none() {
    let mut entries = SecretEntries::new(three_entries());

    let (k0, v0) = entries.take_next().expect("first entry");
    assert_eq!(k0, Value::Text("k0".into()));
    assert_eq!(v0, Value::Text("secret-zero".into()));
    assert_eq!(entries.len(), 2, "take_next must shrink the remainder");

    let (k1, _) = entries.take_next().expect("second entry");
    assert_eq!(k1, Value::Text("k1".into()));

    let (k2, _) = entries.take_next().expect("third entry");
    assert_eq!(k2, Value::Text("k2".into()));

    assert_eq!(entries.len(), 0);
    assert!(entries.is_empty());
    assert!(
        entries.take_next().is_none(),
        "take_next past the end must return None, not panic"
    );
}

/// `Drop` for `SecretEntries` is the same security claim as
/// `SecretValueTree`'s: it must run on every exit, including an early
/// `?` that leaves entries un-drained. This proves scope exit invokes
/// exactly one wipe pass, sharing the same `WIPE_CALLS` counter
/// `drop_invokes_the_wipe` uses for `SecretValueTree` — the two types
/// are deliberately pinned by the same mechanism.
#[test]
fn secret_entries_drop_invokes_the_wipe() {
    let before = wipe_calls();
    {
        let mut entries = SecretEntries::new(three_entries());
        // Partially drain, mirroring a decoder that errors out midway:
        // the remainder must still be wiped when `entries` drops here.
        let _ = entries.take_next();
    }
    assert_eq!(
        wipe_calls(),
        before + 1,
        "scope exit did not wipe — is `impl Drop for SecretEntries` still there?"
    );
}

/// Controller finding I3 (fix round 1): the test above proves `Drop` runs
/// SOME wipe pass, via a counter incremented once above the wipe loop, but
/// nothing previously checked that the loop actually wiped anything — the
/// counter increment and the wipe body were two separate statements in
/// `Drop::drop`, so deleting the loop body left every existing
/// `SecretEntries` test green (the counter still ticked once). Demonstrated
/// by mutation: with the loop body removed, all seven `SecretEntries` /
/// `SecretValueTree` tests as they stood passed.
///
/// Fixed structurally, not just by adding this test: `SecretEntries` now
/// has the same shape as `SecretValueTree` — a private `fn wipe(&mut self)`
/// that both `Drop::drop` and `#[cfg(test)] wipe_for_test` call, so no
/// mutation can satisfy a counter-only test without also satisfying an
/// effect-based one. This test is the effect-based one: it harvests
/// `as_slice()` before and after an explicit `wipe_for_test()` (no `Drop`
/// involved, so it isolates the wipe's EFFECT from the fact that `Drop`
/// called it — `secret_entries_drop_invokes_the_wipe` above covers the
/// latter) and checks both a value and a KEY (the same I1 finding applies
/// here: `SecretEntries`' keys are exactly as plaintext-bearing as
/// `SecretValueTree`'s).
#[test]
fn secret_entries_wipe_reaches_every_entry_including_keys() {
    let mut entries = SecretEntries::new(three_entries());

    let mut before = Vec::new();
    for (k, v) in entries.as_slice() {
        harvest(k, &mut before);
        harvest(v, &mut before);
    }
    assert!(
        before.iter().any(|b| b == b"secret-zero"),
        "fixture did not contain the payload the test is about"
    );
    assert!(
        before.iter().any(|b| b == b"k0"),
        "fixture did not contain the KEY the test is about"
    );

    entries.wipe_for_test();

    let mut after = Vec::new();
    for (k, v) in entries.as_slice() {
        harvest(k, &mut after);
        harvest(v, &mut after);
    }
    assert!(
        !after.iter().any(|b| b == b"secret-zero"),
        "a value survived the wipe"
    );
    assert!(
        !after.iter().any(|b| b == b"secret-two"),
        "a value survived the wipe"
    );
    assert!(
        !after.iter().any(|b| b.contains(&0xD0)),
        "Bytes survived the wipe"
    );
    assert!(!after.iter().any(|b| b == b"k0"), "a KEY survived the wipe");
}

/// `wipe_leaked_value` must actually OVERWRITE, not merely tick the counter.
///
/// This is the effect half of that function's coverage, and before this test
/// it did not exist: `grep -c wipe_leaked_value` over this file returned 0,
/// and its only exercise was two counter assertions in `unlock::bundle`'s
/// tests. Those cannot see a vacuous body, because the counter is
/// incremented at the TOP of `wipe_leaked_value`, before it walks anything —
/// so replacing `wipe_value(value)` with `let _ = value;` left the entire
/// suite green (verified by mutation during the #560 review).
///
/// That is exactly the failure mode `SecretValueTree` and `SecretEntries`
/// each already guard with a counter test AND an effect test (`drop_invokes_
/// the_wipe` + `wipe_reaches_every_depth_and_every_container_arm`, and their
/// `SecretEntries` twins). `wipe_leaked_value` is the third entry point into
/// the same `wipe_value` walk and got only the counter half; this closes it.
///
/// Uses `nested_secret_tree` rather than a flat value on purpose — the
/// function's contract is the full recursive walk, so a test that only
/// proved a top-level `Bytes` was cleared would leave the container arms
/// unpinned on this path.
#[test]
fn wipe_leaked_value_overwrites_every_payload_it_is_given() {
    let mut leaked = nested_secret_tree();

    let mut before = Vec::new();
    harvest(&leaked, &mut before);
    assert!(
        before.iter().any(|b| b == b"top-secret"),
        "fixture did not contain the payload the test is about"
    );
    assert!(
        before.iter().any(|b| b == b"deep-secret"),
        "fixture did not contain the nested payload the test is about"
    );
    assert!(
        before.iter().any(|b| b.contains(&0xAA)),
        "fixture did not contain the Bytes payload the test is about"
    );

    let calls_before = wipe_calls();
    wipe_leaked_value(&mut leaked);
    assert_eq!(
        wipe_calls(),
        calls_before + 1,
        "wipe_leaked_value must tick the shared counter exactly once"
    );

    let mut after = Vec::new();
    harvest(&leaked, &mut after);
    assert!(
        !after.iter().any(|b| b == b"top-secret"),
        "a top-level Text payload survived wipe_leaked_value"
    );
    assert!(
        !after.iter().any(|b| b == b"deep-secret"),
        "a nested Text payload survived wipe_leaked_value"
    );
    assert!(
        !after.iter().any(|b| b == b"top_text"),
        "a map KEY survived wipe_leaked_value"
    );
    assert!(
        !after.iter().any(|b| b.iter().any(|&x| x != 0)),
        "a payload survived wipe_leaked_value with non-zero bytes"
    );
}
