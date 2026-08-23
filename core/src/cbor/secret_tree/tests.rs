use super::*;

/// A tree with a secret at every depth and in every container arm.
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
            ]),
        ),
    ])
}

/// Collect every `Bytes`/`Text` payload in the tree, so a test can assert
/// on what survived a wipe.
fn harvest(v: &Value, out: &mut Vec<Vec<u8>>) {
    match v {
        Value::Bytes(b) => out.push(b.clone()),
        Value::Text(t) => out.push(t.as_bytes().to_vec()),
        Value::Array(items) => items.iter().for_each(|i| harvest(i, out)),
        Value::Map(entries) => entries.iter().for_each(|(k, val)| {
            harvest(k, out);
            harvest(val, out);
        }),
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
///   silently accepts anything not named above, and the `9` asserted
///   below is a hand-maintained literal a human must bump after
///   deciding whether `wipe_value` needs a new arm — nothing here
///   derives it from the match. Do not read the `assert_eq!` as a
///   working tripwire against additions; it isn't one, and no
///   compile-time introspection over a foreign `#[non_exhaustive]` enum
///   is available in stable Rust to build one.
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
    assert_eq!(
        secretary_core_value_variant_count(),
        9,
        "a named ciborium::Value variant was removed or renamed — review \
         wipe_value and, if it still handles every remaining named \
         variant correctly, update this count by hand"
    );
}

/// Exhaustively NAMES every variant this version of `ciborium::Value`
/// has, forcing a compile error if one is removed or renamed. Does not
/// count anything dynamically: the returned `9` is a literal, and the
/// match's own result is discarded (`_named`, prefixed to silence the
/// unused-value lint) — see the doc comment on the test above for what
/// this can and cannot prove.
fn secretary_core_value_variant_count() -> usize {
    let probe = Value::Null;
    let _named = match &probe {
        Value::Integer(_) => 1,
        Value::Bytes(_) => 2,
        Value::Float(_) => 3,
        Value::Text(_) => 4,
        Value::Bool(_) => 5,
        Value::Null => 6,
        Value::Tag(_, _) => 7,
        Value::Array(_) => 8,
        Value::Map(_) => 9,
        _ => 0,
    };
    9
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
// Unlike `SecretValueTree`, Task 3 does not give `SecretEntries` a
// production caller (Task 7 does). Without a genuine test caller for
// each of `new` / `len` / `is_empty` / `as_slice` / `take_next`, every one of them
// would be flagged `dead_code` under a plain, non-test build, and per
// this branch's R4 ruling an uncalled item gets deleted rather than
// `#[allow]`-ed — so the tests below exist to exercise the real
// contract, not merely to silence a lint.

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
