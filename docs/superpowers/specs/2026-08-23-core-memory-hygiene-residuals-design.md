# Core memory-hygiene residual closeout — design

**Date:** 2026-08-23
**Branch:** `feature/core-memory-hygiene-residuals`, worktree `.worktrees/core-memory-hygiene-residuals`, from `main` @ `6e65ca8d`.
**Issues:** #522, #524, #521, #527, #525, #523, and **#542** (audit C-4's write side, filed during this slice). **#543** is filed and deferred.

---

## 1. What this slice is, and what it is not

#513/#518/#503 (PR #520) converted 50 secret slots to wrap-before-use. Its
whole-branch review filed four residuals it deliberately did not fix
(#521, #522, #523, #524); the #526 desktop review filed a fifth (#527);
#525 predates both. This slice closes all six, plus the one live remnant of
a 2026-07-02 audit finding that #522's framing dropped.

**It is not a new census.** The four scan roots of #513's census were
already shown to be narrower than the repo (`desktop/src-tauri/src` sat
outside all of them and held two genuine windows). This slice takes the
six filed items as its scope and adds only what reading those six sites
forces it to add. A fresh whole-repo census is a separate piece of work.

### 1.1 The correction that reshaped #522

**#522 as filed names one residue. There are three, and the third is the
worst.** The issue says the secret key "exists as an unwrapped copy in
`take_fixed_bytes`' frame, in addition to the `Sensitive`-wrapped
destination" — a stack claim. But `take_fixed_bytes` reaches its array
through `Vec::try_into`, whose implementation in the pinned toolchain's own
std source (`library/alloc/src/vec/mod.rs:4527`) is:

```rust
fn try_from(mut vec: Vec<T, A>) -> Result<[T; N], Vec<T, A>> {
    if vec.len() != N { return Err(vec); }
    unsafe { vec.set_len(0) };
    let array = unsafe { ptr::read(vec.as_ptr() as *const [T; N]) };
    Ok(array)
}
```

`set_len(0)` followed by `ptr::read` is a **copy**, not a move-out. The
`Vec`'s heap buffer is then deallocated with the secret key still in it.
Heap residue outlives stack residue — a freed stack frame is reused by the
next call, a freed heap block is reused only when the allocator hands it
out again.

So the three residues at each secret-key decode site are:

1. the `[u8; N]` materialised in `take_fixed_bytes`' own frame;
2. the by-value return temporary in the caller's frame;
3. the CBOR byte string's **heap buffer**, freed unwiped by `try_into`.

**This is not a new finding.** The 2026-07-02 audit's **C-4** stated it
exactly — "`take_fixed_bytes` consumes a `Vec<u8>` of key bytes that
deallocates un-wiped" — and it is the one sub-item of C-4 still live. The
other three were closed by #357 (canonical re-encode buffer), #513 Task 6
(bundle plaintext) and #518 (the `Copy` locals). The memory-hygiene memo
does not mention `take_fixed_bytes` at any point.

### 1.2 What was checked and found NOT to be a defect

`derive_wrap_key`'s `okm` slot has the shape of a window — a plain
`Vec<u8>` from HKDF, a `key.copy_from_slice(&okm)` that can panic in
principle, then a trailing `okm.zeroize()`. It is **not** one:
`hkdf_sha256_extract_and_expand` allocates `vec![0u8; len]` and returns it,
so `okm.len()` is exactly the requested 32 by construction and
`copy_from_slice` cannot panic. Adjacent, per CLAUDE.md's rule. Recorded
here so a later reader does not re-derive it as a finding.

---

## 2. #524 — `derive_wrap_key`'s `ikm`

### 2.1 Why the issue's proposed fix does not close the issue's own hazard

#524 proposes `SecretBytes::try_build(Vec::with_capacity(n), |buf| { … })`,
mirroring `Sensitive::try_build`. That closes the **panic window** — the
buffer is wrapper-covered from allocation rather than from the last
`extend_from_slice`.

It does **not** close the hazard #524 itself calls its sharp edge. If the
capacity arithmetic is ever wrong, an `extend_from_slice` reallocates: the
allocator copies the contents to a new block and frees the **old** one,
unwiped. `Drop` on the wrapper wipes whatever buffer the `Vec` points at
when it drops — the new one. The freed original is exactly the residue the
issue is worried about, and wrapping first has no effect on it.

### 2.2 The constructor

```rust
impl SecretBytes {
    /// Build a secret by concatenating `parts`, with capacity for exactly
    /// their total length.
    ///
    /// The capacity and the pushes are derived from the SAME slice list, in
    /// one expression, so the two cannot drift: a mid-build reallocation —
    /// which would free an unwiped buffer holding the concatenated secret —
    /// is unrepresentable rather than merely unlikely (#524).
    ///
    /// The wrapper is constructed before the first push, so an unwinding
    /// panic during the build drops and wipes it.
    #[must_use]
    pub fn concat(parts: &[&[u8]]) -> Self;
}
```

### 2.3 Why `concat` and not `build` / `try_build`

Three reasons, in order of weight:

1. **It closes the realloc hazard; `build` does not.** §2.1.
2. **It lends no `&mut`.** `Sensitive::build`'s doc comment names the
   move-out family as its residual hole, and #521 (this slice, §4) exists to
   police it. Adding a second `&mut`-lending constructor widens exactly the
   capability the same slice is adding a CI guard for.
3. **No caller needs a general incremental fill.** `derive_wrap_key` is
   the only site #524 names, and it is a pure concatenation.

`SecretBytes::build` / `try_build` are therefore **not** added. If a
fallible incremental fill ever appears, adding them then is a reviewed
decision with a live caller to justify it.

### 2.4 The call site

```rust
// §7 normative: ikm = ss_x || ss_pq || ct_x || ct_pq || sender_pk_bundle
//                     || recipient_pk_bundle
let ikm = SecretBytes::concat(&[
    ss_x.expose(),
    ss_pq.expose(),
    ct_x,
    ct_pq,
    sender_pk_bundle,
    recipient_pk_bundle,
]);
```

The six-term capacity expression naming `X25519_PK_LEN` at `ct_x`'s
position is deleted. That expression is what #524 flags: `ct_x` is typed
`&[u8; X25519_PK_LEN]`, so the two agree today by type — but a future
change giving the X25519 KEM ciphertext its own length constant would make
the capacity silently wrong, with no compiler error.

### 2.5 What is testable here, stated honestly

A wipe of freed heap is **not observable from safe Rust**, and neither is a
reallocation that did not happen. So:

- **Tested:** `concat` produces the byte-exact concatenation, in order, for
  representative inputs including empty parts, a single part, and the
  no-parts case; and `derive_wrap_key`'s output is unchanged (the existing
  `hybrid_kem_kat.json` replay is the regression gate).
- **Not tested, structural:** that no reallocation occurs. The argument is
  that capacity and pushes are computed from one slice list in one
  function, so they cannot disagree. This slice does not add an assertion
  pretending otherwise.

---

## 3. #522 + audit C-4 — `bundle.rs`

### 3.1 Read side: `take_fixed_bytes_into`

```rust
/// Write-through fixed-size byte extractor.
///
/// The destination is supplied by the caller — which is expected to have
/// wrapper-covered it via `Sensitive::try_build` — so no unwrapped
/// `[u8; N]` is materialised in this frame or returned by value (#522).
///
/// The source `Vec` is wrapped rather than wiped after the fact:
/// `Vec::try_into` reaches an array via `set_len(0)` + `ptr::read`, i.e. a
/// COPY, so the CBOR byte string's heap buffer would otherwise be
/// deallocated with the secret key still in it (audit C-4). `SecretBytes::new`
/// MOVES the buffer, so its `Drop` covers every exit below, including the
/// wrong-length `return` — there is no trailing statement for control flow
/// to skip.
fn take_fixed_bytes_into<const N: usize>(
    v: Value,
    field: &'static str,
    out: &mut [u8; N],
) -> Result<(), BundleError> {
    let Value::Bytes(b) = v else {
        return Err(BundleError::Malformed("expected byte string"));
    };
    let bytes = SecretBytes::new(b);
    let got = bytes.len();
    if got != N {
        return Err(BundleError::WrongKeySize { field, expected: N, got });
    }
    out.copy_from_slice(bytes.expose());
    Ok(())
}
```

`take_fixed_bytes` is **deleted**, not kept as a sibling. It also serves
the two public-key sites (`x25519_pk`, `ed25519_pk`), which are converted
to the write-through form with a plain `[u8; N]` destination. Keeping it
for those would leave the by-value shape available and re-create the
unevenness #522 complains about — #503's principle, which #522 cites, is
"removes the by-value producer, so the unsafe shape is awkward to write
rather than merely discouraged."

Secret call sites become:

```rust
KEY_X25519_SK => set_once(
    &mut x25519_sk_bytes,
    Sensitive::try_build([0u8; X25519_SK_LEN], |slot| {
        take_fixed_bytes_into(v, KEY_X25519_SK, slot)
    })?,
    KEY_X25519_SK,
)?,
```

**`take_sized_bytes`: signature unchanged, error path fixed.** Its success
path returns the `Vec` by move into `Sensitive::new`, so the heap buffer's
ownership transfers and no copy exists — #522 says so and is right, and
that path needs nothing. Its wrong-length **error** path is different: it
drops a plain `Vec` unwiped, holding a byte string that failed a length
check on a secret-key field. Same class as C-4, one line to close with the
same `SecretBytes::new`-first move. The function keeps returning
`Result<Vec<u8>, _>` — there is no by-value *secret copy* to remove here,
only an unwiped early-return drop.

**Not changed:** `take_uuid`, which has the same `try_into` shape over a
user UUID. A UUID is not secret material (`vault.toml` is cleartext on
disk, vault-format §2).

### 3.2 Write side: audit C-4's untracked half

`to_canonical_cbor` builds its entry list as

```rust
(Value::Text(KEY_X25519_SK.into()), Value::Bytes(self.x25519_sk.expose().clone()))
```

— a fresh plain `Vec<u8>` per secret key. `ciborium::Value` has no
zeroizing `Drop`, so all four long-term secret keys are freed unwiped on
every call. C-4 named the *encoded output* buffer (closed by #513 Task 6)
and the canonical re-encode (closed by #357) but not these clones, and no
issue tracks them. Filed as **#542** as part of this slice so the fix
carries a tracker citation.

Fix is a local newtype rather than a trailing sweep, so the panic path is
covered:

```rust
/// Owns a CBOR entry list whose byte strings are wiped on drop.
///
/// `ciborium::Value` is a foreign type with no zeroizing `Drop`, and the
/// entries built by `to_canonical_cbor` clone every long-term secret key
/// into a `Value::Bytes`. Wiping in `Drop` rather than after `encode_map`
/// covers the unwinding-panic and early-return paths a trailing sweep
/// would skip (audit C-4).
struct ZeroizingEntries(Vec<(Value, Value)>);
```

**Boundary, stated rather than glossed:** the `vec![…]` literal constructs
every clone *before* the wrapper takes ownership. If that literal itself
unwinds part-way, the already-built elements are dropped as temporaries,
unwiped. The only unwind source there is allocation failure, which aborts
rather than unwinds, so this is not a live path — but it is not the
"covered on every path" completeness the wrapper has once it exists.

### 3.3 File size

`bundle.rs` is 986 lines before this slice and gains roughly 50. That is
already past the 500-line guideline. Splitting it into a directory module
is **not** done here: it is frozen-adjacent identity-bundle codec, and
mixing a structural move with a security fix means one review has to cover
both. Filed as **#543** instead.

---

## 4. #521 — the move-out guard

### 4.1 Shape

`scripts/check-secret-slot-hygiene.sh`, a **bash** guard sourcing the
existing `scripts/lib/hygiene-allowlist.sh` for `allowlisted` and
`is_comment_line`.

The issue proposes `scripts/check-secret-slot-hygiene.py` while citing the
bash allowlist library for its semantics. Bash is chosen because the rule
is a five-identifier denial over Rust source — the payload/placement guards'
machinery exists to parse declarations and construction sites, none of which
this rule needs — and because sourcing the shared matchers is the whole
reason those matchers were hoisted into `scripts/lib/` in the first place.
`is_comment_line`'s `//` / `/* */` handling is already exactly right for
Rust.

### 4.2 Rules

| Rule | Denies |
|---|---|
| `S1` | `mem::swap`, `mem::replace`, `mem::take`, `mem::forget` (bare and `std::`-qualified) |
| `S2` | `ManuallyDrop` |

**Tree-wide across the roots, not scoped to a `build` closure.** Scoping to
a closure body would need brace matching in bash, and would miss the class
#521 explicitly names: `mem::forget` / `ManuallyDrop` defeat `ZeroizeOnDrop`
on *every* wrapper in `secret.rs`, wherever they are written, not only
inside a fill closure.

Roots: `core/src`, `ffi/secretary-ffi-bridge/src`, `ffi/secretary-ffi-py/src`,
`ffi/secretary-ffi-uniffi/src`, `desktop/src-tauri/src`, `cli/src` — the six
#521 lists.

### 4.3 Two decisions that differ from the existing guards

- **`#[cfg(test)]` code IS scanned.** #496 found that the payload guard's
  permissive `#[cfg(...test...)]` matcher was used as a skip list, where an
  over-match is **fail-open** — `#[cfg(not(test))]` silenced a violation in
  one line. This guard has no test carve-out at all. A test that genuinely
  needs `mem::swap` becomes a reviewed allowlist entry with a visible key.
- **`--self-test` probes are written to `mktemp -d`, never the source
  tree.** #516 is open against the payload guard for doing the opposite:
  its probe files race a parallel session and hide residue from
  `git status`. Not repeating it.

### 4.4 Self-test controls

Two-sided, following the established discipline — a green guard must never
be vacuous:

- **Positive:** a planted `mem::swap` inside a `Sensitive::build` closure; a
  planted `mem::forget`; a planted `ManuallyDrop`. Each must fire.
- **Negative:** `secret.rs:196`'s doc comment, which names `std::mem::swap`
  and `std::mem::replace` in prose. `is_comment_line` anchors on `//`, so
  `///` is prose and this must stay silent.

The allowlist (`scripts/secret-slot-hygiene-allowlist.txt`) ships **empty**.
The census is empty today: one grep hit tree-wide, and it is the doc comment
above.

### 4.5 CI

Two steps in `.github/workflows/test.yml` beside the other hygiene guards,
`--self-test` first. No branch-ruleset change is needed: the steps join an
existing required job rather than creating a new check.

---

## 5. #525 — `derive_device_kek` expected-bytes KAT

`derive_device_kek` has three unit tests. None pins expected bytes:
`device_kek_is_deterministic_and_independent_of_recovery_kek` compares two
of its own outputs, and `device_kek_matches_independent_hkdf_reference`
recomputes with **the same `Hkdf::<Sha256>` primitive**, so a defect in that
crate, or a salt/info change mirrored into both, passes. It is the only KDF
in the file with no expected-bytes vector — `derive_recovery_kek` has
`recovery_kek_test_vector_zero_entropy`.

- **Vehicle:** `core/tests/data/device_kek_kat.json`, consumed by a new
  `device_kek_kats` test in `core/tests/kdf.rs` via the existing `load_kat`
  helper. A JSON fixture rather than an inline `hex("…")` literal, per the
  standing repo rule that KATs live in JSON.
- **Provenance:** expected bytes generated from Python `cryptography`'s
  HKDF — an independent implementation — and **never** from
  `derive_device_kek` itself, which would pin whatever the function
  currently does including a bug. The generating command is recorded in the
  fixture's `comment` field so it can be re-derived.
- **Scope:** Rust only. `conformance.py` already has its own clean-room
  `derive_device_kek` (line 1655), so a cross-language replay is possible
  and is deliberately **not** done here — it widens the slice and the
  clean-room path is already exercised end-to-end by the golden-vault
  device-slot test.
- **Vectors:** three 32-byte device secrets — all-zero (`00×32`), all-ones
  (`ff×32`), and the ascending byte counter `00 01 02 … 1f`. Enough to catch
  a wrong salt, a wrong info string, or a wrong output length; not an
  exhaustive suite and not claimed as one.

---

## 6. #527 — desktop `record_title` candidates

`labels_for_record` builds `Vec<Candidate>` where `Candidate.value: String`
holds each allowlisted field's decrypted plaintext. The vector drops
unwiped, holding two things that never reach the frontend: priority-race
losers, and the tail of any value truncated to `MAX_LABEL_CHARS`.

Fix: `Candidate.value` becomes `SecretString`. `secretary-core` is already
a dependency of `desktop/src-tauri` and `SecretString` is already imported
there.

Touched: the struct, the one push site in `labels_for_record`, the two read
sites in `select_labels` (`.expose().trim()`), and the `cand()` test helper.

**`Candidate.name` stays `String`** and that is deliberate: a candidate only
exists if `allowlist_rank` returned `Some`, so `name` is necessarily one of
the six compile-time literals in `TITLE_NAMES`, not runtime plaintext.

**The gate ordering in `labels_for_record` is not touched.** Its doc
comment states that `allowlist_rank` and `is_text` precede `expose_text`,
that the ordering is enforced by structure and review rather than by a
test, and "Do not reorder." This change alters the type of what is pushed,
never the order of the checks.

---

## 7. #523 — dangling SHA in CLAUDE.md

`CLAUDE.md:735` cites `9cad5b3c` for the creation of `array32_from_vec_into`.
`main` squash-merges, so that branch-local SHA is unreachable from `main`
and the citation dangles. Repointed at the merge commit `2e6dd764` (PR #520).

---

## 8. Sequencing

Each step is one commit; the guard lands last so it scans the finished tree.

| # | Item | Files |
|---|---|---|
| 1 | #523 | `CLAUDE.md` |
| 2 | #524 | `core/src/crypto/secret.rs`, `core/src/crypto/kem.rs` |
| 3 | #522 + C-4 read side | `core/src/unlock/bundle.rs` |
| 4 | C-4 write side | `core/src/unlock/bundle.rs` |
| 5 | #525 | `core/tests/data/device_kek_kat.json`, `core/tests/kdf.rs` |
| 6 | #527 | `desktop/src-tauri/src/record_title.rs` |
| 7 | #521 | `scripts/check-secret-slot-hygiene.sh`, allowlist, `.github/workflows/test.yml` |
| 8 | Docs | `memory-hygiene-audit-internal.md`, `CLAUDE.md`, `ROADMAP.md`/`README.md` if warranted |

Steps 3 and 4 touch the same file and are kept separate so the read-side and
write-side arguments can be reviewed independently.

## 9. Gates

Everything in the baton's resume block, plus the new guard. The two that
matter most for this slice specifically:

- `cargo test --release --workspace` — the `hybrid_kem_kat.json` replay is
  the regression gate on §2, and the bundle round-trip tests on §3.
- `uv run core/tests/python/conformance.py` — §2 and §3 both touch code on
  the golden-vault decrypt path; the clean-room verifier is what proves the
  observable byte format did not move.

**No on-disk format change, no FFI surface change, no `.udl` change, no KAT
regeneration.** `git diff main... -- ffi/secretary-ffi-uniffi/src/secretary.udl`
must be empty, and `core/tests/data/` must gain exactly one file.

## 10. Issues filed by this slice

- **#542** — audit C-4's write-side remnant (§3.2), fixed in this slice.
- **#543** — `bundle.rs` directory-module split (§3.3), deferred.
