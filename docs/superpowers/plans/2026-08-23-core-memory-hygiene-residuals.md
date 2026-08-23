# Core memory-hygiene residual closeout — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the six memory-hygiene residuals left by PR #520 and the #526 desktop review (#522, #524, #521, #527, #525, #523), plus the one live remnant of 2026-07-02 audit finding C-4 (#542).

**Architecture:** Six independent fixes plus one new CI guard. Two touch frozen-adjacent crypto (`crypto/secret.rs`, `crypto/kem.rs`, `unlock/bundle.rs`) and are guarded by the existing KAT replays; one touches the desktop Tauri backend; one adds a bash tripwire modelled on the existing iOS/Android log-hygiene guards. No on-disk format change, no FFI surface change.

**Tech Stack:** Rust (stable, pinned 1.97.0), bash guards sourcing `scripts/lib/hygiene-allowlist.sh`, JSON KAT fixtures under `core/tests/data/`, GitHub Actions.

**Spec:** [`docs/superpowers/specs/2026-08-23-core-memory-hygiene-residuals-design.md`](../specs/2026-08-23-core-memory-hygiene-residuals-design.md)

## Global Constraints

- **Worktree:** all work happens in `/Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals` on branch `feature/core-memory-hygiene-residuals`. Verify with `pwd && git branch --show-current` before any `cargo` or `git` command. The Edit tool targets the MAIN repo unless the path spells out `.worktrees/core-memory-hygiene-residuals/`.
- **Always `--release`.** The crypto crates are unusably slow in debug.
- **`#![forbid(unsafe_code)]`** is a workspace lint. Do not introduce `unsafe`.
- **Clippy must stay clean** with `-D warnings`, both with and without `--tests`.
- **No hardcoded crypto values in `.rs` files.** KAT vectors live in `core/tests/data/*.json`.
- **Commit trailer**, on every commit: `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`
- **Issue-citation convention:** cite as `(#N)`, never `Closes #N` — GitHub's auto-close keywords are case-insensitive and a squash-merge would close the issue against repo convention.
- **Do not touch** `ffi/secretary-ffi-uniffi/src/secretary.udl` or any file under `core/tests/data/` other than the one new fixture in Task 5.

---

### Task 1: #523 — repoint the dangling SHA in CLAUDE.md

**Files:**
- Modify: `CLAUDE.md:735`

**Interfaces:**
- Consumes: nothing.
- Produces: nothing. Documentation only; no later task depends on it.

`main` squash-merges, so the branch-local SHA `9cad5b3c` cited for the creation of `array32_from_vec_into` is unreachable from `main`. The merge commit that carries that work is `2e6dd764` (PR #520).

- [ ] **Step 1: Confirm the SHA is genuinely unreachable from `main`**

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
git merge-base --is-ancestor 9cad5b3c origin/main && echo "REACHABLE — do not change" || echo "UNREACHABLE — proceed"
git merge-base --is-ancestor 2e6dd764 origin/main && echo "2e6dd764 reachable — good replacement"
```

Expected: `UNREACHABLE — proceed` then `2e6dd764 reachable — good replacement`.

- [ ] **Step 2: Make the edit**

Current text at `CLAUDE.md:734-735`:

```
      pre-date this work; the sixth, `array32_from_vec_into`, was created
      by this branch (Task 7, `9cad5b3c`) and inherits the forwarding shape
```

Replace with:

```
      pre-date this work; the sixth, `array32_from_vec_into`, was created
      by that work (PR #520, merged as `2e6dd764`) and inherits the forwarding shape
```

- [ ] **Step 3: Verify no other dangling SHA remains in CLAUDE.md**

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
for s in $(grep -oE '`[0-9a-f]{7,40}`' CLAUDE.md | tr -d '`' | sort -u); do
  git merge-base --is-ancestor "$s" origin/main 2>/dev/null || echo "STILL DANGLING: $s"
done
```

Expected: no output. If a SHA prints, it is a second instance of #523 — fix it the same way and say so in the commit body.

- [ ] **Step 4: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
git add CLAUDE.md
git commit -F - <<'MSG'
docs: repoint CLAUDE.md's dangling `9cad5b3c` at the merge commit (#523)

`main` squash-merges, so a branch-local SHA cited in a durable doc stops
resolving the moment the PR lands. `9cad5b3c` was PR #520's Task 7 commit;
the reachable citation is the merge commit `2e6dd764`.

Verified by `git merge-base --is-ancestor`, and every other backticked SHA in
CLAUDE.md re-checked the same way.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

---

### Task 2: #524 — `SecretBytes::concat` and `derive_wrap_key`

**Files:**
- Modify: `core/src/crypto/secret.rs` (add `concat` to `impl SecretBytes`, add unit tests to the existing `#[cfg(test)] mod tests` at line 260)
- Modify: `core/src/crypto/kem.rs:251-270` (`derive_wrap_key`)

**Interfaces:**
- Consumes: the existing `SecretBytes { inner: Vec<u8> }` at `core/src/crypto/secret.rs:25`.
- Produces: `pub fn SecretBytes::concat(parts: &[&[u8]]) -> SecretBytes`. No later task consumes it, but it becomes public API.

Read spec §2 before starting. The key point: `try_build` (what the issue asks for) does **not** close the reallocation hazard the issue itself flags, because `Drop` wipes only the buffer the `Vec` points at when it drops, not one a `realloc` already freed. `concat` derives capacity and pushes from one slice list, so they cannot disagree.

- [ ] **Step 1: Write the failing tests**

Add to `core/src/crypto/secret.rs`, inside the existing `#[cfg(test)] mod tests` block (it begins `mod tests {` with `use super::{SecretBytes, SecretString};`), after the `SecretString` tests:

```rust
    // --- SecretBytes::concat (#524) ------------------------------------------

    #[test]
    fn concat_joins_parts_in_order() {
        let s = SecretBytes::concat(&[b"abc", b"de", b"f"]);
        assert_eq!(s.expose(), b"abcdef");
    }

    #[test]
    fn concat_length_is_the_sum_of_part_lengths() {
        // The property the realloc argument rests on: the buffer ends up
        // holding exactly what was reserved for it. A shorter or longer
        // result would mean capacity and pushes had drifted apart, which is
        // the drift `concat` exists to make unrepresentable (#524).
        let parts: [&[u8]; 4] = [&[0u8; 32], &[1u8; 32], &[2u8; 1088], &[3u8; 7]];
        let expected: usize = parts.iter().map(|p| p.len()).sum();
        let s = SecretBytes::concat(&parts);
        assert_eq!(s.len(), expected);
    }

    #[test]
    fn concat_skips_empty_parts_without_disturbing_order() {
        let s = SecretBytes::concat(&[b"", b"xy", b"", b"z", b""]);
        assert_eq!(s.expose(), b"xyz");
    }

    #[test]
    fn concat_of_no_parts_is_empty() {
        let s = SecretBytes::concat(&[]);
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn concat_of_a_single_part_copies_it() {
        let s = SecretBytes::concat(&[b"only"]);
        assert_eq!(s.expose(), b"only");
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
cargo test --release -p secretary-core --lib crypto::secret::tests::concat 2>&1 | tail -20
```

Expected: FAIL to compile — `no function or associated item named 'concat' found for struct 'SecretBytes'`.

- [ ] **Step 3: Implement `concat`**

In `core/src/crypto/secret.rs`, inside `impl SecretBytes` (which currently ends after `is_empty` at roughly line 52), add after `new`:

```rust
    /// Build a secret by concatenating `parts`, reserving capacity for
    /// exactly their total length.
    ///
    /// Prefer this over `let mut v = Vec::with_capacity(n); v.extend_from_slice(..);
    /// let s = SecretBytes::new(v);` for any incrementally-built secret. That
    /// shape has two failure modes this constructor removes:
    ///
    /// 1. The buffer is not wrapper-covered until the final statement, so an
    ///    unwinding panic part-way through the fill frees it unwiped. Here the
    ///    wrapper exists before the first push (#513's wrap-before-use rule).
    /// 2. More subtly, if the hand-written capacity is ever wrong, an
    ///    `extend_from_slice` REALLOCATES: the allocator copies to a new block
    ///    and frees the old one, unwiped. Wrapping first does not help —
    ///    `Drop` wipes whatever buffer the `Vec` points at when it drops, which
    ///    is the new one. Here the capacity and the pushes are derived from the
    ///    same `parts` slice in the same function, so they cannot drift and no
    ///    reallocation can occur (#524).
    ///
    /// That second property is structural, not asserted: a reallocation that
    /// did not happen is not observable from safe Rust, so there is no test
    /// for it and this doc does not claim one.
    #[must_use]
    pub fn concat(parts: &[&[u8]]) -> Self {
        let total: usize = parts.iter().map(|p| p.len()).sum();
        // Wrapper first: `s` is `ZeroizeOnDrop` before any secret byte lands
        // in it, so an unwinding panic below drops and wipes it.
        let mut s = Self {
            inner: Vec::with_capacity(total),
        };
        for part in parts {
            s.inner.extend_from_slice(part);
        }
        s
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
cargo test --release -p secretary-core --lib crypto::secret::tests::concat 2>&1 | tail -12
```

Expected: `test result: ok. 5 passed; 0 failed`.

- [ ] **Step 5: Convert `derive_wrap_key`**

In `core/src/crypto/kem.rs`, replace lines 251-270 — everything from `let mut ikm_buf = Vec::with_capacity(` through `let ikm = SecretBytes::new(ikm_buf);` inclusive — with:

```rust
    // §7 normative order: ikm = ss_x || ss_pq || ct_x || ct_pq
    //                           || sender_pk_bundle || recipient_pk_bundle
    //
    // `concat` reserves exactly the total length of these six slices and
    // pushes exactly these six slices, so no reallocation can free an
    // unwiped intermediate holding both KEM shared secrets. The previous
    // form hand-wrote the capacity, naming `X25519_PK_LEN` at `ct_x`'s
    // position: correct today only because `ct_x` is typed
    // `&[u8; X25519_PK_LEN]`, and silently wrong the day an X25519 KEM
    // ciphertext gets its own length constant (#524).
    //
    // The buffer is also wrapper-covered from allocation rather than from a
    // trailing `SecretBytes::new`, so an unwinding panic inside
    // `hkdf_sha256_extract_and_expand` below (its own internal `.expect()`,
    // see that function's doc comment) still wipes it via `Drop` (#513).
    let ikm = SecretBytes::concat(&[
        ss_x.expose(),
        ss_pq.expose(),
        ct_x,
        ct_pq,
        sender_pk_bundle,
        recipient_pk_bundle,
    ]);
```

Leave everything after that line — the `info` build, the HKDF call, the `okm`/`key` handling — untouched. Spec §1.2 records that the `okm` slot was checked and is not a defect.

- [ ] **Step 6: Verify the KEM output did not move**

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
cargo test --release -p secretary-core --test kem 2>&1 | tail -8
cargo test --release --workspace 2>&1 | tail -25
```

Expected: all pass. The `hybrid_kem_kat.json` replay is the gate — if `derive_wrap_key`'s output changed, the concatenation order is wrong and it will fail here.

- [ ] **Step 7: Lint and format**

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
cargo fmt --all
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -8
cargo clippy --release --workspace -- -D warnings 2>&1 | tail -8
```

Expected: clean. `X25519_SS_LEN` / `ML_KEM_768_SS_LEN` / `X25519_PK_LEN` are declared in `kem.rs` itself and still used in signatures, so removing the capacity expression orphans no imports — if clippy reports an unused import anyway, delete it.

- [ ] **Step 8: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
git add core/src/crypto/secret.rs core/src/crypto/kem.rs
git commit -F - <<'MSG'
feat(core): SecretBytes::concat, and use it for derive_wrap_key's ikm (#524)

#524 asks for `SecretBytes::try_build`. That closes the panic window but NOT
the hazard #524 itself calls its sharp edge: if the hand-written capacity is
ever wrong, `extend_from_slice` reallocates and frees the OLD buffer unwiped,
and `Drop` only ever wipes the buffer the Vec points at when it drops — the
new one.

`concat` derives the capacity and performs the pushes from the same slice
list in the same function, so the two cannot drift and no reallocation can
occur. It is also strictly less surface than the constructor pair: it lends
no `&mut`, which matters because the same slice adds a CI guard (#521)
policing exactly that capability.

The call site now reads as its own normative spec line — §7's
ss_x || ss_pq || ct_x || ct_pq || sender_pk_bundle || recipient_pk_bundle.
The deleted capacity expression named X25519_PK_LEN at ct_x's position:
correct today only because ct_x is typed `&[u8; X25519_PK_LEN]`, and silently
wrong the day an X25519 KEM ciphertext gets its own constant.

No output change — hybrid_kem_kat.json replays unchanged.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

---

### Task 3: #522 — write-through `take_fixed_bytes_into`

**Files:**
- Modify: `core/src/unlock/bundle.rs` — the decode loop at lines 406, 411, 426, 431; `take_fixed_bytes` at line 597; `take_sized_bytes` at line 612; imports at line 57; tests in `#[cfg(test)] mod tests` at line 636.

**Interfaces:**
- Consumes: `Sensitive::try_build` (pre-existing, `core/src/crypto/secret.rs:245`), `SecretBytes::new` (pre-existing).
- Produces: `fn take_fixed_bytes_into<const N: usize>(v: Value, field: &'static str, out: &mut [u8; N]) -> Result<(), BundleError>` — private to `bundle.rs`. Task 4 touches the same file but does not call it.

Read spec §1.1 and §3.1 first. `take_fixed_bytes` leaves **three** residues, not the one #522 names; the third is the CBOR byte string's heap buffer, freed unwiped because `Vec::try_into` is `set_len(0)` + `ptr::read`, i.e. a copy.

- [ ] **Step 1: Write the failing tests**

Add to `core/src/unlock/bundle.rs`, inside the existing `#[cfg(test)] mod tests` block at line 636 (which opens with `use super::*;`):

```rust
    // --- take_fixed_bytes_into (#522, audit C-4) ----------------------------

    #[test]
    fn take_fixed_bytes_into_writes_through_on_the_happy_path() {
        let mut out = [0u8; 4];
        take_fixed_bytes_into(Value::Bytes(vec![1, 2, 3, 4]), "field", &mut out)
            .expect("exact length must be accepted");
        assert_eq!(out, [1, 2, 3, 4]);
    }

    #[test]
    fn take_fixed_bytes_into_rejects_a_wrong_length_and_reports_both_sizes() {
        let mut out = [0u8; 4];
        let err = take_fixed_bytes_into(Value::Bytes(vec![1, 2, 3]), "x25519_sk", &mut out)
            .expect_err("short input must be rejected");
        match err {
            BundleError::WrongKeySize {
                field,
                expected,
                got,
            } => {
                assert_eq!(field, "x25519_sk");
                assert_eq!(expected, 4);
                assert_eq!(got, 3);
            }
            other => panic!("expected WrongKeySize, got {other:?}"),
        }
    }

    #[test]
    fn take_fixed_bytes_into_leaves_the_destination_untouched_on_a_wrong_length() {
        // The destination is caller-owned and, at every production call site,
        // already wrapper-covered by `Sensitive::try_build`. A rejected decode
        // must not half-fill it. Seeded non-zero so "untouched" is
        // distinguishable from "zeroed", which a zero-seeded assertion could
        // not tell apart (a #513 review finding).
        let mut out = [0xAAu8; 4];
        let _ = take_fixed_bytes_into(Value::Bytes(vec![1, 2, 3]), "field", &mut out);
        assert_eq!(out, [0xAAu8; 4]);
    }

    #[test]
    fn take_fixed_bytes_into_rejects_a_non_bytes_cbor_value() {
        let mut out = [0u8; 4];
        let err = take_fixed_bytes_into(Value::Text("nope".into()), "field", &mut out)
            .expect_err("a text value is not a byte string");
        assert!(matches!(err, BundleError::Malformed(_)));
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
cargo test --release -p secretary-core --lib unlock::bundle::tests::take_fixed_bytes_into 2>&1 | tail -20
```

Expected: FAIL to compile — `cannot find function 'take_fixed_bytes_into' in this scope`.

- [ ] **Step 3: Add the import**

`core/src/unlock/bundle.rs:57` currently reads:

```rust
use crate::crypto::secret::Sensitive;
```

Change it to:

```rust
use crate::crypto::secret::{SecretBytes, Sensitive};
```

- [ ] **Step 4: Replace `take_fixed_bytes` with the write-through form**

Delete the whole `take_fixed_bytes` function at `core/src/unlock/bundle.rs:597-611` and put this in its place:

```rust
/// Write-through fixed-size byte extractor.
///
/// The destination is supplied by the caller — which for every secret-key
/// site is a slot already wrapper-covered by `Sensitive::try_build` — so no
/// unwrapped `[u8; N]` is materialised in this frame or returned by value.
/// The by-value predecessor (`take_fixed_bytes`) left one copy here and
/// another in the caller's return temporary (#522); it is deleted rather
/// than kept alongside this, so the unsafe shape is awkward to write rather
/// than merely discouraged — the same move #503 made on both binding crates.
///
/// The source `Vec` is WRAPPED rather than wiped after the fact.
/// `Vec::try_into` reaches its array via `set_len(0)` + `ptr::read` — a COPY,
/// not a move-out — so the CBOR byte string's heap buffer would otherwise be
/// deallocated with the secret key still in it. That is the 2026-07-02
/// audit's finding C-4, and it was its last live sub-item.
/// `SecretBytes::new` MOVES the buffer, so `Drop` covers every exit below,
/// including the wrong-length `return`, with no trailing statement for
/// control flow to skip.
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
        return Err(BundleError::WrongKeySize {
            field,
            expected: N,
            got,
        });
    }
    out.copy_from_slice(bytes.expose());
    Ok(())
}
```

- [ ] **Step 5: Convert the four call sites**

In the decode loop, replace the four arms at `core/src/unlock/bundle.rs:405-432`.

The two **secret** sites — the destination is wrapper-covered before the fill:

```rust
                KEY_X25519_SK => set_once(
                    &mut x25519_sk_bytes,
                    Sensitive::try_build([0u8; X25519_SK_LEN], |slot| {
                        take_fixed_bytes_into(v, KEY_X25519_SK, slot)
                    })?,
                    KEY_X25519_SK,
                )?,
```

```rust
                KEY_ED25519_SK => set_once(
                    &mut ed25519_sk_bytes,
                    Sensitive::try_build([0u8; ED25519_SK_LEN], |slot| {
                        take_fixed_bytes_into(v, KEY_ED25519_SK, slot)
                    })?,
                    KEY_ED25519_SK,
                )?,
```

The two **public** sites — no wrapper needed, a public key is not secret, but they use the same helper so the by-value producer has no remaining caller:

```rust
                KEY_X25519_PK => set_once(
                    &mut x25519_pk,
                    {
                        let mut pk = [0u8; X25519_PK_LEN];
                        take_fixed_bytes_into(v, KEY_X25519_PK, &mut pk)?;
                        pk
                    },
                    KEY_X25519_PK,
                )?,
```

```rust
                KEY_ED25519_PK => set_once(
                    &mut ed25519_pk,
                    {
                        let mut pk = [0u8; ED25519_PK_LEN];
                        take_fixed_bytes_into(v, KEY_ED25519_PK, &mut pk)?;
                        pk
                    },
                    KEY_ED25519_PK,
                )?,
```

- [ ] **Step 6: Close `take_sized_bytes`'s wrong-length error path**

`take_sized_bytes` (now around line 612) returns its `Vec` by move on success, so the success path needs nothing. Its wrong-length `return` drops a plain `Vec` unwiped. Replace the body's opening so the buffer is wrapper-covered before the length check, keeping the signature unchanged:

```rust
fn take_sized_bytes(
    v: Value,
    field: &'static str,
    expected: usize,
) -> Result<Vec<u8>, BundleError> {
    let Value::Bytes(b) = v else {
        return Err(BundleError::Malformed("expected byte string"));
    };
    // Wrapper-covered before the length check so the REJECT path does not
    // free a secret-key-shaped byte string unwiped (audit C-4). The success
    // path unwraps back to a `Vec` that the caller moves straight into
    // `Sensitive::new`, so ownership of the same heap buffer transfers and no
    // copy is made.
    let bytes = SecretBytes::new(b);
    if bytes.len() != expected {
        return Err(BundleError::WrongKeySize {
            field,
            expected,
            got: bytes.len(),
        });
    }
    Ok(bytes.expose().to_vec())
}
```

**Note the one real cost:** `bytes.expose().to_vec()` copies, where the old code moved. That is a deliberate trade — a copy on the success path in exchange for a wiped reject path — and the copy's source is wiped by `bytes`' own `Drop` one line later. If the reviewer prefers the move, the alternative is to keep the plain `Vec` and add an explicit `b.zeroize()` before the wrong-length `return`, which trades the copy for a trailing statement a panic could skip. Flag this in the commit body so the choice is reviewed, not assumed.

- [ ] **Step 7: Run the tests**

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
cargo test --release -p secretary-core --lib unlock::bundle 2>&1 | tail -15
cargo test --release --workspace 2>&1 | tail -25
```

Expected: all pass, including the pre-existing `from_canonical_cbor_reports_the_missing_field_and_takes_the_early_return` and `from_canonical_cbor_early_return_leaves_both_pq_secret_keys_wrapped`.

- [ ] **Step 8: Prove the by-value producer is gone**

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
grep -n "take_fixed_bytes\b" core/src/unlock/bundle.rs || echo "OK: no by-value take_fixed_bytes remains"
```

Expected: `OK: no by-value take_fixed_bytes remains`. (`take_fixed_bytes_into` will not match because of the `\b`.)

- [ ] **Step 9: Lint, format, and run the clean-room verifier**

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
cargo fmt --all
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -8
uv run core/tests/python/conformance.py 2>&1 | tail -8
```

Expected: clippy clean; conformance PASS. This code is on the golden-vault decrypt path, so conformance is the proof that observable byte format did not move.

- [ ] **Step 10: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
git add core/src/unlock/bundle.rs
git commit -F - <<'MSG'
fix(core): write-through fixed-size decode, closing all three residues (#522)

#522 names one residue — the `[u8; N]` in `take_fixed_bytes`' own frame.
There are three, and the third is the worst: `Vec::try_into` reaches its
array via `set_len(0)` + `ptr::read`, which is a COPY, so the CBOR byte
string's heap buffer is deallocated with the secret key still in it. Heap
residue outlives stack residue.

That is not a new claim. The 2026-07-02 audit's C-4 said exactly this, and it
was C-4's last live sub-item — the canonical re-encode buffer was closed by
#357, the bundle plaintext by #513 Task 6, and the `Copy` locals by #518.

`take_fixed_bytes_into` writes through a caller-owned destination (already
wrapper-covered by `Sensitive::try_build` at both secret sites) and wraps the
source Vec in SecretBytes so Drop covers every exit including the
wrong-length return. The by-value producer is DELETED rather than kept as a
sibling, and the two public-key sites move onto the same helper — #503's
principle, which #522 cites: remove the by-value producer so the unsafe shape
is awkward to write rather than merely discouraged.

`take_sized_bytes`'s success path already moved its Vec and needed nothing;
its wrong-length reject path dropped one unwiped, and is closed the same way.
FOR REVIEW: that fix trades a move for a copy on the success path
(`bytes.expose().to_vec()`), the copy's source being wiped by Drop one line
later. The alternative — keep the move, add a trailing `b.zeroize()` before
the reject — trades the copy for a statement a panic can skip. Chose the copy.

conformance.py passes, so the observable byte format did not move.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

---

### Task 4: #542 — audit C-4's write side in `to_canonical_cbor`

**Files:**
- Modify: `core/src/unlock/bundle.rs` — `to_canonical_cbor` (the `entries` vec ending at line ~340 with `encode_map(&entries)`), plus a new `ZeroizingEntries` type and a test.

**Interfaces:**
- Consumes: `ciborium::Value` (already imported at line 49), `zeroize::Zeroize` (already used at line 476 via `use zeroize::Zeroize as _;`).
- Produces: `struct ZeroizingEntries(Vec<(Value, Value)>)` — private to `bundle.rs`. Nothing later consumes it.

Read spec §3.2. `to_canonical_cbor` clones every long-term secret key into a plain `Value::Bytes`; `ciborium::Value` has no zeroizing `Drop`.

- [ ] **Step 1: Write the failing test**

Add to `core/src/unlock/bundle.rs`'s `#[cfg(test)] mod tests`:

```rust
    // --- ZeroizingEntries (#542, audit C-4 write side) ----------------------

    #[test]
    fn zeroizing_entries_wipes_every_byte_string_on_drop() {
        // Observe the wipe through a raw pointer to the Vec's heap buffer,
        // captured while the value is alive. This asserts the Drop impl runs
        // and does what it says; it is NOT a claim that freed heap is
        // observable in general (it is not — see the spec §2.5).
        let secret = vec![0x42u8; 32];
        let ptr = secret.as_ptr();
        let entries = ZeroizingEntries(vec![(
            Value::Text("x25519_sk".into()),
            Value::Bytes(secret),
        )]);
        // Alive: the bytes are still there.
        assert_eq!(unsafe_read_first_byte(ptr), 0x42);
        drop(entries);
        assert_eq!(unsafe_read_first_byte(ptr), 0x00);
    }
```

That test needs `unsafe`, which the workspace forbids. **Use this version instead** — it asserts on the same `Drop` behaviour without reading freed memory, by wiping in place and inspecting before the drop:

```rust
    // --- ZeroizingEntries (#542, audit C-4 write side) ----------------------

    #[test]
    fn zeroizing_entries_wipe_clears_every_byte_string() {
        // Asserts the wipe LOGIC directly. Whether a freed allocation retains
        // bytes is not observable from safe Rust (spec §2.5), so what is
        // tested here is that `wipe` reaches every `Value::Bytes` in the list
        // and leaves the text keys alone.
        let mut entries = ZeroizingEntries(vec![
            (Value::Text("x25519_sk".into()), Value::Bytes(vec![0x42; 32])),
            (Value::Text("created_at".into()), Value::Integer(7.into())),
            (Value::Text("ed25519_sk".into()), Value::Bytes(vec![0x99; 64])),
        ]);
        entries.wipe();
        match &entries.0[0].1 {
            Value::Bytes(b) => assert!(b.iter().all(|&x| x == 0), "first key not wiped"),
            other => panic!("expected Bytes, got {other:?}"),
        }
        match &entries.0[2].1 {
            Value::Bytes(b) => assert!(b.iter().all(|&x| x == 0), "second key not wiped"),
            other => panic!("expected Bytes, got {other:?}"),
        }
        // Non-byte entries are untouched, so the map still round-trips.
        assert!(matches!(&entries.0[1].1, Value::Integer(_)));
        assert!(matches!(&entries.0[0].0, Value::Text(t) if t == "x25519_sk"));
    }

    #[test]
    fn to_canonical_cbor_still_round_trips_through_from_canonical_cbor() {
        // The wipe must not disturb the encoding: `encode_map` runs BEFORE
        // the wipe, so the emitted bytes are unaffected.
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([9u8; 32]);
        let bundle = IdentityBundle::generate(&mut rng, "alice".into(), 1_700_000_000_000);
        let encoded = bundle.to_canonical_cbor().expect("encode");
        let decoded = IdentityBundle::from_canonical_cbor(&encoded).expect("decode");
        assert_eq!(decoded.user_uuid, bundle.user_uuid);
        assert_eq!(decoded.x25519_sk.expose(), bundle.x25519_sk.expose());
    }
```

**Before writing the round-trip test, check how the existing tests in this file construct an `IdentityBundle`** — the exact `generate` signature and RNG import may differ from the sketch above:

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
sed -n '636,700p' core/src/unlock/bundle.rs
```

Match whatever helper those tests already use rather than inventing a new one. If an equivalent round-trip test already exists, skip the second test and keep only the `wipe` test.

- [ ] **Step 2: Run to verify failure**

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
cargo test --release -p secretary-core --lib unlock::bundle::tests::zeroizing_entries 2>&1 | tail -15
```

Expected: FAIL to compile — `cannot find struct 'ZeroizingEntries' in this scope`.

- [ ] **Step 3: Add the type**

Add near `encode_map` in `core/src/unlock/bundle.rs`:

```rust
/// Owns a CBOR entry list whose byte strings are wiped when it drops.
///
/// `to_canonical_cbor` clones every long-term secret key out of its wrapper
/// into a `Value::Bytes`, and `ciborium::Value` is a foreign type with no
/// zeroizing `Drop` — so without this, all four secret keys are freed
/// unwiped on every vault create and every unlock (the canonicality check in
/// `from_canonical_cbor` re-encodes, so the read path pays it too). That is
/// the write-side half of the 2026-07-02 audit's C-4, tracked as #542.
///
/// Wiping in `Drop` rather than after `encode_map` is deliberate: it covers
/// the unwinding-panic and early-return paths a trailing sweep would skip.
///
/// **Boundary, stated rather than glossed:** the `vec![…]` literal builds
/// every clone BEFORE this wrapper takes ownership. If that literal itself
/// unwinds part-way, the already-built elements drop as temporaries, unwiped.
/// The only unwind source there is allocation failure, which aborts rather
/// than unwinds, so it is not a live path — but it is not the "covered on
/// every path" completeness the wrapper has once it exists.
struct ZeroizingEntries(Vec<(Value, Value)>);

impl ZeroizingEntries {
    /// Zeroize every `Value::Bytes` in the list, leaving keys and non-byte
    /// values alone. Separate from `Drop` so it is directly testable.
    fn wipe(&mut self) {
        use zeroize::Zeroize as _;
        for (_, value) in &mut self.0 {
            if let Value::Bytes(bytes) = value {
                bytes.zeroize();
            }
        }
    }
}

impl Drop for ZeroizingEntries {
    fn drop(&mut self) {
        self.wipe();
    }
}
```

- [ ] **Step 4: Use it in `to_canonical_cbor`**

The function currently ends:

```rust
        ];
        encode_map(&entries)
    }
```

Change the `let entries = vec![` binding to wrap, and the tail to:

```rust
        ]);
        // `entries` holds a cleartext clone of all four long-term secret keys.
        // `ZeroizingEntries::drop` wipes them at the end of this expression,
        // on the error path as well as the success path (#542).
        encode_map(&entries.0)
    }
```

That is: change `let entries = vec![` to `let entries = ZeroizingEntries(vec![`, change the closing `];` to `]);`, and change `encode_map(&entries)` to `encode_map(&entries.0)`.

- [ ] **Step 5: Run the tests**

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
cargo test --release -p secretary-core --lib unlock::bundle 2>&1 | tail -15
cargo test --release --workspace 2>&1 | tail -25
uv run core/tests/python/conformance.py 2>&1 | tail -6
```

Expected: all pass, conformance PASS. `to_canonical_cbor` is on the golden-vault path in both directions.

- [ ] **Step 6: Lint and format**

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
cargo fmt --all
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -8
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace 2>&1 | tail -8
```

Expected: all clean.

- [ ] **Step 7: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
git add core/src/unlock/bundle.rs
git commit -F - <<'MSG'
fix(core): wipe to_canonical_cbor's secret-key clones on drop (#542)

Audit C-4's write side, untracked until this slice filed #542. C-4 named the
encoded output buffer (closed by #513 Task 6) and the canonical re-encode
(closed by #357) but folded the intermediate `Value::Bytes` clones into
those, so they were never fixed.

`to_canonical_cbor` clones every long-term secret key into a
`Value::Bytes`, and `ciborium::Value` has no zeroizing Drop, so all four
were freed unwiped on every vault create and every unlock — the read path
pays it too, because the canonicality check re-encodes.

`ZeroizingEntries` wipes in Drop rather than after `encode_map`, so the
unwinding-panic and early-return paths are covered, not just the happy one.
`wipe` is a separate method so the behaviour is directly testable without
reading freed memory, which is not observable from safe Rust anyway.

Known boundary, recorded in the type's doc comment rather than glossed: the
`vec![…]` literal builds its clones before the wrapper owns them, so a
mid-literal unwind leaves them unwiped. The only unwind source there is
allocation failure, which aborts.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

---

### Task 5: #525 — `derive_device_kek` expected-bytes KAT

**Files:**
- Create: `core/tests/data/device_kek_kat.json`
- Modify: `core/tests/common/mod.rs` (add `DeviceKekKat` / `DeviceKekVector` structs beside `HkdfSha256Kat` at line 180)
- Modify: `core/tests/kdf.rs` (add the test; extend the `use` lines at 5 and 7-10)

**Interfaces:**
- Consumes: `common::load_kat` (`core/tests/common/mod.rs:88`), `de_hex` (same file), `secretary_core::crypto::kdf::derive_device_kek` (`core/src/crypto/kdf.rs:353`).
- Produces: nothing consumed by later tasks.

Read spec §5. The three existing tests never pin expected bytes — one compares two of its own outputs, one recomputes with the same `Hkdf::<Sha256>` primitive.

**The vectors below are already verified.** They were generated from Python `cryptography`'s HKDF (an independent implementation) and then checked against the Rust `derive_device_kek` by execution. Do not regenerate them from `derive_device_kek` — that would pin whatever the function currently does, including a bug.

- [ ] **Step 1: Create the fixture**

`core/tests/data/device_kek_kat.json`:

```json
{
  "comment": "crypto-design §5a: device_kek = HKDF-SHA-256(ikm=device_secret, salt=0x00*32, info=\"secretary-v1-device-kek\", L=32). Expected bytes generated from an INDEPENDENT implementation (Python `cryptography`), never from derive_device_kek itself. Regenerate with: uv run --with cryptography python -c 'from cryptography.hazmat.primitives import hashes; from cryptography.hazmat.primitives.kdf.hkdf import HKDF; print(HKDF(algorithm=hashes.SHA256(), length=32, salt=bytes(32), info=b\"secretary-v1-device-kek\").derive(bytes(32)).hex())'. Source test: core/tests/kdf.rs::device_kek_kats.",
  "vectors": [
    {
      "name": "all_zero_secret",
      "device_secret": "0000000000000000000000000000000000000000000000000000000000000000",
      "device_kek": "dfdeaca5104911dc481f0c2ee18075583092a3468f82ef4c8e2f87c7f2612d3b"
    },
    {
      "name": "all_ones_secret",
      "device_secret": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "device_kek": "bcecfc61615d11fe4c4b9e40f62238e8a8a9784f9882ac52136a54282bc333cb"
    },
    {
      "name": "ascending_counter_secret",
      "device_secret": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      "device_kek": "08c50948dff50e656479efb3502d5b71facd1a5cf3e3054df601c60bcc0701ff"
    }
  ]
}
```

- [ ] **Step 2: Add the typed KAT structs**

In `core/tests/common/mod.rs`, after the `HkdfSha256Vector` struct that ends at line 196:

```rust
#[derive(Debug, Deserialize)]
pub struct DeviceKekKat {
    pub vectors: Vec<DeviceKekVector>,
}

#[derive(Debug, Deserialize)]
pub struct DeviceKekVector {
    pub name: String,
    #[serde(deserialize_with = "de_hex")]
    pub device_secret: Vec<u8>,
    #[serde(deserialize_with = "de_hex")]
    pub device_kek: Vec<u8>,
}
```

- [ ] **Step 3: Write the test**

In `core/tests/kdf.rs`, extend line 5:

```rust
use common::{load_kat, Argon2idKat, DeviceKekKat, HkdfSha256Kat};
```

and extend the `secretary_core::crypto::kdf` import at lines 7-10 to include `derive_device_kek`:

```rust
use secretary_core::crypto::kdf::{
    derive_device_kek, derive_master_kek, derive_recovery_kek, hkdf_sha256_extract_and_expand,
    Argon2idParams, KdfError, TAG_RECOVERY_KEK,
};
```

Then add the test, next to the recovery-KEK tests:

```rust
#[test]
fn device_kek_kats() {
    // #525: the three unit tests in `crypto::kdf` never pin expected bytes —
    // one compares two of `derive_device_kek`'s own outputs, and the other
    // recomputes with the SAME `Hkdf::<Sha256>` primitive, so a defect in
    // that crate, or a salt/info change mirrored into both, passes. These
    // vectors come from an independent implementation (see the fixture's
    // `comment` field for the generating command).
    let kat: DeviceKekKat = load_kat("device_kek_kat.json");
    assert!(!kat.vectors.is_empty(), "no device_kek vectors");
    for v in &kat.vectors {
        assert_eq!(
            v.device_secret.len(),
            32,
            "{}: device_secret must be 32 bytes",
            v.name
        );
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&v.device_secret);
        let derived = derive_device_kek(&Sensitive::new(secret));
        assert_eq!(
            derived.expose()[..],
            v.device_kek[..],
            "device_kek mismatch for vector {}",
            v.name
        );
    }
}
```

- [ ] **Step 4: Run the test**

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
cargo test --release -p secretary-core --test kdf device_kek_kats 2>&1 | tail -12
```

Expected: PASS, 1 test.

To confirm the KAT is not vacuous, temporarily change one hex digit of the first `device_kek` value in the fixture, re-run, and confirm it FAILS with `device_kek mismatch for vector all_zero_secret` — then revert the digit.

- [ ] **Step 5: Full suite, lint, format**

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
cargo fmt --all
cargo test --release --workspace 2>&1 | tail -20
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -8
```

Expected: all pass and clean.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
git add core/tests/data/device_kek_kat.json core/tests/common/mod.rs core/tests/kdf.rs
git commit -F - <<'MSG'
test(core): expected-bytes KAT for derive_device_kek (#525)

`derive_device_kek` was the only KDF in the file with no expected-bytes
vector. Its three unit tests cannot catch the class a KAT exists for: one
compares two of its own outputs, and `device_kek_matches_independent_hkdf_
reference` recomputes with the SAME `Hkdf::<Sha256>` primitive, so a defect
in that crate — or a salt/info change mirrored into both sides — passes.

Three vectors (all-zero, all-ones, ascending counter), generated from Python
`cryptography`'s HKDF and cross-checked against the Rust implementation by
execution before being committed. Never generated from `derive_device_kek`
itself, which would pin whatever the function currently does including a bug.
The regenerating command is recorded in the fixture's `comment` field.

JSON fixture rather than an inline hex literal, per the repo rule that KATs
live in `core/tests/data/*.json`.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

---

### Task 6: #527 — `Candidate.value` becomes `SecretString`

**Files:**
- Modify: `desktop/src-tauri/src/record_title.rs` — imports (line 25), `Candidate` (line 103), `select_labels` (line 148), `labels_for_record` (line 206), the `cand` test helper (line 215).

**Interfaces:**
- Consumes: `secretary_core::crypto::secret::SecretString` (`secretary-core` is already a dependency of `desktop/src-tauri`, declared at `desktop/src-tauri/Cargo.toml:60` for exactly this type).
- Produces: `Candidate { rank: usize, name: String, value: SecretString }` — `pub(crate)`, consumed only within this module.

Read spec §6. The residue is priority-race losers and truncated-away tails, neither of which reaches the frontend.

- [ ] **Step 1: Change the test helper first, so the tests fail**

In `desktop/src-tauri/src/record_title.rs`, the helper at line 215:

```rust
    fn cand(rank: usize, name: &str, value: &str) -> Candidate {
        Candidate {
            rank,
            name: name.to_owned(),
            value: SecretString::new(value.to_owned()),
        }
    }
```

- [ ] **Step 2: Run to verify failure**

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
cargo test --release -p secretary-desktop --lib record_title 2>&1 | tail -15
```

Expected: FAIL to compile — mismatched types, `expected 'String', found 'SecretString'`.

- [ ] **Step 3: Add the import**

`desktop/src-tauri/src/record_title.rs:25` currently reads:

```rust
use secretary_ffi_bridge::Record;
```

Add above it:

```rust
use secretary_core::crypto::secret::SecretString;
```

- [ ] **Step 4: Change the struct**

```rust
pub(crate) struct Candidate {
    pub(crate) rank: usize,
    pub(crate) name: String,
    /// The field's decrypted plaintext, zeroize-on-drop.
    ///
    /// Not a bare `String`: the candidate list holds more than what ships.
    /// Priority-race losers never reach the frontend at all, and for a value
    /// longer than [`MAX_LABEL_CHARS`] only the truncated head does — so the
    /// tail is residue with no wire destination. `reveal.rs` beside this was
    /// hardened under #513's memory-hygiene pass and this code was not (#527).
    pub(crate) value: SecretString,
}
```

**`name` deliberately stays `String`:** a `Candidate` only exists if `allowlist_rank` returned `Some`, so `name` is necessarily one of the six compile-time literals in `TITLE_NAMES`, not runtime plaintext.

- [ ] **Step 5: Update the two read sites in `select_labels`**

Line 149:

```rust
    candidates.retain(|c| !c.value.expose().trim().is_empty());
```

Line 158:

```rust
    let title = truncate(first.value.expose().trim());
```

Line 163:

```rust
        .map(|c| format!("{}: {}", c.name, truncate(c.value.expose().trim())));
```

- [ ] **Step 6: Update the producer in `labels_for_record`**

Line 206 currently reads `candidates.push(Candidate { rank, name, value });`. Change to:

```rust
        // Wrapped at the point of production, so the value is
        // `ZeroizeOnDrop`-covered for its whole life in this vector — losers
        // and truncated tails included (#527). `SecretString::new` MOVES the
        // String, so this adds no copy.
        candidates.push(Candidate {
            rank,
            name,
            value: SecretString::new(value),
        });
```

**Do not reorder anything in the loop above this line.** The `allowlist_rank` / `is_text` gate precedes `expose_text` and its doc comment says "Do not reorder"; this change alters the type of what is pushed, never the order of the checks.

- [ ] **Step 7: Run the tests**

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
cargo test --release -p secretary-desktop --lib record_title 2>&1 | tail -15
cargo test --release --workspace 2>&1 | tail -20
```

Expected: all record_title tests pass, including the truncation and priority tests.

- [ ] **Step 8: Lint and format**

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
cargo fmt --all
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -8
```

Expected: clean.

- [ ] **Step 9: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
git add desktop/src-tauri/src/record_title.rs
git commit -F - <<'MSG'
fix(desktop): hold record-title candidates in SecretString (#527)

`labels_for_record` built a `Vec<Candidate>` whose `value: String` held each
allowlisted field's decrypted plaintext, and the vector dropped unwiped. It
holds more than what ships: priority-race losers never reach the frontend at
all, and for a value longer than MAX_LABEL_CHARS only the truncated head
does, so the tail has no wire destination.

`reveal.rs` beside this was hardened under #513's memory-hygiene pass; this
code shipped in #526 outside that discipline. The spec's stated reasoning
("no Sensitive wrapper — it is serde_json-bound one line later") is true of
the title and subtitle, and not true of losers and tails.

`SecretString::new` moves the String, so this adds no copy.

`name` deliberately stays a plain String: a Candidate only exists if
`allowlist_rank` returned Some, so it is necessarily one of the six
compile-time literals in TITLE_NAMES, never runtime plaintext.

The gate ordering in `labels_for_record` is untouched — this changes the type
of what is pushed, never the order of the checks that precede expose_text.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

---

### Task 7: #521 — the move-out guard and its CI wiring

**Files:**
- Create: `scripts/check-secret-slot-hygiene.sh`
- Create: `scripts/secret-slot-hygiene-allowlist.txt` (header comments only; no entries)
- Modify: `.github/workflows/test.yml` (new job after `rust-error-payload-hygiene`, which ends at line 297)
- Modify: `CLAUDE.md` (add the guard to the Commands block)

**Interfaces:**
- Consumes: `allowlisted <rule-id> <hit>` and `is_comment_line <text>` from `scripts/lib/hygiene-allowlist.sh`, plus `SELF_TEST_TMP` / `cleanup_self_test` from the same file. `allowlisted` reads `$ALLOWLIST` and `$REPO_ROOT` from the sourcing script's scope — both must be set and non-empty before it is called. Allowlist format is four TAB-separated fields: `<repo-relative path>\t<rule id>\t<exact trimmed source line>\t<justification>`.
- Produces: nothing consumed by later tasks.

Read spec §4. Two decisions differ from the existing guards and must survive review: it scans `#[cfg(test)]` code (no carve-out at all, because #496 proved a test carve-out is fail-OPEN), and it denies tree-wide rather than only inside a `build` closure (because `mem::forget` / `ManuallyDrop` defeat `ZeroizeOnDrop` on every wrapper, wherever written).

- [ ] **Step 1: Confirm the census is still empty**

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
grep -rn --include="*.rs" -E "\bmem::(swap|replace|take|forget)\b|\bManuallyDrop\b" \
  core/src ffi/secretary-ffi-bridge/src ffi/secretary-ffi-py/src \
  ffi/secretary-ffi-uniffi/src desktop/src-tauri/src cli/src
```

Expected: exactly one hit, `core/src/crypto/secret.rs:196`, which is the `///` doc comment warning about the family. If anything else appears, it is a live violation — stop and report it before writing the guard, because the allowlist is meant to ship empty.

- [ ] **Step 2: Write the guard**

Create `scripts/check-secret-slot-hygiene.sh`:

```bash
#!/usr/bin/env bash
#
# check-secret-slot-hygiene.sh — deny the move-out family around the secret
# wrappers in core/src/crypto/secret.rs (#521).
#
# WHY THIS EXISTS
# ---------------
# `Sensitive::build` / `try_build` hand their fill closure a `&mut T`. The
# doc comment on `build` names the residual hole honestly:
#
#   A closure that moves the secret out — e.g. via `std::mem::swap` or
#   `std::mem::replace` — defeats the wipe, because the wrapper would then
#   zeroize whatever was swapped in. […] every closure written here is a
#   review point.
#
# "Every closure written here is a review point" is convention. This repo's
# standard is CI enforcement — #467, #472, #474, #486, #500, #504 and #515
# were each spent converting exactly that sentence into a pinned sink. This
# script is that conversion for the one remaining unenforced capability on a
# security-critical type.
#
# The swap family is uniquely bad because it does not merely leak: it makes
# the wrapper's own wipe VACUOUS, so the code looks protected and is not.
# `mem::forget` / `ManuallyDrop` are a superset — they defeat `ZeroizeOnDrop`
# on EVERY wrapper in secret.rs, not just `Sensitive`.
#
# SCOPE: TREE-WIDE, NOT CLOSURE-SCOPED
# ------------------------------------
# The rules deny these identifiers anywhere in the scanned roots rather than
# only inside a `build`/`try_build` closure body. Closure-scoping would need
# brace matching in bash AND would miss the `mem::forget` / `ManuallyDrop`
# class, which is not confined to a closure. Tree-wide is simpler and
# strictly stronger, and it costs nothing: the census is empty.
#
# TEST CODE IS SCANNED
# --------------------
# There is deliberately NO `#[cfg(test)]` carve-out. #496 found the
# error-payload guard's permissive `#[cfg(...test...)]` matcher was used as a
# SKIP LIST, where an over-match is fail-OPEN — `#[cfg(not(test))]` or any
# `#[cfg_attr(test, ...)]` silenced a violation in one line. A test that
# genuinely needs one of these identifiers becomes a reviewed allowlist entry
# with a visible key, which is the outcome we want.
#
# USAGE
# -----
#   bash scripts/check-secret-slot-hygiene.sh              # guard the tree
#   bash scripts/check-secret-slot-hygiene.sh --self-test  # prove the matchers fire
#
# Exit 0 when no unallowlisted hit remains; exit non-zero (printing each
# offending line) otherwise.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/hygiene-allowlist.sh
source "$SCRIPT_DIR/lib/hygiene-allowlist.sh"

REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
readonly REPO_ROOT

ALLOWLIST="$REPO_ROOT/scripts/secret-slot-hygiene-allowlist.txt"

# RULE S1 — the move-out family. `\b` before `mem` so `xmem::take` does not
# match; `\b` after the verb so `mem::taken` does not either.
readonly S1_RE='\bmem::(swap|replace|take|forget)\b'

# RULE S2 — `ManuallyDrop` defeats `ZeroizeOnDrop` on every wrapper, not just
# `Sensitive`. `\b` after the name so `ManuallyDropGuard` does not match.
readonly S2_RE='\bManuallyDrop\b'

# Roots holding secret-bearing code, per #521. Repo-relative.
readonly SCAN_ROOTS=(
  core/src
  ffi/secretary-ffi-bridge/src
  ffi/secretary-ffi-py/src
  ffi/secretary-ffi-uniffi/src
  desktop/src-tauri/src
  cli/src
)

# Print offending hits for one rule under one root. Args: <root> <rule> <ERE>.
scan_rule() {
  local root="$1" rule="$2" re="$3" hit text
  while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    # `grep -rn` emits `<path>:<line>:<text>`; strip both leading fields.
    text="${hit#*:}"; text="${text#*:}"
    is_comment_line "$text" && continue
    allowlisted "$rule" "$hit" && continue
    echo "$hit"
  done < <(grep -rn --include='*.rs' -E "$re" "$root" 2>/dev/null || true)
}

scan_all() {
  local base="$1" root
  for root in "${SCAN_ROOTS[@]}"; do
    [[ -d "$base/$root" ]] || continue
    scan_rule "$base/$root" S1 "$S1_RE"
    scan_rule "$base/$root" S2 "$S2_RE"
  done
}

run_guard() {
  local hits
  hits="$(scan_all "$REPO_ROOT")"
  if [[ -n "$hits" ]]; then
    echo "check-secret-slot-hygiene: FORBIDDEN move-out construct(s) found:" >&2
    echo "$hits" >&2
    cat >&2 <<'EOF'

`mem::swap` / `mem::replace` / `mem::take` / `mem::forget` / `ManuallyDrop`
move a secret out of, or suppress the Drop on, a zeroize-on-drop wrapper —
so the wipe silently becomes a no-op while the code still LOOKS protected.

If a hit is a reviewed exception, add it to
scripts/secret-slot-hygiene-allowlist.txt as four TAB-separated fields:
  <repo-relative path>\t<S1|S2>\t<exact trimmed source line>\t<justification>
Adding an entry is a SECURITY DECISION. The allowlist ships empty.
EOF
    return 1
  fi
  echo "check-secret-slot-hygiene: OK (${#SCAN_ROOTS[@]} roots, 2 rules, no findings)"
}

# Two-sided self-test. A guard never observed failing is indistinguishable
# from a no-op; a guard that fires on everything is worse. Probes are written
# to `mktemp -d`, NEVER into the source tree — the payload guard writes its
# probes into the live tree and races parallel sessions, which is #516.
self_test() {
  SELF_TEST_TMP="$(mktemp -d)"
  trap cleanup_self_test EXIT
  local d="$SELF_TEST_TMP" fails=0
  mkdir -p "$d/core/src"

  write_case() { printf '%s\n' "$2" > "$d/core/src/$1.rs"; }

  # --- S1/S2 positives (must ALL be caught) ---
  write_case P1  '    std::mem::swap(slot, &mut plain);'
  write_case P2  '    mem::swap(slot, &mut plain);'
  write_case P3  '    let old = mem::replace(slot, [0u8; 32]);'
  write_case P4  '    let stolen = mem::take(slot);'
  write_case P5  '    mem::forget(secret);'
  write_case P6  '    std::mem::forget(secret);'
  write_case P7  '    let kept = ManuallyDrop::new(secret);'
  write_case P8  '    use std::mem::ManuallyDrop;'
  # The shape the guard exists for: a move-out INSIDE a build closure.
  write_case P9  '    let s = Sensitive::build([0u8; 32], |slot| { std::mem::swap(slot, &mut plain); });'
  # Test code is NOT carved out. This is the decision that differs from the
  # other guards in this repo (#496: a test carve-out is fail-OPEN).
  printf '%s\n%s\n%s\n%s\n' '#[cfg(test)]' 'mod tests {' '    fn t() { mem::swap(a, b); }' '}' \
    > "$d/core/src/P10.rs"
  # The two comment-hole shapes. Both are REAL CODE and must be caught; both
  # defeated an earlier `is_comment_line` (round 1, and #475).
  write_case P11 '    /* set up */ std::mem::swap(a, b);'
  printf '%s\n%s\n' '    /* two-line' '    */ std::mem::swap(a, b);' > "$d/core/src/P12.rs"

  # --- negatives (must ALL stay silent) ---
  # N1 is the REAL line at core/src/crypto/secret.rs:196 — the doc comment
  # that names the family in prose. If this ever fires, the guard would
  # demand an allowlist entry for its own rationale.
  write_case N1 '    /// `std::mem::swap` or `std::mem::replace` — defeats the wipe, because'
  write_case N2 '    // mem::forget(x) would defeat ZeroizeOnDrop here.'
  write_case N3 '    /* ManuallyDrop is not permitted in this module. */'
  write_case N4 '    let s = Sensitive::new(buf);'
  # Word-boundary controls: substring matches that must NOT fire.
  write_case N5 '    xmem::take(&mut v);'
  write_case N6 '    let guard = ManuallyDropGuard::new(x);'

  # --- allowlist control: exact-line matching, NOT substring ---
  # ONE file, TWO lines. Line 1 is the allowlist entry verbatim; line 2 is a
  # DIFFERENT line in the SAME file sharing the entry's distinctive substring.
  # They must be one file — with two files the paths differ and the entry
  # never applies to the second either way, making the control vacuous.
  local a_keep='    let taken = mem::take(&mut self.pending);'
  local a_catch='    let other = mem::take(&mut self.buffered);'
  printf '%s\n%s\n' "$a_keep" "$a_catch" > "$d/core/src/A.rs"

  ALLOWLIST="$d/allowlist.txt"
  {
    # The real, exact-line exemption for line 1.
    printf '%s\t%s\t%s\t%s\n' "core/src/A.rs" S1 "$(trim "$a_keep")" 'self-test fixture: legitimate exact-line exemption'
    # A deliberately SHORT needle of the kind a substring allowlist would use.
    # Under exact-line matching it can never equal a full source line, so it
    # exempts nothing. Under substring matching it would exempt line 2 too —
    # which is what makes this pair DETECT the regression, not merely describe it.
    printf '%s\t%s\t%s\t%s\n' "core/src/A.rs" S1 'mem::take' 'self-test fixture: short needle, MUST be inert'
  } > "$ALLOWLIST"

  # `allowlisted` relativizes hits against $REPO_ROOT, so point it at the
  # probe dir for the duration of the self-test.
  local saved_root="$REPO_ROOT"
  REPO_ROOT="$d"

  local hits p n
  hits="$(scan_all "$d")"

  REPO_ROOT="$saved_root"

  for p in P1 P2 P3 P4 P5 P6 P7 P8 P9 P10 P11 P12; do
    grep -q "/$p\.rs:" <<<"$hits" || { echo "SELF-TEST FAILED: no hit on positive control $p" >&2; fails=1; }
  done
  for n in N1 N2 N3 N4 N5 N6; do
    grep -q "/$n\.rs:" <<<"$hits" && { echo "SELF-TEST FAILED: fired on negative control $n" >&2; fails=1; }
  done
  # The allowlist pair, asserted BY LINE NUMBER — this is what fails if
  # exact-line matching ever regresses to substring.
  grep -q "/A\.rs:1:" <<<"$hits" &&
    { echo "SELF-TEST FAILED: allowlisted line A.rs:1 was reported" >&2; fails=1; }
  grep -q "/A\.rs:2:" <<<"$hits" ||
    { echo "SELF-TEST FAILED: A.rs:2 escaped via its file's allowlist entry (substring match?)" >&2; fails=1; }

  if [[ $fails -eq 0 ]]; then
    echo "check-secret-slot-hygiene --self-test: OK (12 positive, 6 negative, 2 allowlist controls)"
    return 0
  fi
  return 1
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
else
  run_guard
fi
```

**`trim` is used in the self-test's allowlist writer.** Confirm it is exported by the shared lib before relying on it:

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
grep -n "^trim()" scripts/lib/hygiene-allowlist.sh
```

If `trim` is not defined there, write the allowlist entry with the leading whitespace already stripped by hand instead of calling it.

- [ ] **Step 3: Create the empty allowlist**

`scripts/secret-slot-hygiene-allowlist.txt`:

```
# Allowlist for scripts/check-secret-slot-hygiene.sh (#521).
#
# FORMAT — four TAB-separated fields:
#   <repo-relative path>\t<rule id: S1|S2>\t<exact trimmed source line>\t<justification>
#
# Keyed on the EXACT TRIMMED SOURCE LINE, never a substring. A substring entry
# would exempt every future line in the same file containing the same needle,
# which was demonstrably exploitable against the iOS guard (#467, third review
# round). Re-indenting an exempted line keeps its entry valid; editing its
# content does not, so a bypass line cannot be quietly repurposed.
#
# ADDING AN ENTRY IS A SECURITY DECISION. These identifiers do not merely leak
# a secret — they make a zeroize-on-drop wrapper's wipe VACUOUS, so reviewed
# code keeps looking protected while it is not. Prefer restructuring the call
# site over adding a row here.
#
# THIS FILE SHIPS EMPTY, and that is the point: the census at the time the
# guard landed found exactly one hit tree-wide, and it was the doc comment in
# core/src/crypto/secret.rs warning about the family. Keeping this list short
# is what keeps its entries meaningful.
```

- [ ] **Step 4: Run the self-test, and prove it is not vacuous**

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
chmod +x scripts/check-secret-slot-hygiene.sh
bash scripts/check-secret-slot-hygiene.sh --self-test
```

Expected: `check-secret-slot-hygiene --self-test: OK (12 positive, 6 negative, 2 allowlist controls)`.

Now mutate the guard and confirm the self-test catches it — a self-test that has never been observed failing proves nothing:

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
cp scripts/check-secret-slot-hygiene.sh /tmp/guard.bak
# Mutation 1: break rule S2 entirely.
sed -i '' "s/readonly S2_RE='.*'/readonly S2_RE='THIS_MATCHES_NOTHING'/" scripts/check-secret-slot-hygiene.sh
bash scripts/check-secret-slot-hygiene.sh --self-test && echo "BAD: self-test passed with S2 disabled" || echo "GOOD: mutation caught"
cp /tmp/guard.bak scripts/check-secret-slot-hygiene.sh
# Mutation 2: reintroduce a #[cfg(test)] skip, the fail-open shape #496 found.
sed -i '' 's|is_comment_line "$text" \&\& continue|is_comment_line "$text" \&\& continue\n    [[ "$hit" == *"/P10.rs:"* ]] \&\& continue|' scripts/check-secret-slot-hygiene.sh
bash scripts/check-secret-slot-hygiene.sh --self-test && echo "BAD: self-test passed with test code skipped" || echo "GOOD: mutation caught"
cp /tmp/guard.bak scripts/check-secret-slot-hygiene.sh
rm /tmp/guard.bak
```

Expected: `GOOD: mutation caught` both times. If either prints `BAD`, the corresponding control is not actually load-bearing — fix the control before continuing.

- [ ] **Step 5: Run the guard for real**

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
bash scripts/check-secret-slot-hygiene.sh
```

Expected: `check-secret-slot-hygiene: OK (6 roots, 2 rules, no findings)`.

- [ ] **Step 6: Lint the shell**

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
shellcheck scripts/check-secret-slot-hygiene.sh
```

Expected: clean. `shellcheck` is at `/opt/homebrew/bin/shellcheck`. Add targeted `# shellcheck disable=` comments with a reason only where the existing guards already do so (e.g. `SC2329` for a function invoked only via `trap`).

- [ ] **Step 7: Wire it into CI**

In `.github/workflows/test.yml`, add a new job after `rust-error-payload-hygiene` (which ends at line 297 with `run: uv run scripts/check-test-support-placement.py`) and before `android-host:`. The repo's convention is one job per guard.

```yaml
  rust-secret-slot-hygiene:
    name: rust secret-slot hygiene
    # Denies the move-out family — mem::swap/replace/take/forget and
    # ManuallyDrop — anywhere in the secret-bearing roots (#521). These do not
    # merely leak: they make a zeroize-on-drop wrapper's wipe VACUOUS, so the
    # code still looks protected. `Sensitive::build`'s doc comment named this
    # as "every closure written here is a review point"; this is the tripwire
    # that turns that convention into enforcement.
    #
    # Pure grep over *.rs — no Rust toolchain, so it runs on ubuntu in
    # seconds, like the two log-hygiene jobs above.
    runs-on: ubuntu-latest
    timeout-minutes: 10   # runaway cap (vs the 6h default); real duration ~1s
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      # --self-test FIRST: a guard never observed failing is indistinguishable
      # from a no-op. Two-sided — the matchers must fire on known-positives AND
      # stay silent on known-negatives.
      #
      # The step names are QUOTED: an unquoted ` #` inside a YAML `name:` starts
      # a comment and silently truncates it — valid YAML, so actionlint stays
      # green. That trap cost a fixup in #470.
      - name: 'check-secret-slot-hygiene.sh --self-test'
        run: bash scripts/check-secret-slot-hygiene.sh --self-test
      - name: 'check-secret-slot-hygiene.sh'
        run: bash scripts/check-secret-slot-hygiene.sh
```

- [ ] **Step 8: Validate the workflow, including the quoted-name trap**

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
actionlint .github/workflows/test.yml
# actionlint-green does NOT mean the names survived. Read them back.
python3 -c "
import yaml,sys
d=yaml.safe_load(open('.github/workflows/test.yml'))
j=d['jobs']['rust-secret-slot-hygiene']
print('job name:', j['name'])
for s in j['steps']:
    if 'name' in s: print('  step:', s['name'])
"
```

Expected: `actionlint` clean, and both step names printed in full including the `--self-test` suffix. A truncated name means an unquoted `#` slipped in.

- [ ] **Step 9: Document it in CLAUDE.md**

Add to the Commands block in `CLAUDE.md`, after the `check-test-support-placement.py` entry:

```bash
# Assert no move-out construct defeats a zeroize-on-drop wrapper (#521).
# `mem::swap`/`replace`/`take`/`forget` and `ManuallyDrop` do not merely leak —
# they make the wrapper's own wipe VACUOUS, so the code still looks protected.
# Tree-wide over six roots, NOT scoped to a `build` closure (ManuallyDrop is
# not confined to one), and test code IS scanned: #496 proved a `#[cfg(test)]`
# carve-out is fail-OPEN. Ships with an EMPTY allowlist. Same --self-test-first
# discipline; probes go to `mktemp -d`, never the source tree (cf. #516).
bash scripts/check-secret-slot-hygiene.sh --self-test
bash scripts/check-secret-slot-hygiene.sh
```

- [ ] **Step 10: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
git add scripts/check-secret-slot-hygiene.sh scripts/secret-slot-hygiene-allowlist.txt .github/workflows/test.yml CLAUDE.md
git commit -F - <<'MSG'
ci: deny the move-out family around the secret wrappers (#521)

`Sensitive::build`'s doc comment names its own residual hole — a closure that
moves the secret out via mem::swap/replace defeats the wipe — and closes with
"every closure written here is a review point". That is convention. This
repo's standard is CI enforcement; #467, #472, #474, #486, #500, #504 and
#515 were each spent converting exactly that sentence into a pinned sink.

The family is uniquely bad because it does not merely leak: it makes the
wrapper's own wipe VACUOUS, so the code still looks protected. mem::forget
and ManuallyDrop are a superset, defeating ZeroizeOnDrop on every wrapper in
secret.rs rather than just Sensitive.

Bash rather than the Python the issue proposes: the rule is a five-identifier
denial over Rust source, and sourcing scripts/lib/hygiene-allowlist.sh is why
those matchers were hoisted there. is_comment_line's `//` / `/* */` handling
is already exactly right for Rust.

Two decisions differ from the sibling guards, both deliberate:

- TREE-WIDE, not scoped to a build closure. Closure-scoping needs brace
  matching in bash and would miss the ManuallyDrop class entirely.
- TEST CODE IS SCANNED, with no carve-out at all. #496 found the
  error-payload guard's permissive `#[cfg(...test...)]` matcher was used as a
  skip list, where an over-match is fail-OPEN.

Probes go to `mktemp -d`, never the source tree — the payload guard writes
its into the live tree and races parallel sessions, which is #516.

Self-test is two-sided: 12 positive controls (including a move-out inside a
build closure, a hit inside `#[cfg(test)]`, and both comment-hole shapes),
6 negatives (including the real secret.rs:196 doc comment and two
word-boundary decoys), and the exact-line-vs-substring allowlist pair. Both
mutations — disabling S2, and reintroducing a test-code skip — were verified
to make the self-test fail.

Ships with an EMPTY allowlist: the census found one hit tree-wide, and it was
the doc comment warning about the family.

NOTE FOR MERGE: this adds a new CI check. `main`'s protect_main ruleset
(id 15821032) lists 22 required checks by name, so `rust secret-slot hygiene`
must be added there before it is enforced on PRs.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

---

### Task 8: Documentation and the full gate run

**Files:**
- Modify: `docs/manual/contributors/memory-hygiene-audit-internal.md`
- Modify: `CLAUDE.md` (the "Memory hygiene: zeroize discipline" section)
- Modify: `README.md` and/or `ROADMAP.md` — **only if warranted**; check, do not assume.

**Interfaces:**
- Consumes: everything from Tasks 1-7.
- Produces: nothing.

- [ ] **Step 1: Extend the audit memo**

Add a section to `docs/manual/contributors/memory-hygiene-audit-internal.md` recording:

- That `take_fixed_bytes` had **three** residues and that the heap one is audit C-4's last live sub-item — the memo currently does not mention `take_fixed_bytes` at all (verify with `grep -n take_fixed_bytes docs/manual/contributors/memory-hygiene-audit-internal.md`, which returns nothing today).
- That C-4's write side (#542) was untracked until this slice and is now closed, with `ZeroizingEntries`' stated boundary.
- `SecretBytes::concat` and **why it is not `build`/`try_build`** — specifically that wrapping first does not close a realloc, which is the part a future reader is most likely to get wrong.
- That #521's guard now enforces the `&mut` caveat the memo's own wrapper-discipline section describes, and that the memo's "All three wrappers are sound. No changes recommended." should now note that `mem::forget` / `ManuallyDrop` defeat all three (the point #521 makes).

Cite only SHAs reachable from `origin/main`, or cite by PR number. This memo is a handoff document for a paid external review whose reader will run the commands it cites — see the #520 baton's §3 on the audit trail nearly dying at squash-merge.

- [ ] **Step 2: Update CLAUDE.md's zeroize section**

The section currently offers two shapes: `build`/`try_build` when a fallible call intervenes, and the trailing wipe when provably adjacent. Add `concat` as the shape for an incrementally-built secret, and state the realloc reasoning in one sentence so nobody "simplifies" it back to `try_build`.

- [ ] **Step 3: Decide on README.md and ROADMAP.md, by checking rather than assuming**

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
grep -n "memory hygiene\|zeroize\|#513\|Memory hygiene" README.md ROADMAP.md
```

This slice adds no user-visible feature, no phase completion, and no new sub-project state. If the grep shows a claim that this work falsifies (e.g. a "residuals closed" statement), fix it; otherwise change nothing and say so in the commit body. Do not add a changelog entry for its own sake — `README.md` style is brief and audience-aware.

- [ ] **Step 4: Run the complete gate set**

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
pwd && git branch --show-current
cargo fmt --all -- --check
cargo build --release --workspace
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
cargo clippy --release --workspace -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
uv run core/tests/python/conformance.py
uv run scripts/check-error-payload-hygiene.py --self-test && uv run scripts/check-error-payload-hygiene.py
uv run scripts/check-test-support-placement.py --self-test && uv run scripts/check-test-support-placement.py
bash scripts/check-secret-slot-hygiene.sh --self-test && bash scripts/check-secret-slot-hygiene.sh
bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh
bash ios/scripts/check-public-log-hygiene.sh --self-test && bash ios/scripts/check-public-log-hygiene.sh
bash android/scripts/check-log-hygiene.sh --self-test && bash android/scripts/check-log-hygiene.sh
(cd desktop && pnpm test && pnpm run svelte-check)
(cd android && ./gradlew :vault-access:test :kit:compileDebugKotlin)
actionlint .github/workflows/test.yml
```

Record the actual numbers (test counts, guard control counts) — the handoff cites them, and a number taken on report rather than observed is the failure mode this repo's reviews keep finding.

- [ ] **Step 5: Assert the untouched surfaces really are untouched**

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
git diff main... -- ffi/secretary-ffi-uniffi/src/secretary.udl   # must be EMPTY
git diff main... --stat -- core/tests/data/                      # must show ONLY device_kek_kat.json
git diff main... --stat                                          # review the whole shape
```

- [ ] **Step 6: Verify every commit carries the trailer, per commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
for c in $(git rev-list main..HEAD); do
  git log -1 --format='%H %s' "$c"
  git log -1 --format='%(trailers:key=Co-Authored-By)' "$c" | grep -q 'Claude Opus 5' \
    || echo "  ^^ MISSING TRAILER"
done
```

Per-commit, not a range query: on git 2.54 a range `%(trailers:…)` audit never returns empty, so it always looks clean.

- [ ] **Step 7: Commit the docs**

```bash
cd /Users/hherb/src/secretary/.worktrees/core-memory-hygiene-residuals
git add docs/manual/contributors/memory-hygiene-audit-internal.md CLAUDE.md
git commit -F - <<'MSG'
docs: record the residual closeout in the audit memo and CLAUDE.md

The memo did not mention `take_fixed_bytes` at all, so the three-residue
correction and audit C-4's last live sub-item are now written down where the
external reviewer will look. C-4's write side (#542) is recorded with
ZeroizingEntries' stated boundary rather than as a completeness claim.

CLAUDE.md's zeroize section gains `SecretBytes::concat` as the shape for an
incrementally-built secret, with the realloc reasoning stated in one sentence
so it does not get "simplified" back to try_build — wrapping first does not
close a reallocation, which is the part a future reader is most likely to get
wrong.

Every SHA cited is reachable from origin/main.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

---

## Self-review

**Spec coverage.** §2 → Task 2. §3.1 → Task 3. §3.2 → Task 4. §3.3 → no task (deferred as #543 by design; the plan does not split `bundle.rs`). §4 → Task 7. §5 → Task 5. §6 → Task 6. §7 → Task 1. §8 sequencing → task order matches. §9 gates → Task 8 Steps 4-6. §10 issues filed → done before the plan was written (#542, #543). §1.2's "not a defect" finding → Task 2 Step 5 explicitly leaves `okm` alone. No gaps.

**Placeholder scan.** Task 4 Step 1 contains a deliberate false start (an `unsafe`-requiring test) immediately replaced by the version to use, and a `sed -n` command telling the implementer to match the file's existing bundle-construction helper rather than trusting the sketch — that is a real instruction with a real command, not a TODO. Task 8 Step 3 is conditional but carries the exact grep that decides it. Task 7 Step 2 carries a `grep` to confirm `trim` exists before the self-test relies on it, with the fallback stated. No other conditionals.

**Type consistency.** `SecretBytes::concat(parts: &[&[u8]]) -> Self` — defined Task 2 Step 3, used Task 2 Step 5. `take_fixed_bytes_into<const N: usize>(v: Value, field: &'static str, out: &mut [u8; N]) -> Result<(), BundleError>` — defined Task 3 Step 4, used Task 3 Step 5, tested Task 3 Step 1 with the same argument order. `ZeroizingEntries(Vec<(Value, Value)>)` with `fn wipe(&mut self)` — defined Task 4 Step 3, used Task 4 Step 4, tested Task 4 Step 1 via `.0` and `.wipe()`. `Candidate.value: SecretString` — changed Task 6 Step 4, read via `.expose()` at Step 5, produced via `SecretString::new` at Step 6, and the test helper at Step 1 matches. Guard rule ids `S1`/`S2` are consistent across the script, the allowlist header, and the self-test's allowlist rows.
