# NEXT_SESSION.md — canonical-CBOR residue closeout (#561, #565–#569)

**Session date:** 2026-08-24/25, from `main` @ `467c7072`. Branch `feature/cbor-residue-closeout`; worktree `.worktrees/cbor-residue-closeout`.

Housekeeping → brainstorm → spec → 8-task plan → **subagent-driven execution, fresh implementer per task, independent review after each, whole-branch review at the end** → full gate run. **All 8 tasks complete. 21 commits. 6 fix rounds. Final review: READY TO MERGE.**

---

## (1) What we shipped

### Housekeeping (on `main`, before the slice)

**Five verified-done issues closed** after checking each against code, not against the previous baton's word: **#547**, **#548**, **#555**, **#557**, **#559**. The repo cites fixes as `(#N)` and never `Closes #N`, so they had outlived their fixes.

**#519 re-audited and corrected on the issue.** The previous baton called it "the largest unfixed exposure" and named its fix as "a custom UDL type with hand-authored `Lower`/`Lift`". Both halves needed correction, established by reading uniffi 0.32.0's vendored source:

- **`uniffi::custom_type!` cannot close it.** `uniffi_macros-0.32.0/src/custom.rs:236-247` generates `<Vec<u8> as Lower>::write(lower_expr, buf)` — a custom type must still materialise a real `Vec<u8>` first, so the transient copy survives verbatim. Only a hand-authored `unsafe impl Lower` avoids it, in a crate that sets `unsafe_code = "deny"`.
- **There are three copies per call, and any in-repo fix reaches only the first.** The second is the `RustBuffer`: `lower_into_rust_buffer` (`uniffi_core-0.32.0/src/ffi_converter_traits.rs:265`) hands it to the foreign side, which frees it through uniffi's own generated `rustbuffer_free`. **We never see that free — unclosable in-repo at any effort level.**

So the maximal in-repo fix closes **1 of 3** copies at a materially worse cost than the issue implied. That is the honest reason it has been deferred three times, not a scheduling accident. The misleading in-code comment (`wrappers/block.rs`, which blamed "there is no local to wrapper-type" — false; the bridge's `to_vec()` result *is* a local we own) is corrected in this branch.

### The slice — commits (21, `2613f5e2..91829b01`)

| # | SHA | What |
|---|---|---|
| 1-2 | `2613f5e2` `c61b25ce` | design spec, 8-task plan |
| 3-5 | `004bde73` `00f74cba` `ed718326` | **T1** `cbor::scratch` — owns ciborium's parser scratch buffer |
| 6-7 | `34ac4766` `135c7644` | **T2** six secret-bearing parse sites routed onto it |
| 8-9 | `45a391ae` `f9d3519f` | **T3** the three encoders return `SecretBytes` |
| 10-12 | `e6e4b5b1` `4b728bb6` `83a50999` | **T4** bundle encode borrows instead of copying |
| 13 | `1c68f9a4` | **T5** `set_once` wipes the duplicate it rejects |
| 14 | `110bc7ed` | **T6** `parse_manifest_map` rejects duplicate keys |
| 15-16 | `b48d3f01` `0c03b337` | **T7** proptest pins the RFC 8949 key order |
| 17-21 | `fb0d1397` `d8f141cd` `a5fb52e0` `91829b01` | **T8** docs; three review-fix waves |

### The measured result

| Mechanism | Before | After |
|---|---|---|
| Parser scratch buffer (4 KiB, holds every payload ≤ 4096 B) | unwiped, unreachable | owned + wiped on every exit |
| `record::encode` / `encode_plaintext` / `encode_manifest` output | `Vec<u8>`, wrapped by a **deletable** call | `SecretBytes` **by construction** |
| `re_encoded` on both strict decode paths | unwiped `Vec<u8>` | `SecretBytes`, no wrap call to delete |
| Bundle encode: four long-term secret keys | copied out of `Sensitive` on every encode | **borrowed — no copy exists** |
| `set_once` duplicate reject | dropped unwiped | wiped, `T: Zeroize` compiler-enforced |
| `parse_manifest_map` duplicate key | silent last-wins | rejected, data-free payload (#474) |

**No on-disk format change.** `core/tests/data/` diff EMPTY; `secretary.udl` diff EMPTY.

### The one genuinely risky change, and how it was proven

T4 turned `Value::Integer(created_at_ms.into())` into `CanonicalValue::Uint(created_at_ms)` in the bundle encoder. The final reviewer proved equivalence **two ways rather than trusting the green test**:

- **By source:** `ciborium-0.2.2/src/value/ser.rs:34-57` narrows `Value::Integer` through the `try_from` ladder; every arm reaches `Header::Positive(v)`, which is minimal-length by construction. Since `created_at_ms: u64`, the big-num arms are structurally unreachable — equivalence holds over the **whole u64 domain**, not just the fixture value.
- **By execution:** a throwaway crate against the same pinned `=0.2.2` compared both encodings over every CBOR head boundary, every power of two and its predecessor, plus 500,000 xorshift values — **0 mismatches**.

---

## (2) What's next — concrete acceptance criteria

**Nothing on this branch is unfinished.** CI has never run on it; check that first.

- **#573 — the highest-value follow-up, and sharper than it looks.** `manifest.rs`'s four **nested** map parsers (`parse_vector_clock_entry`, `parse_block_entry`, `parse_trash_entry`, `parse_kdf_params`) still silently last-win on a duplicate key; `block.rs`/`record.rs` check at every level. **What makes this sharper than the top-level gap #568 closed:** implementing #568 established by execution that `decode_manifest` has **no re-encode-and-compare canonicality check** (#572) — so the nested layer has no second backstop either. Acceptance: mirror `parse_manifest_map`'s shape in all four; the `ManifestError::DuplicateKey` variant already exists and is data-free.
- **#572** — add the missing canonicality re-check to `decode_manifest`, so it matches `record::decode` and `block::decode_plaintext`. Acceptance: a non-canonical manifest body is rejected; `golden_vault_001_pinned` stays green.
- **#571** — `unlock/mod.rs:211` is the last deletable `SecretBytes::new(<encoder>()?)` of the #558 class in `core`, holding cleartext CBOR of all four long-term secret keys. This slice deliberately left `bundle::to_canonical_cbor`'s `Vec<u8>` return alone (T5's tests depend on it). Acceptance: make it return `SecretBytes` like its three siblings, or record why not.
- **#570** — `ciborium`'s decode side grows payload buffers from capacity 0, so any field over 4 KiB reallocates repeatedly and frees unwiped prefixes. **Routine, not an edge case** — an attachment, a long note, a stored key file. No public hook; needs upstream or an accepted-and-documented decision. This slice documented it precisely (including the corrected count: 6 allocation events / 5 reallocations for a 100 kB `bstr`, final capacity 131072) but did not close it.
- **#519** — see §1. Re-shaped, not advanced. The honest next step is an upstream uniffi issue for a zeroize-aware lowering hook, which is the only thing that can reach copy 2.
- **#574** — `spec_test_name_freshness.py` exits 1 with 88 unresolved citations, all pre-existing in `memory-hygiene-audit-internal.md`. Not wired into CI. Filed rather than silently ignored.
- Carried unchanged: **#550** · **#556** · **#562** · **#563** · **#564** · **#543** · **#545** · **#501** · **#512** · **#514** · **#516** · **#517** · **#494** · **#495** · **#502** · **#506** · **#508**–**#510** · **#473/#476** · **#477** · **#459** · **#464** · **#492** · **#417** · **#447** · **#443/#444**.

---

## (3) Open decisions and risks

### The session's main lesson: a claim I wrote propagated three levels before anyone checked it

My design spec asserted that `decode_manifest` has a re-encode-and-compare canonicality check backstopping the duplicate-key gap. **It does not.** The claim travelled spec → plan → task brief unchecked, and was caught only when Task 6's implementer read the code. Verified independently twice more.

The consequence runs opposite to the intuition: it makes #568 **more** justified, not less — the hybrid signature is the only decoder-level defence, with no second check. Corrected in place with a strikethrough (`0c03b337`), and the missing check filed as **#572**.

This is the same defect class the slice's own reviews kept finding, committed by the person writing the rules. Recorded rather than quietly edited.

### Five mechanisms shipped correct but unobservable, and were caught

The complaint this slice exists to close (#557/#558 — *"the mechanism is right, nothing would notice if it were removed"*) recurred **five times in the slice's own new code**:

1. **T1's scratch wipe** — deleting the `zeroize()` left the suite green. Closed by a content-based test following the `secret_tree` precedent.
2. **T2 made two pre-existing assertions vacuous.** `manifest.rs:2510` and `record.rs:2314` assert `wipe_calls() > before` to prove an early-return path wipes its tree. Adding an *unconditional* scratch wipe before that early return meant the inequality passed on the scratch wipe alone. Proved by killing the `Drop` with `ManuallyDrop` — the test still passed. That was #547/#557's early-return coverage, silently unpinned.
3. **T4 deleted a wipe test correctly** (nothing left to wipe) but left the new *elimination* property pinned by nothing — reverting to the old `SecretEntries` body would have left everything green, `golden_vault_001_pinned` included.
4. **A test I wrote into the plan was vacuous.** T7's `byte_length_not_char_count_decides_order` never exercised `CanonicalMap::serialize`.
5. **T8's memo table claimed a code wrap that does not exist** — and the commit *refreshed that row's line number* without re-verifying the fact, so a stale row read as freshly confirmed. In the document named as the principal handoff for the paid external review.

**Every remaining mechanism is now pinned by a test that fails when the mechanism is removed**, verified by mutation at the final review. Zero `> before` assertions survive anywhere in the branch.

### What is proven, stated precisely

A wipe of freed heap is **not observable from safe Rust** — the counter tests pin that `Drop` *ran*, not that bytes are gone. `CborScratch`'s content-based test pins the **live** buffer, which is observable; that is a different and weaker claim than "the secret is unrecoverable", and the module doc says so. `from_secret_reader` is behaviour-identical to `from_reader` **by construction** (same buffer length, same `recurse: 256`), verified against vendored source rather than docs, and `CBOR_SCRATCH_LEN == 4096` is pinned by a `const _` assert — a compile error, not a green-test claim.

### Rulings made on the user's behalf

Fourteen, all in the (gitignored) execution ledger with their cost-if-wrong. The load-bearing ones:

- **P1** — the plan's Task 1 signature named `ciborium_io`, which is not a dependency and is not re-exported. Changed to `from_secret_reader(bytes: &[u8]) -> Result<Value, CborFault>`, classifying internally. Every call site got simpler and every secret-bearing parse is now *forced* through the #474 classification.
- **T2-A / T8-retry** — two agents died mid-task (one interrupt, one watchdog stall) leaving uncommitted work. Both times I kept the work and had a **fresh** implementer verify and re-derive it rather than discard. Both times that found real bugs the original had left.
- **T6-A** — my own false spec claim, above.
- **T67-B** — filed the nested-parser gap (#573) rather than widening a task already carrying a new error variant.

---

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After the PR merges (squash leaves the branch "not fully merged"):
#   git worktree remove .worktrees/cbor-residue-closeout
#   git branch -D feature/cbor-residue-closeout
git worktree list && git status -s

# Gates for this slice (run from the worktree while the PR is open):
#   cd /Users/hherb/src/secretary/.worktrees/cbor-residue-closeout
#   cargo fmt --all -- --check
#   cargo build --release --workspace          # separate from the test run ON PURPOSE
#   cargo test --release --workspace
#   cargo clippy --release --workspace --tests -- -D warnings
#   cargo clippy --release --workspace -- -D warnings
#   RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
#   uv run core/tests/python/conformance.py
#   uv run scripts/check-error-payload-hygiene.py --self-test && uv run scripts/check-error-payload-hygiene.py
#   uv run scripts/check-test-support-placement.py --self-test && uv run scripts/check-test-support-placement.py
#   bash scripts/check-secret-slot-hygiene.sh --self-test && bash scripts/check-secret-slot-hygiene.sh
#   bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh
#   bash ios/scripts/check-public-log-hygiene.sh --self-test && bash ios/scripts/check-public-log-hygiene.sh
#   bash android/scripts/check-log-hygiene.sh --self-test && bash android/scripts/check-log-hygiene.sh
#   git diff main... --stat -- core/tests/data/                       # must be EMPTY
#   git diff main... -- ffi/secretary-ffi-uniffi/src/secretary.udl    # must be EMPTY
```

**Verified at `91829b01`** (controller-run or reviewer-reproduced, not taken on report): `cargo test --release --workspace` **97 result blocks, 0 failures** · `cargo build --release --workspace` clean · clippy clean **with and without** `--tests` · rustdoc `-D warnings` clean · `cargo fmt --check` clean · `conformance.py` **PASS** · error-payload guard **OK** · placement guard **OK** · secret-slot guard **OK** · lean-binding **OK** · iOS log hygiene **OK** · Android log hygiene **OK** · `core/tests/data/` diff **EMPTY** · `.udl` diff **EMPTY** · all **21** commits carry the trailer (checked **per commit** — on git 2.54 a range `%(trailers:…)` audit never returns empty) · **zero** auto-close keywords.

**Not verified:** **CI has never run on this branch** — check it first. `desktop/` `pnpm test` was not re-run (no Svelte/TS file changed). The Swift/Kotlin conformance runners are manual-only and nothing crossing the FFI changed (`.udl` diff empty). `core/fuzz` (workspace-excluded, nightly) was not compiled. `spec_test_name_freshness.py` exits 1 for pre-existing reasons (#574) — it was checked to stay at exactly 88 with an **identical member set**, not merely the same count.

---

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; the symlink is retargeted in the same commit on the feature branch. Do **not** sync to `main` during the pause window. If resuming this branch for fixups: `git fetch origin && git merge origin/main` FIRST (branch version wins on this doc) before editing.

## Closing inventory

- **State on close:** PR-ready, all 8 tasks done, full gate set green, final whole-branch review returned **READY TO MERGE** with one Minor, fixed in one wave plus a scoped re-review.
- **Docs:** design spec + 8-task plan committed **with their corrections recorded in place**, not silently edited. `memory-hygiene-audit-internal.md` extended with a section for this slice and an explicit "what this does not claim"; four falsified passages corrected, plus three more the brief did not name. `CLAUDE.md` gained the "return the wrapper, don't ask callers to apply one" pattern **with its boundary** (right where output is always secret; wrong for `aead::encrypt`, whose plaintext genuinely is not — the RFC-vector KATs encrypt literals). `ROADMAP.md`'s memory-hygiene bullet records this slice. **`README.md` deliberately unchanged** — no user-visible feature, nothing falsified.
- **Filed this session:** **#571** · **#572** · **#573** · **#574**.
- **Closed this session:** #547, #548, #555, #557, #559 (verified against code first).
- **Next:** CI on the PR · **#573** (sharpened by #572) · #572 · #571 · #570 · #519 (re-shaped) · #574.
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-08-25-cbor-residue-closeout-shipped.md`.
