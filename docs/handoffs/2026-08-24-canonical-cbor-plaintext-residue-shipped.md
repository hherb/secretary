# NEXT_SESSION.md — canonical-CBOR plaintext residue (#547, #548)

**Session date:** 2026-08-23/24, from `main` @ `0116cd2e`. Branch `feature/cbor-plaintext-residue`; worktree `.worktrees/cbor-plaintext-residue`.

Housekeeping → brainstorm → spec → 9-task plan → **subagent-driven execution, fresh implementer per task, independent review after each, whole-branch review at the end** → full gate run. **All 9 tasks complete. 20 commits. 11 fix rounds.**

---

## (1) What we shipped

### Housekeeping (on `main`, before the slice)

- **Six verified-done issues closed** after checking each against code: **#521**, **#522**, **#525**, **#527**, **#542**, **#544**. The repo cites fixes as `(#N)` and never `Closes #N`, so they had outlived their fixes.
- **Both new CI jobs added to the `protect_main` ruleset** (id `15821032`), which now requires **24** checks: **`rust secret-slot hygiene`** and **`clean-room conformance`**. Both were green on `main` before being made required. This was the previous baton's first "what's next" item.

### The slice — commits (20, `3e5804f0..f266d991`)

| # | SHA | What |
|---|---|---|
| 1-2 | `3e5804f0` `c5ae059b` | design spec, 8-task plan |
| 3-5 | `c459afa0` `de02697f` `f2ead3b5` | **T1** clone-free `encode_canonical_map`, `canonical/` directory module, recursive `cbor_size_bound` |
| 6-7 | `588ea31e` `d664ad34` | **T2** borrowing `CanonicalValue`/`CanonicalMap` |
| 8-9 | `ab50d527` `6ac4cfed` | **T3** `SecretValueTree`/`SecretEntries` recursive zeroize-on-drop |
| 10-11 | `c4f1b38e` `b5208d9b` | **T4** record encode borrows its field plaintext (#547's named site) |
| 12-13 | `b58b816e` `4ab17b3b` | **T5** block encode embeds records inline, deleting the encode→reparse round-trip |
| 14-15 | `00473e13` `51980e34` | **T6** both decode paths wrap their parsed tree; `record::decode_value` |
| 16-17 | `c9e74993` `f7b11fd4` | **T7** #548 closed; four private mechanisms retired; two fall-through arms wiped |
| 18 | `f976f70b` | **T7b** manifest decode wrapped and borrow-converted |
| 19-20 | `a4d8bd8e` `f266d991` | **T8** docs/census/gates; final-review fix wave |

### The measured result

| Path | Unwiped plaintext buffers before | After |
|---|---|---|
| Block save (per record field) | **6** copies + the terminal AEAD input | **0** |
| Block open | **~2N+2** | **1** (`re_encoded`, the canonicality re-check's output — tracked, see §3) |
| Manifest save | — | **2** (`block_name` through `canonical_sort_entries`; out of scope by design) |

**No on-disk format change.** `core/tests/data/` diff is EMPTY; `secretary.udl` diff is EMPTY.

### The two mechanisms

- **Eliminate** what we make: `CanonicalValue`/`CanonicalMap` ([core/src/vault/canonical/value.rs](core/src/vault/canonical/value.rs)) borrow straight out of a `SecretString`/`SecretBytes`, and sort keys **allocation-free** via `(key.len(), key.as_bytes())`.
- **Wipe** what `ciborium`'s parser makes: `SecretValueTree` / `SecretEntries` / `wipe_leaked_value` ([core/src/cbor/secret_tree/](core/src/cbor/secret_tree/)) recursively zeroize `Bytes` and `Text` through `Array`, `Map` (**keys and values**) and `Tag`, on `Drop`.

---

## (2) What's next — concrete acceptance criteria

**Nothing on this branch is unfinished.** CI has never run on it; check that first.

- **#519 — still the largest unfixed exposure, and it did not move this session either.** `ffi-uniffi`'s four secret accessors have no Rust-side wipe **at all**, leaking a device secret, a full recovery mnemonic, and decrypted record fields into freed heap on **every call, unconditionally, no panic required**, on both mobile platforms. The previous baton said it "should jump the queue"; it was deprioritised twice now. Acceptance: a custom UDL type with hand-authored `Lower`/`Lift`, or upstream support. Note the cost the baton must not hide: touching `.udl` means regenerating Swift+Kotlin, re-running both conformance runners, **and** building `:kit`/`:app` (a uniffi return-shape change can pass conformance yet break the Gradle module).
- **#558 (filed this session)** — the two AEAD plaintext buffers this slice wrapped in `SecretBytes` are **unpinned**: reverting both leaves all 437 core lib tests green, because `wipe_calls()` instruments only the hand-written `Drop`s, not `SecretBytes`'s derive. Acceptance: either a type-level pin (make the AEAD entry points take `&SecretBytes`, so a plain `Vec<u8>` does not typecheck — a census found all six `aead::encrypt` sites already pass `.expose()`, so this may be nearly free) or a recorded decision.
- **#557 (filed this session)** — `block::decode_plaintext`'s `SecretValueTree` wrap is likewise unpinned; deleting it leaves the suite green. Same class as #558. One `wipe_calls()` test closes it.
- **#559 (filed this session)** — `CanonicalValue`/`CanonicalMap`'s crate boundary rests on a private `mod value;`, not on their own `pub` declarations. One-word loosening elsewhere in the same file would silently widen them. Acceptance: declare both `pub(crate)`.
- **#556 (filed this session)** — `record.rs` is now 2607 lines (1936 on `main`); sibling of #543 (`bundle.rs`, now 1646). Both grew this session, mostly retained differential oracles.
- **#550** — `conformance.py`'s `ed25519_verify` has `ml_dsa_65_verify`'s fail-OPEN shape, and five deps stay unbounded. **Sharper now:** this session established that `conformance.py` invokes no Rust at all, so it is a docs↔fixture gate, not a Rust-encoder gate. That makes its own correctness the whole of its value.
- Carried unchanged: **#547**/**#548** (closed in code, issues open per the `(#N)` convention) · **#545** · **#543** · **#501** · **#512** · **#514** · **#516** · **#517** · **#494** · **#495** · **#502** · **#506** · **#508**–**#510** · **#473/#476** · **#477** · **#459** · **#464** · **#492** · **#417** · **#447** · **#443/#444**.

---

## (3) Open decisions and risks

**Three false claims in the design spec I wrote, each caught by review, each recorded as a struck-through correction in the spec rather than silently edited.** This is the session's main lesson.

1. **"The sort buffer is not secret-bearing"** — false. `record.fields` keys are user-authored field names inside an encrypted record, which CLAUDE.md's own #474 section calls "a decrypted CBOR field name". Fixed by **elimination**, not wiping: `(len, bytes)` is exactly the RFC 8949 §4.2.1 order for `&str` keys, verified before ruling by 184,041 pairwise comparisons across every CBOR head-length class and multi-byte UTF-8 — **zero mismatches**.
2. **"`conformance.py` is byte-identity proof"** — false for any Rust-side change. It contains zero references to `secretary_core`, `cargo` or `subprocess`; it reads the static fixture with a pure-Python implementation and would pass identically had the encoder moved. The real gate is `golden_vault_001_pinned`, which **rebuilds every vault file** with today's encoder and byte-compares against the frozen fixture **without round-tripping** — the only anchor that can catch a compensating encoder/decoder pair.
3. **"`manifest.rs` carries no decrypted user content"** — false, and it is why `manifest.rs` was excluded from the whole slice. `manifest.rs:347` and `docs/vault-format.md:209` both declare `block_name` as user-visible plaintext within the encrypted manifest. Task 7b was added mid-slice to cover it.

**The single most repeated defect, across 11 fix rounds: a doc comment asserting what the code beside it does not support** — most often a PRE-EXISTING comment a change falsified and left standing. Two patterns worth carrying forward:
- **Sweeping where you edited misses where the claims live.** Two sweeps were called complete and both missed hits in other files.
- **Grepping for the words you would have written misses the words someone else wrote.** A public `BlockPlaintext` doc survived a sweep because it said "parsed back into" and the sweep looked for "round-trip".
- **A false count is worse than none.** One task shipped "the two conversion sites" when there were nine; ruling R11 stands — delete an enumeration rather than correct it a third time.

**A rustdoc gotcha, the mirror of the one CLAUDE.md documents.** CLAUDE.md warns that *widening* a `use` can red the `-D warnings` gate by making an explicit link redundant. This session found the opposite: **narrowing visibility** broke two public intra-doc links in `record.rs`. Both directions are live.

**What is proven, stated precisely.** A wipe of freed heap is **not observable from safe Rust**, and neither is a reallocation `ciborium`'s parser performed before we saw the value. `Drop` panic-safety was traced and is clean — a panic in a `Drop` during unwind aborts the process, which would turn a leak into a crash. The wipe cannot be defeated by `mem::take`/`.clear()`/`.drain()`: both tuple fields are module-private and neither type exposes a `&mut` or consuming accessor.

**One commit message had to be rewritten.** `bc5f2791` contained "also closes #555", a genuine GitHub auto-close match and a violation of the constraint every implementer was held to. Rewritten via `filter-branch`; trees verified byte-identical, 20/20 trailers intact, zero auto-close keywords remain. **The commit SHAs from Task 7 onward changed as a result** — `bc5f2791`→`c9e74993`, `93107984`→`f7b11fd4`, `b5ddae2f`→`f976f70b`, `9935019a`→`a4d8bd8e`.

**16 controller rulings** are recorded in the execution ledger (gitignored, `.superpowers/sdd/…/progress.md`). The load-bearing ones are summarised in the PR body.

---

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After the PR merges (squash leaves the branch "not fully merged"):
#   git worktree remove .worktrees/cbor-plaintext-residue
#   git branch -D feature/cbor-plaintext-residue
git worktree list && git status -s

# Gates for this slice (run from the worktree while the PR is open):
#   cd /Users/hherb/src/secretary/.worktrees/cbor-plaintext-residue
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
#   (cd desktop && pnpm test)
#   git diff main... --stat -- core/tests/data/                       # must be EMPTY
#   git diff main... -- ffi/secretary-ffi-uniffi/src/secretary.udl    # must be EMPTY
```

**Verified at `f266d991`** (controller-run or reviewer-reproduced, not taken on report): `cargo test --release --workspace` **1962 passed / 0 failed** · `cargo build --release --workspace` clean · clippy clean **with and without** `--tests` · rustdoc `-D warnings` clean · `cargo fmt --check` clean · `conformance.py` **PASS** · error-payload guard **OK** · placement guard **OK** · secret-slot guard **OK** · lean-binding **OK** · iOS log hygiene **OK** · Android log hygiene **OK** · desktop `pnpm test` **786 passed** · `core/tests/data/` diff **EMPTY** · `.udl` diff **EMPTY** · all **20** commits carry the trailer (checked **per commit** — on git 2.54 a range `%(trailers:…)` audit never returns empty) · **zero** auto-close keywords in any commit body.

**Not verified:** **CI has never run on this branch** — check it first. Android Gradle and `pnpm run svelte-check` were not re-run (no Kotlin or Svelte file changed). The Swift/Kotlin conformance runners are manual-only and nothing crossing the FFI changed (`.udl` diff empty). `core/fuzz` (workspace-excluded, nightly) was not compiled.

---

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; the symlink is retargeted in the same commit on the feature branch. Do **not** sync to `main` during the pause window. If resuming this branch for fixups: `git fetch origin && git merge origin/main` FIRST (branch version wins on this doc) before editing.

## Closing inventory

- **State on close:** PR-ready, all 9 tasks done, full gate set green, whole-branch review returned **ready**.
- **Docs:** design spec + 9-task plan committed with their corrections recorded in-place; `memory-hygiene-audit-internal.md` extended (six-copy trace, both mechanisms, an explicit "what this does NOT claim") and an inherited error corrected — the bundle's early-return path exposes **four** secret keys, not three, verified by recomputing RFC 8949 canonical key order for all eleven fields by hand; `CLAUDE.md`'s zeroize section gained the borrow-vs-wrap bullet. `README.md` / `ROADMAP.md` deliberately unchanged — no user-visible feature, no phase completion, nothing falsified.
- **Filed this session:** **#555** (closed by T7) · **#556** · **#557** · **#558** · **#559**.
- **Closed this session:** #521, #522, #525, #527, #542, #544 (verified against code first).
- **Next:** CI on the PR · **#519** (now twice-deferred and still the largest exposure) · #558/#557 (unpinned mechanisms) · #559 · #550 · #556/#543.
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-08-24-canonical-cbor-plaintext-residue-shipped.md`.
