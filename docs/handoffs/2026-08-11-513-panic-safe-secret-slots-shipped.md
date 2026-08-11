# NEXT_SESSION.md — panic- and error-safe secret slots

**Session date:** 2026-08-11, from `main` @ `9c18794`. Branch `feature/513-panic-safe-secret-slots`; worktree `.worktrees/513-panic-safe-secret-slots`.

Brainstorm → spec → 10-task plan → **subagent-driven execution with an independent review after every task and a scoped re-review after every fix round** → whole-branch review on the most capable model → one fix wave + a four-token second pass. **All 10 tasks complete. 26 commits.**

---

## (1) What we shipped

**#513 as filed asked for three `Zeroizing<[u8; 32]>` conversions.** The census found the issue understated itself in three separate ways, and the slice that resulted is materially different from the one requested.

### The three corrections that reshaped it

| #513 claimed | Measured |
|---|---|
| "the process is typically about to die" | **Both boundaries `catch_unwind`** — uniffi `rustcalls.rs:207`, pyo3 `trampoline.rs:301`. The process *survives* with residue on a frame later calls reuse. |
| "`panic = "abort"` would make it moot" | Appears in **no `.toml`** in the workspace. Unwinding is the real behaviour in dev and release. |
| scoped to unwinding panics (E1) | A slot is dirty between its last write and its wipe, so **`?` (E2) and `return Err` (E3) leak on ordinary paths too** — and two were live. |

### The two live leaks, filed as #518

- **`unlock/mnemonic.rs::parse`** held the user's complete 24-word recovery phrase in `normalized: String` and wiped it only on the happy path. Both error returns freed the heap buffer unwiped — including `UnknownWord`, which fires on **one mistyped word**, the most common way this function fails during a vault recovery.
- **`unlock/bundle.rs::from_canonical_cbor`** left already-decoded X25519/Ed25519 secret keys on the stack when its `.ok_or(MissingField)?` chain returned. `Option<[u8; N]>` is `Copy`, so the struct construction copied rather than moved.

A **thirteenth stack-residue gap** also surfaced, unrelated to any window: `mnemonic::generate` moved `entropy` into `Sensitive::new` inside the return literal and **never wiped the source slot at all**. Its sibling `parse()` does. The 2026-05-02 audit's twelve-gap table lists this function's `full` buffer but not this slot, and the function's own doc comment claimed a wipe covering only `entropy_buf`.

### The mechanism

**Wrap first, don't fill-then-wipe.** Two additive constructors on the existing `Sensitive<T>`:

```rust
pub fn build(init: T, f: impl FnOnce(&mut T)) -> Self;
pub fn try_build<E>(init: T, f: impl FnOnce(&mut T) -> Result<(), E>) -> Result<Self, E>;
```

The wrapper is constructed *before* the fill closure runs, so the value is `ZeroizeOnDrop`-covered for the whole fill and there is no trailing statement for control flow to skip. Everywhere else, `SecretBytes` / `SecretString` already fitted and simply were not being used.

**`#513`'s suggested `zeroize::Zeroizing` was rejected with evidence**: `zeroize 1.8.2` declares `#[derive(Debug, Default, Eq, PartialEq)] pub struct Zeroizing<Z>`, so it forwards `Debug` (a `{:?}` prints the secret) and supplies a variable-time `==` — regressing both properties this repo's own wrappers deliberately reject.

**`expose_mut` was also rejected**, and the reasoning is the load-bearing part: any API handing out `&mut T` on a secret wrapper permits `std::mem::swap(secret.expose_mut(), &mut plain)` in safe code, moving the secret out so `Drop` wipes zeros. A `Scratch<T>` newtype exposing `&mut T` has the identical hole. A constructor confines the borrow to one reviewable expression per call site. See spec §2.2.

### Commits (26, `bb7e057..1914ba6`)

| SHA | What |
|---|---|
| `bb7e057` `a27c084` `5644bb9` | design spec; the `&mut`-accessor rejection; the census corrections it forced |
| `db63773` `7e1dcb1` `ba08c9d` | 10-task plan, plus two controller repairs to it |
| `567a8dc` | **Task 1** — `build`/`try_build` + the unwind proof |
| `d1cccc5` `7ad67ff` | **Task 2** — the 101-site census, + reclassifying 4 accessors as WINDOW |
| `fa36ce5` | **Task 3** — `kdf.rs` ×3, `kem.rs::derive_wrap_key`'s `ikm` |
| `039136b` `e54d00c` | **Task 4** — #518's recovery-phrase leak + the 13th gap |
| `d7bb7c5` | **Task 5** — #518's identity-bundle leak |
| `916a624` | **Task 6** — the cleartext four-key CBOR buffer |
| `ead37e9` `ece3720` | **Task 7** — ffi-py's by-value `[u8; 32]` producer deleted (#503's ffi-py half) |
| `b1d94d8` `ef56f53` | **Task 8** — 37 ffi-py sites + precedence tests |
| `63f73db` | **Task 9** — the three uniffi sites #513 named, + 4 precedence tests |
| `b912bf8` `22f58b7` `869b737` | **Task 10** — the audit memo, CLAUDE.md, ROADMAP |
| `0ab3e02` | fmt sweep — Tasks 1 and 4 left the tree rustfmt-dirty |
| `9693cda` `7f7ad2b` `1914ba6` | whole-branch review closeout (see §3) |

### Net

49 windowed slots converted **plus one adjacent slot converted opportunistically** (design §3.3 pre-authorised it); 44 adjacent sites deliberately untouched; the **bridge crate needed no conversion at all**; two dead `zeroize` direct deps removed from the wrapper crates. **No on-disk format change, no FFI surface change, no `.udl` change, no KAT regeneration.**

---

## (2) What's next — concrete acceptance criteria

**Nothing on this branch is unfinished.** CI has never run on it; that is the first thing to check.

- **#519 — should jump the queue.** `ffi-uniffi`'s four secret accessors (`take_secret`, `take_phrase`, `expose_text`, `expose_bytes`) never wipe their Rust-side transient **at all** — an *absent* wipe, not a windowed one, so it is a different defect class from #513 with a different fix shape. Correctly out of scope here, verified twice: the project uses UDL scaffolding (`uniffi::include_scaffolding!` from `build.rs`), so lowering happens in generated code and there is **no local in `wrappers/*.rs` to wrapper-type**. **But it leaks a device secret, a full recovery mnemonic, and decrypted record fields into freed heap on every call, unconditionally, no panic required, on both mobile platforms** — a larger exposure than most E1 windows this slice closed. Acceptance: a custom UDL type with a hand-authored `Lower`/`Lift` that wipes after serialising, or upstream uniffi support, or an explicit reviewed decision recorded in the memo. The ffi-py twins were fixable and are fixed.
- **#518** — closed in code by `039136b` + `d7bb7c5`. Verify and close on the tracker.
- **#503** — its ffi-py half closed by `ead37e9`; the uniffi half was already done. Fully addressed.
- **#501** — ffi-py's pytest suite still never runs in CI. This slice ran it manually (134 passing, including 6 new precedence tests). Every run of it this session was by hand; a CI step is overdue.
- Carried unchanged: **#512** · **#511** · **#514** · **#494** · **#495** · **#505**-**#510** · **#502** · **#516** · **#517** · **#473/#476** · **#477** · **#459** · **#464** · **#492** · **#417** · **#447** · **#443/#444**.

---

## (3) Open decisions and risks

- **One commit body will auto-close an issue on merge.** `bb7e0574` contains lowercase *"closes #503's ffi-py half"*, and GitHub's auto-close keywords are **case-insensitive**, so a squash-merge will close #503 against this repo's explicit `(#N)`-never-`Closes #N` convention. #503 *is* genuinely fully addressed, so the outcome is not wrong — but **edit the squash message if you want to keep the convention intact**. History was left alone deliberately: rewriting 26 commits to fix one word would invalidate every SHA cited in this baton and in the audit memo.
- **The audit trail nearly died on merge, and that was the whole-branch review's most valuable catch.** `main` squash-merges, so the memo's WINDOW table citing 8 branch-local SHAs would have dangled, and the census file — the only record of the 44 ADJACENT judgements and their reasons — had been *deleted* on this branch, making the memo's own recovery commands return nothing on a squashed `main`. #519's body pointed at the same dead path. Fixed by restoring the census to the tree and relabelling the column by task. **If you delete a plans-directory artifact that a durable doc cites, check what squash-merge does to the citation.**
- **Documentation overclaiming was the defect class this branch could not stop producing** — eight instances, four of them mine. Three off-by-one source citations; a `#518` citation for a defect #518 does not cover; a `#501` citation for a bug with no issue number; "cannot recur" where the class was still expressible; "nothing left to wipe" where a move is a memcpy and the source slot retains bytes; and — twice — a "re-verified by execution" count invalidated by the very commit that wrote it. The memo is a handoff for a paid external review whose reader will run the commands it cites, so each was worth the round.
- **Three findings traced to my own briefs, not the implementers'.** I pre-judged four accessor sites as non-windows instead of letting the window test decide (the review proved `PyBytes::new` panics and they *are* windows); I specified a zero-seeded "destination untouched" assertion that could not distinguish untouched from wiped; and I put a `#501` citation into the plan that propagated into shipped source. The per-task review loop caught all three.
- **What is proven, stated precisely.** A wipe of freed heap or a dead stack frame is **not observable from safe Rust**, so there is no per-site assertion and this slice does not pretend otherwise. The per-site argument is *type-level*: a wrapper-typed local has no control-flow path that opts out of `Drop`. What **is** directly tested is the mechanism — `core/tests/secret_panic_safety.rs`, whose witnesses were isolated per-test in `7f7ad2b` after review found a shared `static AtomicBool` admitting both a false pass and a CI flake. Two independent agents broke `try_build` (fill-then-wrap) and confirmed exactly 2 of its 5 tests fail.
- **Deferred minor, carried deliberately:** `parse_rejects_a_short_phrase_with_wrong_length` duplicates the pre-existing `parse_rejects_wrong_word_count`. Its comment says so in plain language. Cheap future deletion.

---

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After the PR merges (squash leaves the branch "not fully merged"):
#   git worktree remove .worktrees/513-panic-safe-secret-slots && git branch -D feature/513-panic-safe-secret-slots
git worktree list && git status -s

# Gates for this slice (run from the worktree while the PR is open):
#   cd /Users/hherb/src/secretary/.worktrees/513-panic-safe-secret-slots
#   cargo fmt --all -- --check
#   cargo build --release --workspace
#   cargo test --release --workspace
#   cargo clippy --release --workspace --tests -- -D warnings
#   cargo clippy --release --workspace -- -D warnings
#   RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
#   uv run core/tests/python/conformance.py
#   uv run scripts/check-error-payload-hygiene.py --self-test && uv run scripts/check-error-payload-hygiene.py
#   uv run scripts/check-test-support-placement.py --self-test && uv run scripts/check-test-support-placement.py
#   bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh
#   bash ios/scripts/check-public-log-hygiene.sh --self-test && bash ios/scripts/check-public-log-hygiene.sh
#   bash android/scripts/check-log-hygiene.sh --self-test && bash android/scripts/check-log-hygiene.sh
#   (cd desktop && pnpm test && pnpm run svelte-check)
#   (cd android && ./gradlew :vault-access:test :kit:compileDebugKotlin)
#   # ffi-py's pytest suite — CI NEVER runs it (#501), so run it by hand:
#   (cd ffi/secretary-ffi-py && uv run --with maturin maturin develop --release && uv run --with pytest pytest tests/ -v)
#   git diff main... -- ffi/secretary-ffi-uniffi/src/secretary.udl    # must be EMPTY
#   git diff main... --stat -- core/tests/data/                       # must be EMPTY
```

**Verified at `1914ba6e`** (controller-run, not taken on report): `cargo test --release --workspace` **1864 passed / 0 failed** · `cargo build --release --workspace` clean · clippy clean **with and without** `--tests` · rustdoc `-D warnings` clean · `cargo fmt --check` clean · `conformance.py` **PASS** · payload guard **OK** (41/18/55/32/11/3) · placement guard **OK** (34/34 controls, 11 manifests) · lean-binding **OK** (3/3) · `.udl` diff **EMPTY** · `core/tests/data/` diff **EMPTY** · every SHA cited in the audit memo verified reachable from `origin/main` · all **26** commits carry the trailer (checked **per commit** — on git 2.54 a range `%(trailers:…)` audit never returns empty).

**Not verified:** **CI has never run on this branch** — check it first. Desktop `pnpm test` and the Android Gradle build were run during Tasks 9/10 but not re-run at `1914ba6e` (the three commits since are docs, one test file, and two `Cargo.toml` dependency removals). The Swift/Kotlin conformance runners are manual-only and nothing crossing the FFI changed (`.udl` diff empty). `core/fuzz` (workspace-excluded, nightly) was not compiled.

---

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; the symlink is retargeted in the same commit on the feature branch. Do **not** sync to `main` during the pause window. If resuming this branch for fixups: `git fetch origin && git merge origin/main` FIRST (branch version wins on this doc) before editing.

## Closing inventory

- **State on close:** PR-ready on `feature/513-panic-safe-secret-slots`, 26 commits, all 10 tasks done, whole-branch review clean after one fix wave and a four-token second pass. Net: `Sensitive::build`/`try_build`; 49 windowed slots converted plus one authorised adjacent one; both #518 leaks closed; the 13th stack-residue gap closed; #503's ffi-py half closed; 10 new precedence tests across both binding crates; the unwind proof isolated per-test; two dead deps removed; the audit memo rewritten with the full census restored to the tree.
- **Docs:** `memory-hygiene-audit-internal.md` substantially extended (census, E1/E2/E3, the twelve→thirteen correction shown rather than renumbered); `CLAUDE.md`'s zeroize section now leads with `build`/`try_build` and demotes the trailing wipe to the adjacent-site fallback; `ROADMAP.md`'s matching stale claim fixed; `README.md` verified to need none.
- **Filed this session:** **#518** · **#519**.
- **Next:** CI on the PR · **#519 (prioritise)** · #501 · #512 · #511 · #514 · #494 · #495 · #505-#510 · #502 · #516 · #517.
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-08-11-513-panic-safe-secret-slots-shipped.md`.
