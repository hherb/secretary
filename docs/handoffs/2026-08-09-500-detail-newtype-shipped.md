# NEXT_SESSION.md — the `Detail` newtype: typing the gated position

**Session dates:** 2026-08-09 (Tasks 1-5) → 2026-08-10 (Tasks 6-8, whole-branch review, ship). From `main` @ `3775ef5`. Branch `feature/500-detail-newtype`; worktree `.worktrees/500-detail-newtype`.

Brainstorm → spec → 8-task plan → **subagent-driven execution with an independent review after every task and a scoped re-review after every fix round** → whole-branch review on the most capable model → one fix wave. **All 8 tasks complete. Branch pushed, PR open.**

---

## (1) What we shipped

**37 commits, `ecd0ff1..b9f3f6b`.** No FFI surface change (`git diff main... -- ffi/secretary-ffi-uniffi/src/secretary.udl` is **empty**), no `core/` change, no on-disk format change, no KAT regeneration, no `#[error]` Display string altered.

### The idea

Three prior slices (#474 → #480 → #486/#496) built a text-matching guard around one invariant, and each shipped a longer LIMITS section than the last, because a guard that reads source text can always be evaded by source text it does not model. CLAUDE.md listed four E3 laundering shapes as needing "local dataflow / interprocedural analysis this construction-site guard does not do" — **two of them in daily use**.

That framing accepted a premise worth rejecting. `detail: format!("{secret}")` was expressible only because the field was declared `String` and Rust enum-variant fields are unconditionally public: the compiler was asked to enforce nothing. All 27 gated bridge fields are now a newtype with a private inner field, so a `String` produced by **any** laundering shape — modelled or not, present or future — does not typecheck.

### This session's commits (`b22a0a7..b9f3f6b`, 10)

| SHA | What |
|---|---|
| `4cdf28a` `92f7531` | **Task 6 (#504)** — ffi-py's two `&str` constructors take `&Detail`; `STR_PARAM_CTOR_EXCEPTIONS` empties; two review-found decoy holes closed |
| `90d7281` | **plan amendment** — Task 7 deletes `array32_from_vec` (human ruling, see §3) |
| `9cad5b3` `7d998b7` | **Task 7 (#503)** — `array32_from_vec_into` writes through the caller's slot at the three `device_secret` sites; by-value predecessor deleted |
| `f9a3feb` `0738ec9` `d49e736` | **Task 8** — 14 stale-doc sites, the honest limits list, the identity-harness baseline (2 fix rounds) |
| `180ae2d` `b9f3f6b` | **whole-branch review fix wave** — `BP57`'s second shadow term pinned; three censuses corrected; two citation nits |

Tasks 1-5 (`ecd0ff1..a905c1b`) are unchanged from the mid-plan baton: the `Detail` type and its `test-support` hatch, the guard learning `Detail`, 27 fields converted across three crates, the bridge narrowed to `Detail`-only, and #498's literal-hint rule.

### What is closed

- **#500** — the newtype, all 8 tasks.
- **#504** — both ffi-py constructors take `&Detail`; the exception set is empty, so a future `&str` constructor fails the guard until someone deliberately re-populates it.
- **#503** — no second un-zeroized `[u8; 32]` frame for a device secret.
- **#497** — closed as a side effect in Task 3; `allow_field_access` is now `False` on every root.
- **#498's cheaper half** — hint-position arguments must be string literals. Its structural half stays **open**.

Per this repo's `(#N)`-not-`Closes #N` convention, all of these remain OPEN on the tracker. They are closed **in code**.

### The whole-branch review earned its keep, again

Spec §10 required an **old-vs-new guard differential** because #496's only real regression was invisible to every per-task review. ~50 adversarial fixtures were pushed through the merge-base guard and the HEAD guard **in matched subprocesses**, and the findings diffed.

**No regression.** Every "old denied → new accepts" row reduces to the one intended narrowing. And a symmetry probe settled the question the differential existed to ask — did this branch *open* the aliasing hole #512 describes?

| fixture | merge-base `3775ef5` | HEAD |
|---|---|---|
| `use std::string::String as Detail;` | DENIED | ACCEPTED |
| `use secret::SecretHolder as String;` | **ACCEPTED** | DENIED |
| `type String = SecretHolder;` | **ACCEPTED** | DENIED |
| `type Detail = String;` | DENIED | DENIED |

The aliasing blind spot **moved spelling and shrank**. It was not opened here.

The reviewer also **mutated eleven production lines** on a throwaway copy and watched the right control fire each time — the branch's own repeated lesson being that four separate times the *control*, not the code, was the defect.

---

## (2) What's next — concrete acceptance criteria

**Nothing on this branch is unfinished.** The PR is open; CI has never run on it, so that is the first thing to check.

Filed this session, none blocking, in rough priority order:

- **#512** — a renaming import (`use std::string::String as Detail;`) defeats the newtype's E2 credit; both E2 and E3 pass it with **zero findings**, verified by execution. The guarantee is per **declaration**, not per root. Acceptance is in the issue: deny the alias in a gated position with a control that reds on a planted alias, **or** real name resolution (much larger — the guard has no name resolution anywhere today), **or** an explicit reviewed decision to accept it permanently, recorded in LIMITS. Whichever, `--self-test` must go red on a planted alias before the change is trusted.
- **#511** — control labels have no uniqueness check. **The `WP9` collision this session was caught by grep, not by any guard.** Must cover both `controls/*.py` and `selftest.py`'s inline checks — the collision was across exactly that boundary.
- **#513** — a panic unwinding through the bridge skips the device-secret `zeroize()` at `namespace/mod.rs:601`, `repair.rs:231`, `:361`. `Zeroizing<[u8; 32]>` closes it on every exit path and the crate is already a dependency. **Census the idiom repo-wide rather than patching three sites**, and re-read `docs/manual/contributors/memory-hygiene-audit-internal.md` first.
- **#514** — the placement guard's `rglob`-symlink and `target`-path-component discovery gaps. Nothing tracked them before (#510 is scoped to `payload_guard`). Discovery must either follow symlinks or **fail loudly**; silence is the defect.
- **#494** · **#495** · **#505**-**#510** · **#501** · **#502** — carried unchanged.
- **E3's remaining laundering shapes** on the **wrapper roots only** — pattern-destructuring binds, `if let`/`while let`/`for`, build-then-mutate, function parameter, dotless reassignment. Closed on the bridge by the compiler; open on the wrappers, where `String` must stay because uniffi's UDL projects one.

---

## (3) Open decisions and risks

- **The sentence this branch invites, and which is wrong, is "laundering is fixed."** The compiler guarantee covers the **bridge**. The two wrapper crates keep `String` and their posture is **unchanged** — E2/E3/E5 remain their only enforcement, at exactly the strength they had before. Spec §4 exists for this sentence; four documents now state it. Do not flatten it.
- **A plan defect was ruled by the human mid-session.** Task 7's text claimed the by-value `array32_from_vec` "stays for the non-secret fingerprint callers". A pre-dispatch census proved it false — all three of its call sites were the `device_secret` sites Task 7 moves, and the fingerprint callers use `array32_from_vec_at`, a different function. Left as written it would have stranded a zero-caller function and failed the plan's own `clippy -D warnings` constraint. **Ruling: delete it** (`90d7281`). The alternatives — `#[allow(dead_code)]`, or moving only some sites — were rejected; the latter leaves #503 live on 2 of 3 secret paths.
- **A census quoted verbatim in three files has three chances to drift, and nothing mechanical keeps them in step.** The fix wave found an *unlisted third* stale copy of the E5 census at `rules/e5.py`. The two OPEN ISSUES registers (CLAUDE.md and the LIMITS docstring) are currently set-identical and were verified so; **if they drift once, collapse them to one site.**
- **`BP57` now runs `run_real_scan` four times and writes two probe files per `--self-test`** (~9 s wall). Cleanup is nested-`finally` guaranteed and was verified under a deliberately failing run; both probes are gitignored and **neither is `mod`-reachable**, so residue can only red the guard — the fail-closed direction.
- **Wrapper `detail.rs` constructor signatures are review-gated, not CI-gated.** Unchanged from the prior baton, and the bridge behaves identically (E4 pins `impl GatedDetail`, not fn signatures). Worth knowing before adding a constructor.
- **One instruction of mine was correctly refused.** I asked the fixer to write line-number citations; it wrote section names instead, because line numbers in that file shifted twice during this branch and embedding more would recreate the exact drift class it was fixing. Accepted.
- **README/ROADMAP need no change, on precedent rather than a bare grep.** README's "Testing and hardening" section covers only fuzzing and has never enumerated the CI guards, and **no** prior slice in this track (#467, #472, #474, #479, #480, #486, #489, #496) added an entry to either file. This slice adds no user-facing feature and no FFI surface.

---

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After the PR merges (squash leaves the branch "not fully merged"):
#   git worktree remove .worktrees/500-detail-newtype && git branch -D feature/500-detail-newtype
git worktree list && git status -s

# Gates for this slice (run from the worktree while the PR is open):
#   cd /Users/hherb/src/secretary/.worktrees/500-detail-newtype
#   uv run scripts/check-error-payload-hygiene.py --self-test && uv run scripts/check-error-payload-hygiene.py
#   uv run scripts/check-test-support-placement.py --self-test && uv run scripts/check-test-support-placement.py
#   cargo build --release --workspace        # load-bearing: the ONLY gate that catches
#                                            # a production Detail::for_test call
#   cargo test --release --workspace
#   cargo clippy --release --workspace --tests -- -D warnings
#   cargo clippy --release --workspace -- -D warnings          # without --tests too
#   RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
#   uv run core/tests/python/conformance.py
#   bash ios/scripts/check-public-log-hygiene.sh --self-test && bash ios/scripts/check-public-log-hygiene.sh
#   bash android/scripts/check-log-hygiene.sh --self-test && bash android/scripts/check-log-hygiene.sh
#   bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh
#   (cd desktop && pnpm test && pnpm run svelte-check)
#   (cd android && ./gradlew :vault-access:test :kit:compileDebugKotlin)
#   git diff main... -- ffi/secretary-ffi-uniffi/src/secretary.udl    # must be EMPTY
```

**Never use `git rebase --exec` to prove every commit scans green** — it rewrites every SHA on the branch and invalidates the SHAs recorded here. Use a detached throwaway worktree and check out each commit of `git rev-list --reverse main..HEAD`, running the guard from inside that commit's own tree. That is how 35/35 was verified.

**Verified at `b9f3f6b`** (controller-run, not taken on report): guard self-test **41/18/54/32/10/3** · real scan **OK** · placement guard **22/22 + OK (11 manifests)** · `cargo test --release --workspace` **1849 passed / 0 failed** · `cargo build --release --workspace` clean · clippy clean **with and without** `--tests` · rustdoc `-D warnings` clean · `cargo fmt --check` clean · conformance.py PASS · iOS/Android/lean-binding guards green · desktop 674 tests + svelte-check 0 errors · Gradle `:kit` BUILD SUCCESSFUL · `.udl` diff **EMPTY** · `core/` diff **EMPTY** · bridge gated-`String` grep **0** · all 37 commits carry the trailer (checked **per commit** — on git 2.54 a range `%(trailers:…)` audit never returns empty) · every commit scans green (35/35 at fix-wave time).

**Not verified:** **CI has never run on this branch** — check it first. The Swift/Kotlin conformance runners are manual-only and nothing crossing the FFI changed (`.udl` diff empty). `:app:assembleDebug` and the `core/fuzz` compile (workspace-excluded, nightly) were not run.

---

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; the symlink already points at it and needed no retargeting this session (same task, continued). Do **not** sync to `main` during the pause window. If resuming this branch for fixups: `git fetch origin && git merge origin/main` FIRST (branch version wins on this doc) before editing.

## Closing inventory

- **State on close:** PR open on `feature/500-detail-newtype`, 37 commits, all 8 tasks done, whole-branch review clean after one fix wave. Net: `Detail` newtype over all 27 gated bridge fields with a private inner field; ten sanctioned constructors returning it; `test-support` hatch absent from every shipped build and CI-enforced; `check-test-support-placement.py` (22 controls); the payload guard's bridge root narrowed to `Detail`-only with alias-shadow, decoy-declaration and `trait GatedDetail`-decoy denies; `run_real_scan`'s shadow wiring pinned on **both** terms; `STR_PARAM_CTOR_EXCEPTIONS` empty; `array32_from_vec` deleted in favour of a write-through sibling. **No on-disk format change, no FFI surface change, no `.udl` change.**
- **Docs:** CLAUDE.md, the guard's LIMITS docstring, the allowlist preamble and `rules/e3.py`'s docstring all rewritten to state the bridge/wrapper boundary as a boundary, with a two-site OPEN ISSUES register.
- **Filed this session:** **#511** · **#512** · **#513** · **#514**.
- **Next:** CI on the PR · #512 · #511 · #513 · #514 · #494 · #495 · #505-#510 · #501 · #502.
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-08-09-500-detail-newtype-shipped.md`.
