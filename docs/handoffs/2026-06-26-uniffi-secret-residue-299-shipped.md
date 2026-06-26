# NEXT_SESSION.md — #299 uniffi value-marshalling secret residue (investigate-upstream → document) ✅ SHIPPED (PR opening)

**Session date:** 2026-06-25 (rolled into 2026-06-26). Started from a clean baton — PR #305 (`cf708b28`, the #300 TSan concurrency follow-up) had merged to `main`; removed the merged worktree/branch (`ios-tsan-concurrency` / `test/ios-tsan-concurrency`). Observed the open #300 follow-up resolved itself: `ios-tsan.yml` ran **green** on both the PR (11m17s) and the merge-to-main (10m31s) — `iPhone 16` sim exists on `macos-latest`, runtime ~10–11 min vs the 60-min cap (comfortable margin). User picked **#299** (`security`). Executed via brainstorm → spec → (lightweight, docs-only) implement, in project-local worktree `.worktrees/uniffi-secret-residue`.

**Status:** ✅ **SHIPPED — branch `docs/uniffi-secret-residue-299`, PR opening.** Docs-only; **no production code change** (the residue is in generated code we don't author, and upstream declined to fix it). `Closes #299` rides in the PR body so #299 closes on merge.

## (1) What we shipped this session

**The task (#299).** PR #298 (#229) scrubs the iOS adapter-owned `Data` and the uniffi namespace wrappers `zeroize()` the Rust `Vec<u8>` param — but a user-entered password / recovery phrase still lingers in **uniffi's generated value-marshalling buffers**, which neither side can reach. The chosen appetite was **investigate upstream uniffi** → document findings, comment upstream if warranted.

**Investigation (grounded, not assumed):**
- Regenerated the **actual** `secretary.swift` (uniffi 0.31, via the `build-xcframework.sh` bindgen step) and read `uniffi_core` v0.31.0. Confirmed **two uncontrolled copies** of an inbound `bytes` secret: (1) the Swift `writer: [UInt8]` in `FfiConverterRustBuffer.lower`, freed without zeroize; (2) the Rust-allocated `RustBuffer`, freed via `uniffi_rustbuffer_free → RustBuffer::destroy → drop(Vec<u8>)` (plain drop, no scrub) **before** our namespace wrapper body runs, so `password.zeroize()` can't reach it.
- **Not closeable in-scope:** uniffi 0.31.2 (current head, 2026-06-16) exposes no zeroize/sensitive hook, no per-arg allocator (only the coarse global `#[global_allocator]`, which still misses copy #1), and `custom_type!` routes through the same un-scrubbed `FfiConverter`. Upstream [mozilla/uniffi-rs#2080](https://github.com/mozilla/uniffi-rs/issues/2080) is **closed wontfix** (maintainers: "uniffi makes many copies … zeroize seems pointless").
- **Android has the identical residue** (Kotlin `ByteArray` → `RustBuffer` → `Vec<u8>`), distinct from the #229 "no adapter copy" finding (different allocations).
- Threat framing: worst case = one secret copy in freed-not-yet-reused heap; not a logic bug; core `Sensitive<T>` discipline unaffected.

**Three deliverables:**
1. **Memo section** — "Accepted limitation: uniffi value-marshalling secret residue (#299)" added to [`docs/manual/contributors/ffi-secret-handling-internal.md`](docs/manual/contributors/ffi-secret-handling-internal.md)'s "What is *not* covered" (the **inbound** sibling of the existing outbound `expose_*`/`take_*` caveat), with the two-copy path, the in-scope-unfixable evidence, the Android note, threat framing, and the Arc-handle mitigation. Cross-linked from the memory-hygiene memo's Cross-FFI out-of-scope bullet. *(Home adjusted from the spec's "memory-hygiene memo" to the dedicated FFI-secret memo — better matches the existing doc architecture; memory-hygiene gets the pointer.)*
2. **Upstream comment on #2080** — posted a constructive secrets-manager-consumer data point + the opt-in `#[uniffi(zeroize)]` ask: <https://github.com/mozilla/uniffi-rs/issues/2080#issuecomment-4805641279>. No new issue (the question was already asked and declined).
3. **Close #299** — via `Closes #299` in the PR body (closes when the docs land on `main`, not before).

**Branch commits** (off `main` @ `cf708b28`):
| SHA | What |
|---|---|
| `3d091fdd` | **docs(spec)**: investigation/disposition design |
| `a2c3b574` | **docs(memo)**: #299 inbound marshalling residue section + cross-link |
| `181d1dfa` | **docs(freshness)**: allowlist the 5 uniffi FFI symbols cited in the memo |
| (+ handoff commit) | this baton + retargeted `NEXT_SESSION.md` symlink |

### Acceptance (verified this session)
```bash
cd /Users/hherb/src/secretary/.worktrees/uniffi-secret-residue
uv run core/tests/python/spec_test_name_freshness.py   # 3 unresolved = the pre-existing #290 set ONLY (my 5 allowlisted)
git diff --name-only main...HEAD | grep -v '^docs/' || echo "docs-only"   # docs-only (incl. the allowlist .txt under core/tests/python)
```
- Zero `core/` Rust / FFI-crate source / on-disk-format / `conformance.py` change → cargo / clippy / CodeQL / Swift+Kotlin-conformance gates unaffected.
- Freshness checker (NOT a CI gate) net-clean: my 5 new FFI-symbol citations allowlisted following the existing precedent; the only remaining 3 hits are the pre-existing #290 `threat-model.md` false-positives (untouched — that's a parallel session's issue).

## (2) What's next
**#299 done (PR open). Pick a fresh item.** Carried candidates:
- **#290** — allowlist the 3 D.4 freshness false-positives (`origin_binding`/`registrable_domain`/`exact_origin` in `threat-model.md`). **Still collision-risky:** `.worktrees/d4-browser-autofill` (`claude/intelligent-davinci-hriple`) is active. *Trivially* closeable now (the allowlist mechanism + precedent are right there — 3 entries), but coordinate with that worktree first.
- **#252** (Android) — `UniffiVaultSession` read-only path (`blockSummaries`/`vaultUuidHex`) lacks the wiped guard; mirrors the iOS #304 hardening for Kotlin.
- **#231** (iOS) — enable `-strict-concurrency=complete` on the SwiftPM targets (natural follow-on to the #300 TSan work).
- **#193** (Rust core) — `pipeline.rs` dedup `copy_clocks` + pipeline-level real-race stale test + split >500 lines (good Rust-learning task, no platform collision).

**Acceptance criteria template:** a failing test reproducing the gap on `main`, the typed-error/enforcement surface *proven* not assumed (security paths, [[feedback_verify_deferred_items]]), the platform's full test gate green, spec/`conformance.py` updated in lockstep if observable bytes/semantics change.

**Open follow-up issues (carried):** #290 / #284 / #280 / #277 / #273 / #272(STALE — see §3) / #269 / #255 / #252 / #247 / #246 / #234 / #232 / #231 / #224 / #218 / #193 / #192 / #190 / #189 / #186 / #183.

## (3) Open decisions and risks
- **#272 is stale and closeable.** `cargo fmt --all --check` passes on `main` (exit 0); the drift was fixed by `f498206c` (#288), which also added the fmt/clippy CI gate. Close #272 with that evidence next session (didn't close it this session to stay scoped to #299).
- **Memo home = FFI-secret memo, not the memory-hygiene memo** (documented spec deviation): the FFI-secret memo already houses the cross-FFI residue caveats (codec-boundary, foreign-runtime heap-copy) and has a "What is *not* covered" section; the memory-hygiene memo's Cross-FFI bullet now points to it. This matches the existing doc architecture better than the spec's original placement.
- **No new upstream issue filed** (per user decision): #2080 already covers it and was declined; we commented instead of refiling a likely-unwelcome duplicate.
- **Outbound secret-return residue** (`take_phrase`/`take_secret`, Rust→Swift) has the *mirror* gap but is out of #299's scope; noted in the memo for completeness (and the OUTBOUND root fix already shipped as #261).
- **README / ROADMAP unchanged (deliberate).** Documenting an accepted FFI-boundary limitation is no capability/milestone — matches the #210/#251/#229/#300 pure-hardening precedent (contrast #261, an actual UDL fix that *did* get a ROADMAP line).
- **Risk:** none to product behavior (no production code touched). The residue itself remains an accepted limitation until/unless upstream uniffi adds an opt-in scrub.
- **Process note (parallel-session hazard hit & recovered):** a `git stash`/`checkout main` dance to get a checker baseline accidentally `pop`ped a *pre-existing parallel-session stash* (`stash@{0}: On main: stale main-checkout spec drafts superseded by #182`), conflicting `docs/vault-format.md`. Recovered cleanly — restored the file to HEAD, the stash stays intact in the list for that session. **Lesson: never stash-dance on a shared worktree; use `git show <ref>:<path>` or a throwaway worktree for baselines.**

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# If PR merged: branch + worktree can be removed:
#   git worktree remove .worktrees/uniffi-secret-residue && git branch -D docs/uniffi-secret-residue-299
git worktree list && git status -s

# Re-verify this session's gate (from the worktree if the PR is still open):
cd .worktrees/uniffi-secret-residue
uv run core/tests/python/spec_test_name_freshness.py   # 3 unresolved = #290 set only
git diff --name-only main...HEAD | grep -v '^docs/' || echo "docs-only"
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; symlink retargeted in the same commit on the feature branch. New-path handoff → no add/add conflict. Branch cut from `origin/main` (`cf708b28`); `origin/main` had **not** advanced at handoff time (verified `origin/main` == merge-base == `cf708b28`), so no history-binding merge was needed.

## Closing inventory
- **State on close:** PR opening on `docs/uniffi-secret-residue-299` (spec `3d091fdd` + memo `a2c3b574` + allowlist `181d1dfa` + handoff). Worktree `.worktrees/uniffi-secret-residue`.
- **Acceptance:** docs-only; freshness checker net-clean (5 new citations allowlisted, only the pre-existing #290 trio remains). Zero `core/` Rust / FFI-crate source / `conformance.py` touched → all language gates unaffected. Upstream #2080 comment posted; #299 closes via the PR.
- **README.md / ROADMAP.md:** unchanged (rationale in §3).
- **CLAUDE.md:** unchanged.
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-06-26-uniffi-secret-residue-299-shipped.md`.
