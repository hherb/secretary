# NEXT_SESSION.md — #402 retention auto-purge **FFI projection** ✅ SHIPPED (PR opening)

**Session date:** 2026-07-09. Ships the **FFI projection of #402** — the core retention API (`auto_purge_expired`, `expired_trash_entries`, `DEFAULT_RETENTION_WINDOW_MS`, merged in #405) is now callable from Python + Swift + Kotlin. Branch `feature/retention-ffi-402` cut from `main` @ `6070e6ec` (#402 core via PR #405). Full design-first flow: brainstorm → spec → plan → subagent-driven execution (7 tasks, fresh implementer + task-reviewer per task, opus whole-branch review + 1 fix). Worked in isolated worktree `.worktrees/retention-ffi-402/`. **FFI-only slice — no core / crypto / on-disk-format change; no new `FfiVaultError` variant; `#![forbid(unsafe_code)]` intact.**

## (1) What we shipped this session

The #402 core slice deliberately deferred the FFI + platform surface. This slice closes the FFI half: the preview→commit pair + the 90-day default constant are projected through the single-source bridge onto both binding flavors, so any platform can now show "N items will be permanently deleted" and commit a retention purge.

**Design decisions (resolved in brainstorming):**
1. **Preview = free function** `expired_trash_entries(manifest, window_ms, now_ms)` — colocates all retention code in one bridge `retention/` module (mirrors core's `retention.rs`), matches the `purge_block`/`empty_trash`/`list_trashed_blocks` free-fn convention. Pure, infallible, empty vec on a wiped handle.
2. **Commit = `auto_purge_expired`** = byte-for-byte the sibling `empty_trash` bridge orchestration + two scalar args (`window_ms`, `now_ms`) + one pass-through report field (`window_ms`). Same snapshot → temp `OpenVault` → core call → write-back-on-Ok shape; **Err path leaves the bridge handle byte-identical** (temp clone owns the only mutation and drops).
3. **90-day const = one bridge-re-exported core const** → uniffi namespace fn `default_retention_window_ms()` (UDL 0.31 has no `const`) + pyo3 module attribute `DEFAULT_RETENTION_WINDOW_MS`. Both read the same const; no drift.
4. **No new error variant** — retention reuses `empty_trash`'s surface (`CorruptVault`/`FolderInvalid`/`SaveCryptoFailure`), so the Swift/Kotlin `ConformanceErrors.{swift,kt}` harnesses are untouched. `device_uuid` length validated at the **binding wrapper** (`uuid_from_vec` → `InvalidArgument`; `uuid_array_or_value_error` → `ValueError`), never the bridge.

**Mechanics:**
- Bridge `retention/{mod,orchestration}.rs`: `ExpiredEntry` + `RetentionPurgeReport` DTOs (6 counts narrowed `usize`→`u32`, `window_ms` passthrough; report intentionally **not** `Default` so a zero-count return still echoes the real window), the two free fns, and `map_core_vault_error_retention` (exhaustive `match`, **no `_` catchall** per #40; `BlockNotInTrash` unreachable → folds to `SaveCryptoFailure`).
- pyo3 `retention.rs` + `lib.rs`: `#[pyclass(frozen, get_all)]` DTOs (no `Clone`/`FromPyObject` — avoids the 0.28 auto-`FromPyObject` trap), two pyfunctions, module const.
- uniffi `wrappers/retention.rs` + `namespace/mod.rs` + `secretary.udl` + `lib.rs`: value-type DTOs, 3 namespace fns, 2 UDL dictionaries + 3 fn decls. **Arg order `window_ms` BEFORE `now_ms` verified end-to-end** through all 5 layers (a swap compiles — both `u64` — but is a silent wrong-window bug; this was the highest-value review check and is clean).

### Branch commits (off `main` @ `6070e6ec`, in order)
- `40373e8f` design · `563036d4` plan
- `63c7a57b` T1 bridge DTOs + `From` + 90d const re-export
- `eb8da2d9` T2 bridge `auto_purge_expired` + `expired_trash_entries` + exhaustive mapper
- `a464bbeb` T3 pyo3 projection + module const
- `7f3b6168` T4 pyo3 `test_retention.py` (4 passed)
- `caafed2f` T5 uniffi projection + UDL (Swift + Kotlin conformance green)
- `405074ce` T7 README + ROADMAP (FFI shipped; platform UX deferred)
- `8096c938` doc-consistency fix (drop stale "Core-only" from #402 entry now FFI shipped)
- `b5bbad80` final-review fix: non-empty retention preview+commit e2e (`ffi/secretary-ffi-bridge/tests/retention.rs`, mutation-verified)
- → then this docs/handoff commit.

### Acceptance (all verified green this session, from the worktree)
```bash
cargo test --release --workspace                                  # NO FAILURES
cargo clippy --release --workspace --tests -- -D warnings         # clean
cargo fmt --all -- --check                                        # clean
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace        # clean
bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh  # pass
uv run core/tests/python/conformance.py                           # exit 0
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh      # all assertions
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh     # 38/38 vectors
cd android && ./gradlew :kit:build :app:assembleDebug -x lintDebug # BUILD SUCCESSFUL (drift gate)
# pyo3: cd ffi/secretary-ffi-py && uv run --with maturin maturin develop --release && uv run --with pytest pytest tests/test_retention.py -v  # 4 passed
```

**Final opus whole-branch review: Ready to merge = With fixes (soft); 0 Critical / 0 Important / 1 Minor (fixed).** It independently verified all 8 security-relevant properties: arg order preserved end-to-end (highest-value check — clean); Err-path leaves the handle byte-identical; mapper exhaustive with no `_`; const is a single-source re-export (no redefined literal); validation at the binding wrapper not the bridge; UDL dictionaries match the wrapper structs field-for-field; no new `FfiVaultError` variant (conformance error harnesses untouched); no secret widened (preview projects only non-secret metadata). The single Minor (no non-empty e2e retention test) was fixed in `b5bbad80`.

**Notable — Android `:kit:lintDebug` fails on the PRE-EXISTING #387** (`StrongBoxUnavailableException [NewApi]` in `KeystoreDeviceSecretEnclave.kt`, last touched by #264, **not** in this branch's diff — this branch changed zero Android files). The drift gate that matters — `:kit:build` + `:app:assembleDebug` compiling the generated retention bindings — is **green**; only the orthogonal lint task fails, tracked as OPEN #387.

## (2) What's next

1. **Platform retention/purge UX (the natural next slice(s) — file each separately):** now that the FFI surface exists, wire desktop/iOS/Android "Run retention now" (preview→confirm→commit over `expired_trash_entries` / `auto_purge_expired`) and the still-deferred #399 "Empty Trash" / "Delete forever" over `empty_trash`/`purge_block`. **Acceptance per platform:** a preview dialog showing count + oldest age (from `ExpiredEntry.age_ms`) before committing; commit reports `purged_count`; desktop already has typed `AppError::BlockPurged` + user message but no purge command/button. Desktop = Tauri command in `generate_handler!` (classify in `writeCommands.ts` per [[project_secretary_desktop_generate_handler_writecommands_coverage]]); mobile = native over uniffi (`default_retention_window_ms()` gives the default window; a per-platform "retention window" setting is a UX decision).
2. **Scheduler policy (design-first, deferred):** all retention is caller-invoked — there is no open-time scheduler by design. If/when a platform wants automatic periodic purge, that's an ADR + threat-model note (when is it safe to auto-discard ciphertext), not a core change.
3. **Manual GUI smoke of the #374 consent flow** (human-only, carried): `pnpm tauri dev` against a **temp copy** ([[feedback_smoke_test_temp_copy_golden_vault]]) of a vault with staged crashed-share residue. Unlock → "Repair now?" → consent dialog → Cancel leaves untouched → Grant adopts widened set.
4. **Housekeeping:** **#387** (`:kit` NewApi lint — `StrongBoxUnavailableException` needs `@RequiresApi(28)` or a lint baseline; surfaced again this session), #290 (`spec_test_name_freshness.py` D.4 false-positives + 3 pre-existing `docs/threat-model.md` citations), #383 (drop RUSTSEC-2026-0194/0195 from `.cargo/audit.toml` only when `cargo tree -i quick-xml --target all` shows a single quick-xml ≥0.41).
5. **Carried mobile (on-device / human-only):** iOS Face ID spot-check; Android #338 on-device biometric cloud-open, #331 SAF custom-ROM, #334 native cloud-provider epic (ADR + threat-model first).

## (3) Open decisions and risks

- **Caller-supplied `window_ms` + caller-supplied `now_ms`** everywhere (no clock, no scheduler in core/bridge/bindings) — the platform owns the *when* and the *policy*. Divergent per-device windows are safe: purge is monotonic and merges via the existing #401 sweep. This is by design, unchanged from the #402 core slice.
- **Retention-timing wall-clock use (accepted, from #402 core):** `tombstoned_at_ms` gates *when* ciphertext is discarded, never a merge decision; `saturating_sub` blocks early purge on a fast clock; previewable via `expired_trash_entries`. Distinct from the #350-forbidden freshness-signal use. The FFI slice adds no new surface here.
- **No new `FfiVaultError` variant / no `manifest_version` bump / no crypto / KEM / signature-site / equal-clock change. `#![forbid(unsafe_code)]` intact.**
- **Deferred Minor on record (reviewer-noted, not a defect):** the uniffi namespace fns hand-map DTO fields inline (like the existing `empty_trash`/`purge_block` fns in the same file) rather than via a `From` impl — kept for consistency with the surrounding code.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After this PR merges, drop the branch + its worktree (squash-merge leaves it "not fully merged"):
#   git worktree remove .worktrees/retention-ffi-402 && git branch -D feature/retention-ffi-402
git worktree list && git status -s
# Re-run the retention FFI suite any time:
cargo test --release -p secretary-ffi-bridge retention \
  && cargo test --release --workspace --test retention \
  && cargo clippy --release --workspace --tests -- -D warnings \
  && bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh \
  && bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
# pyo3 pytest (rebuild first; nuke venv+uv cache if a stale .so hides new symbols):
cd ffi/secretary-ffi-py && uv run --with maturin maturin develop --release \
  && uv run --with pytest pytest tests/test_retention.py -v
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; the symlink retargeted in the same commit on the feature branch (new path → no add/add conflict; `main` updates cleanly on merge). Per the baton convention the handoff rides inside the PR — do **not** sync to `main` during the pause window.

## Closing inventory
- **State on close:** PR opening on `feature/retention-ffi-402` (worktree `.worktrees/retention-ffi-402`). 11 branch commits (design + plan + 5 task commits with per-task review + 2 doc + 1 final-review fix + this handoff). #402's FFI half closes on merge; the #402 issue itself was closed by the core PR #405 — this rides as a follow-up ("closes the FFI half of #402").
- **Acceptance:** full workspace green; clippy `-D warnings`, `cargo fmt -- --check`, rustdoc `-D warnings` clean; lean-binding pass; `conformance.py` exit 0; Swift (all assertions) + Kotlin (38/38) conformance; pyo3 pytest 4 passed; Android drift gate `:kit:build`+`:app:assembleDebug` SUCCESSFUL. Final opus review: 0 Critical / 0 Important; 1 Minor fixed.
- **Follow-up still open:** platform retention/purge UX (desktop/iOS/Android — file as slices); #387 lint (resurfaced).
- **README / ROADMAP:** updated (retention FFI projection shipped; platform UX deferred; "Core-only" qualifier dropped).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-07-09-retention-ffi-402-shipped.md`.
