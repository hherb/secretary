# B.6 v1 pre-v2 cleanup bundle — design

**Date:** 2026-05-16
**Status:** approved (user OK 2026-05-16)
**Branch:** `chore/b6-pre-v2-cleanup`
**Closes:** [#60](https://github.com/hherb/secretary/issues/60), [#61](https://github.com/hherb/secretary/issues/61), [#62](https://github.com/hherb/secretary/issues/62), [#63](https://github.com/hherb/secretary/issues/63)
**Predecessor:** [B.6 v1 read-only KAT design](./2026-05-15-ffi-b6-conformance-kat-design.md), shipped as [PR #58](https://github.com/hherb/secretary/pull/58) (merge commit `d1595c5`).
**Successor:** B.6 v2 lifecycle KAT (issue [#59](https://github.com/hherb/secretary/issues/59)) — out of scope here.

## 1. Goal

Land all four B.6 v1 review-feedback follow-ups (one structural refactor + three semantic adjustments) in a single feature branch with one commit per issue, so the file structure + assertion shape + test coverage + JNA hygiene are all v2-ready *before* lifecycle vectors start landing.

## 2. Non-goals

- No changes to `core/src/` or the bridge crate (`ffi/secretary-ffi-bridge/`).
- No new lifecycle ops (`save_block` / `share_block` / `trash_block` / `restore_block`). Those belong to B.6 v2.
- No regeneration of `golden_vault_001` or other golden fixtures.
- No protocol-format change. The `--ignored generate_conformance_kat` generator is touched only mechanically by #60 (file split).

## 3. Scope (one commit per issue, in this order)

### Commit 1 — #60: split `core/tests/conformance_kat.rs` (595 LOC → directory module)

**Why first.** Pure semantic-neutral refactor. Doing it before #61 (which adds vectors that exercise the existing dispatch) means #61's tests land in the post-split structure with no follow-up moves. Doing it before #62/#63 is order-independent (those touch Swift/Kotlin only) but the refactor is cohesive enough to be its own commit.

**Target structure** (mirrors the existing `core/tests/common/` pattern — `mod.rs` + sibling files):

```
core/tests/
  conformance_kat.rs                       — thin entry: declares `replay_conformance_kat` + `generate_conformance_kat`, plus `mod conformance_kat_helpers;`
  conformance_kat_helpers/
    mod.rs                                  — re-exports the public surface (`pub use` of items used by the two tests)
    types.rs                                — `Kat`, `Vector`, `Operation`, `Expected`, `OkPayload`, `ExpectedRecord`, `ExpectedField`, `BridgeOrSyntheticErr` (with `#[allow(dead_code)]` on doc-only fields preserved)
    fixtures.rs                             — `kat_path`, `fixtures_dir`, `resolve_source`, `resolve_vault_dir`, `resolve_password`, `resolve_mnemonic`
    errors.rs                               — `variant_name_vault`, `vault_error_detail`, `assert_err`, `read_block_err_variant`, `read_block_err_detail`
    dispatch.rs                             — `run_open_password`, `run_open_recovery`, `run_read_block`, `assert_open_ok`, `assert_read_block_ok` (the per-op machinery; the loop itself stays in `conformance_kat.rs`)
```

**Splitting rules:**
- No new types, no renamed types. The split is purely physical.
- Visibility minimised: items used only inside the helper module stay `pub(super)`; items used by the two `#[test]` fns in the top-level file become `pub` at the module boundary.
- Module-level doc comments preserved verbatim per file (the existing crate-level `//!` doc moves to the entry file).
- `#![forbid(unsafe_code)]` stays on the entry file (workspace-wide setting still applies).
- `#[allow(dead_code)]` annotations stay on the two existing sites (`Kat::comment`, `Vector::description`). The previously-removed annotation on `BridgeOrSyntheticErr::Synthetic.detail` (commit `d638f9c`) stays gone.

**Target file sizes:** all five files comfortably below the 500-LOC project guideline; rough estimates 80 / 30 / 80 / 60 / 200 / 200 LOC respectively (entry / mod.rs / types.rs / fixtures.rs / errors.rs / dispatch.rs).

**Acceptance:**
- `cargo test --release --workspace --no-fail-fast` PASS, count unchanged at 641 + 10 ignored.
- `cargo clippy --release --workspace --tests -- -D warnings` clean.
- `cargo fmt --all -- --check` OK.
- `wc -l core/tests/conformance_kat.rs core/tests/conformance_kat_helpers/*.rs` shows all files under 500 LOC.
- The single `replay_conformance_kat` test still emits the same dispatch behaviour for all 9 existing vectors (no observable change).

### Commit 2 — #61: broaden `read_block` wrong-length UUID coverage

**Why now.** The existing single vector (`read_block_wrong_length_uuid` with 2-byte input) gives weak evidence that the wrong-length-rejection path is symmetric. Adding zero-byte + oversize vectors closes that coverage gap before B.6 v2 adds more `read_block`-adjacent vectors.

**JSON additions to `core/tests/data/conformance_kat.json`** (two new entries, slotted alphabetically-by-name immediately before `read_block_wrong_length_uuid`):

```json
{
  "name": "read_block_oversize_uuid",
  "description": "read_block with a 17-byte block_uuid (one byte too many) → synthesized InvalidArgument at the replay layer; uniffi binding rejects with VaultError.InvalidArgument on Swift + Kotlin.",
  "operation": "read_block",
  "after": "open_password_happy",
  "inputs": {
    "block_uuid_bytes_hex": "112233445566778899aabbccddeeff0011"
  },
  "expected": {
    "kind": "err",
    "variant": "InvalidArgument"
  }
},
{
  "name": "read_block_zero_length_uuid",
  "description": "read_block with an empty block_uuid (0 bytes) → synthesized InvalidArgument at the replay layer; uniffi binding rejects with VaultError.InvalidArgument on Swift + Kotlin.",
  "operation": "read_block",
  "after": "open_password_happy",
  "inputs": {
    "block_uuid_bytes_hex": ""
  },
  "expected": {
    "kind": "err",
    "variant": "InvalidArgument"
  }
},
```

**Vector count after this commit:** 11 (was 9).

**Code changes:** none. Both the Rust `BridgeOrSyntheticErr::Synthetic` path and the Swift/Kotlin binding-layer wrong-length rejection already handle arbitrary `block_uuid_bytes_hex` lengths — the existing `bytes.len() != 16` check at `core/tests/conformance_kat.rs:315` (will be in `dispatch.rs` after #60) covers `0` and `17` identically.

**Edge-case verification I'll perform during implementation:**
- The Kotlin runner's `decodeHex` at `Conformance.kt:126` accepts the empty string (returns an empty `ByteArray`). Verify the JNA `readBlock(..., ByteArray(0))` call surfaces as `VaultException.InvalidArgument` and not as some upstream JNA panic.
- The Swift `decodeHex` at `conformance.swift:98` has a `while i + 1 < chars.count` loop — the empty string produces an empty `Data()`, which is the desired input.

**Acceptance:**
- `core/tests/data/conformance_kat.json` has exactly 11 vectors.
- `cargo test --release --workspace --no-fail-fast` PASS — the `replay_conformance_kat` test now exercises 11 vectors and still passes.
- Swift conformance runner: 11/11 PASS.
- Kotlin conformance runner: 11/11 PASS.
- The synthesized-`InvalidArgument` path fires for both new vectors on the Rust side; the uniffi-projected `InvalidArgument` variant fires for both new vectors on Swift and Kotlin.

### Commit 3 — #62: factor Swift+Kotlin `open_password` / `open_recovery` assertion blocks

**Why now.** Each runner currently has two near-duplicate switch arms (Swift: lines 200–264; Kotlin: lines 224–306). B.6 v2 will add 4 more op arms (`save_block`, `share_block`, `trash_block`, `restore_block`), each with its own assert + catch shape. Factoring the shared `handleOpenResult` shape now means v2 lands as ~4 short call-site arms instead of 4 near-duplicate 30-LOC blocks per language.

**Target factoring (Swift):**

```swift
// At top-level (file scope), alongside the other helpers:
func handleOpenOk(
    out: OpenVaultOutput,
    expected: [String: Any],
    name: String,
    kind: String,
    cache: inout [String: OpenVaultOutput],
    check: (Bool, String, String) -> Bool
) {
    if kind != "ok" { _ = check(false, name, "expected err, got ok"); return }
    if let display = expected["display_name"] as? String {
        _ = check(out.identity.displayName() == display, name, "display_name mismatch")
    }
    if let bc = expected["block_count"] as? Int {
        _ = check(Int(out.manifest.blockCount()) == bc, name, "block_count mismatch")
    }
    if let bu = expected["block_uuid_hex"] as? String {
        let summaries = out.manifest.blockSummaries()
        if !summaries.isEmpty {
            _ = check(encodeHex(Data(summaries[0].blockUuid)) == bu, name, "block_uuid mismatch")
        } else {
            _ = check(false, name, "manifest has no blocks but block_uuid pinned")
        }
    }
    cache[name] = out
}

func handleOpenError(
    e: VaultError,
    expected: [String: Any],
    name: String,
    kind: String,
    check: (Bool, String, String) -> Bool
) {
    if kind != "err" { _ = check(false, name, "expected ok, got err: \(e)"); return }
    let want = expected["variant"] as? String ?? ""
    _ = check(vaultErrorName(e) == want, name, "variant mismatch (got \(vaultErrorName(e)), expected \(want))")
    if let needle = expected["detail_contains"] as? String {
        let detail = vaultErrorDetail(e) ?? ""
        _ = check(detail.contains(needle), name, "detail '\(detail)' missing '\(needle)'")
    }
}

// Call site (~12 LOC instead of ~32):
case ("open_vault_with_password", nil):
    let vaultDir = resolveVaultDir(inputs, goldenVaultDir: goldenVaultDir)
    let password = resolvePassword(inputs, goldenVaultDir: goldenVaultDir)
    do {
        let out = try openVaultWithPassword(folderPath: vaultDir, password: password)
        handleOpenOk(out: out, expected: expected, name: name, kind: kind, cache: &cache, check: check)
    } catch let e as VaultError {
        handleOpenError(e: e, expected: expected, name: name, kind: kind, check: check)
    } catch {
        _ = check(false, name, "unexpected non-VaultError exception: \(error)")
    }
```

**Target factoring (Kotlin):** symmetric — `handleOpenOk(out, expected, name, kind, cache, check)` and `handleOpenError(e, expected, name, kind, check)` as `private fun`s above `main()`. Call sites shrink the same way.

**Cross-language symmetry rules:**
- Same function names (`handleOpenOk` / `handleOpenError`) — no case differences.
- Same parameter order: `out, expected, name, kind, cache, check` and `e, expected, name, kind, check`. The cache parameter is `inout` in Swift and a mutable `MutableMap` reference in Kotlin (Kotlin maps are reference types by default — no `inout` marker needed).
- Same assertion order inside each helper (display_name → block_count → block_uuid_hex). The PR #58 reporting-fix that gates the `PASS:` print on `failures.count == preFailureCount` (Swift line 345, Kotlin line 416) is preserved exactly.
- No `else` catch-all on the variant-name `when`/`switch` (the exhaustiveness tripwire from PR #58 stays).

**Acceptance:**
- Swift conformance runner: 11/11 PASS (after #61). Smoke runner: 37/37 unchanged.
- Kotlin conformance runner: 11/11 PASS. Smoke runner: 37/37 unchanged.
- The negative-test verification: temporarily flip one expected field in the KAT (e.g. `display_name` to a wrong value), confirm both runners emit `FAIL: <name>: display_name mismatch` and NO `PASS: <name>` for that vector. Revert immediately. (This is exercising the PR #58 gating fix.)

### Commit 4 — #63: Kotlin runner drains `OpenVaultOutput` cache before exit

**Why now (and why Kotlin-only).** Swift's ARC means the cached `OpenVaultOutput` values are dropped automatically when the dictionary goes out of scope at process exit. Kotlin/JNA needs an explicit `.destroy()` to release the Rust-side handle; the JVM `Cleaner` thread does it eventually but a future second-pass runner (B.6 v2 may re-open the same vault between vector groups) would pin the handles indefinitely.

**Change (Kotlin only):** insert before `exitProcess(0)` and before `exitProcess(1)` at `Conformance.kt:424` / `:428`:

```kotlin
cache.values.forEach { it.destroy() }
cache.clear()
```

For symmetry, this lives at the top of the summary block so both exit paths drain the cache. Implemented via a single `finally`-like sweep at the end of `main()` before the if/else.

**No change to the comment block at `Conformance.kt:181-185`** that documents the cache lifetime — the new explicit destroy replaces the "JVM GC will release them on exit" sentence, so the comment is updated to reflect the explicit drain.

**Acceptance:**
- `cache.values.forEach { it.destroy() }; cache.clear()` runs before both `exitProcess` calls.
- Kotlin conformance runner: 11/11 PASS, no JNA regression, no new warnings.
- Manual sanity: add a `System.err.println("draining cache: ${cache.size}")` debug line during development, confirm it prints `draining cache: 2`. Only the two source vectors that succeed produce cacheable `Ok`s: `open_password_happy` and `open_recovery_happy`. The other source vectors are error cases and the chained `read_block` vectors never cache. Remove the debug line before commit.

## 4. Testing strategy

Each commit runs the gauntlet locally (no subagent dispatch — these are small changes, the implementer self-test is sufficient). At the **end of the bundle**, the full 9-item gauntlet matches the one used at PR #58 close, with the conformance counts bumped to 11/11:

| Check | Expectation |
|---|---|
| `cargo test --release --workspace --no-fail-fast` | 641 passed + 10 ignored — unchanged from B.6 v1 close. `replay_conformance_kat` is a single `#[test]` fn that loops over the vectors; vector-count growth does not raise the cargo test count. The #60 split moves code but adds no new `#[test]` fns. Verify on first run after each commit. |
| `cargo clippy --release --workspace --tests -- -D warnings` | clean |
| `cargo fmt --all -- --check` | OK |
| `uv run core/tests/python/conformance.py` | PASS |
| `uv run core/tests/python/spec_test_name_freshness.py` | PASS (counts to be re-derived; the split + new vectors may shift the 96/0/2 numbers) |
| `bash ffi/secretary-ffi-uniffi/tests/swift/run.sh` | 37/37 PASS (smoke unchanged) |
| `bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh` | **11/11 PASS** (was 9/9) |
| `bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh` | 37/37 PASS (smoke unchanged) |
| `bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh` | **11/11 PASS** (was 9/9) |

Per-commit, the relevant subset runs:
- #60: cargo gauntlet + clippy + fmt only (Rust-only change).
- #61: cargo gauntlet + Swift conformance + Kotlin conformance (adds new vectors).
- #62: Swift conformance + Kotlin conformance + Swift smoke + Kotlin smoke + the negative-test exercise above.
- #63: Kotlin conformance + Kotlin smoke.

## 5. Risks

- **`spec_test_name_freshness.py` count drift.** The 96/0/2 baseline depends on which Rust test files exist + which docs reference them. The #60 file split *may* introduce new `mod`-level test functions if I misjudge the split — needs verification. Mitigation: run the freshness script after #60 and accept whatever the new baseline is, documenting it in the PR description.
- **PR #58 gating fix regression.** The "PASS: never appears after FAIL:" property in commits `4dd9aae` (Swift) and `fdfc302` (Kotlin) is load-bearing for the runner's correctness signal. The factoring in #62 must preserve `preFailureCount` exactly — no premature snapshot reset, no skipping of the gating check at the end of the loop. Mitigation: the negative-test exercise in #62's acceptance criteria explicitly checks this.
- **Cross-language symmetry drift.** Swift and Kotlin helpers diverging in parameter order / assertion order / behaviour would be a real regression risk for B.6 v2. Mitigation: explicit symmetry rules listed in §3 commit 3; both runners verified against the same KAT.
- **#60 boundary judgement: is the split too granular?** Five sub-files for what's logically one test harness might be over-decomposed. Alternative considered: split into just `types.rs` + everything else (`dispatch.rs`) — but `errors.rs` + `fixtures.rs` are clearly distinct concerns and re-grouping them complicates the mental model. The five-file split is what the issue body suggests and what mirrors `common/`. Accepting the risk.
- **No subagent dispatch this session.** The B.6 v1 plan used per-task subagent reviews. This bundle is small enough (4 commits, ~600 net LOC change, no semantic risk to core) that subagent dispatch is wasted overhead. Implementer-side TDD + gauntlet sweep covers it.

## 6. Out of scope (explicit deferral)

- Anything touching `core/src/`, `ffi/secretary-ffi-bridge/src/`, or the uniffi UDL.
- Any new lifecycle KAT vectors (`save_block`, `share_block`, `trash_block`, `restore_block`). → B.6 v2 / issue #59.
- Resolving issue #35 (mid-call wipe race in `save_block`). → its own focused session.
- Resolving issues #37, #38, #45. → blocked on Sub-project C starting.

## 7. Open questions

None. All settled in brainstorming:
- PR shape: one branch, one PR, four commits in the order above.
- File split shape: directory module mirroring `core/tests/common/`.
- #62 + #63 interaction: #62 first, #63 layers on top (both touch `Conformance.kt` but at non-overlapping locations — #62 in the switch arms, #63 at end of `main`).

## 8. Implementation order, summarised

1. `chore(b6): split conformance_kat.rs into directory module helpers (closes #60)`
2. `test(b6): broaden read_block wrong-length UUID coverage with empty + oversize vectors (closes #61)`
3. `refactor(b6): factor open_vault_with_password/recovery into handleOpenOk + handleOpenError helpers (closes #62)`
4. `fix(b6): drain OpenVaultOutput cache before Kotlin runner exit (closes #63)`

Each commit is self-contained and reverts cleanly. Final gauntlet runs once at end of #63.

PR title: `chore(b6): pre-v2 cleanup bundle (#60 #61 #62 #63)`.
