# Issue #35 — Mid-call wipe race in `save_block`: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a deterministic integration test that exercises the documented post-`core::save_block` / pre-`replace_manifest_and_file` concurrent-wipe race in [ffi/secretary-ffi-bridge/src/save/orchestration.rs:114-125](../../ffi/secretary-ffi-bridge/src/save/orchestration.rs#L114-L125), proving (a) the typed `CorruptVault` surface with the documented detail and (b) the partial-success-mid-race contract (on-disk state is updated and remains decodable).

**Architecture:** Add a `mid_call_hook: Mutex<Option<Box<dyn Fn() + Send>>>` field on `OpenVaultManifest` (always present — `--cfg test` is not propagated to dependencies, so `#[cfg(test)]` would hide the installer from integration tests in `tests/*.rs`). The orchestrator unconditionally calls `manifest.run_mid_call_hook()` between `core::save_block` and `replace_manifest_and_file` — a one-`Mutex`-lock no-op in production (hook is `None` unless `install_mid_call_hook` is called, which production code never does). `install_mid_call_hook` is `#[doc(hidden)] pub` so integration tests can reach it but it stays hidden from rustdoc and does not auto-cross the PyO3 / uniffi FFI boundary. A test-only `MidCallRace` helper (two `sync_channel(0)` rendezvous handshakes) hides the worker→main / main→worker signalling so the test reads as plain English.

**Tech Stack:** Rust 2024, `std::sync::Mutex`, `std::sync::mpsc::sync_channel`, `std::thread::scope`. No new dependencies.

**Spec:** [docs/superpowers/specs/2026-05-16-issue-35-save-block-mid-call-wipe-race-design.md](../specs/2026-05-16-issue-35-save-block-mid-call-wipe-race-design.md).

**Branch:** `test/issue-35-save-block-mid-call-wipe-race` (already created; the spec is committed at `aa07c72`).

---

## File map

All edits land in `ffi/secretary-ffi-bridge/`:

| File | Action | Purpose |
|---|---|---|
| `src/vault/manifest.rs` | Modify | Add always-present `mid_call_hook` field + initializer in `Self::new`; add `pub(crate) run_mid_call_hook` caller + `#[doc(hidden)] pub install_mid_call_hook` installer |
| `src/save/orchestration.rs` | Modify | Add one-line `manifest.run_mid_call_hook();` between `Ok(())` arm and `replace_manifest_and_file` |
| `tests/save_block.rs` | Modify | Add `use std::sync::mpsc::*` imports, `MidCallRace` helper, one new `#[test]` |
| `NEXT_SESSION.md` | Modify | Roll the handoff forward |
| `docs/handoffs/2026-05-16-issue-35-save-block-mid-call-wipe-race.md` | Create | Frozen archive of the new NEXT_SESSION.md |

**Total commit shape:** 1 implementation commit (Tasks 1-5) + 1 handoff commit (Task 7). Both on the same branch before push.

---

## Pre-flight

### Confirm working directory and branch

- [ ] **Step 1: Verify state**

Run:
```bash
pwd && git branch --show-current && git status --short && git worktree list
```

Expected:
```
/Users/hherb/src/secretary
test/issue-35-save-block-mid-call-wipe-race
(no output from git status)
/Users/hherb/src/secretary  aa07c72 [test/issue-35-save-block-mid-call-wipe-race]
```

If status is not clean or branch is not `test/issue-35-save-block-mid-call-wipe-race`, STOP and report — the plan assumes the spec commit `aa07c72` is at branch tip with no other unstaged changes.

---

## Task 1: Add hook field + methods on `OpenVaultManifest`

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/vault/manifest.rs`

**Rationale:** The hook field is always present (`--cfg test` is not propagated to dependencies; a `#[cfg(test)]` gate would hide the installer from integration tests). Production code never calls `install_mid_call_hook`, so the hook is always `None` and `run_mid_call_hook` is a one-`Mutex`-lock no-op. `install_mid_call_hook` is `#[doc(hidden)] pub` so it stays out of generated rustdoc and does not cross the PyO3 / uniffi FFI boundary.

### Step 1.1: Add the test-only field to the struct definition

- [ ] **Step 1.1**

Edit `ffi/secretary-ffi-bridge/src/vault/manifest.rs` at the `OpenVaultManifest` struct definition.

Find (around line 28):
```rust
pub struct OpenVaultManifest {
    inner: Mutex<Option<OpenVaultManifestInner>>,
}
```

Replace with:
```rust
pub struct OpenVaultManifest {
    inner: Mutex<Option<OpenVaultManifestInner>>,
    /// Test-only hook fired between `core::*` and
    /// `replace_manifest_and_file` in the save / trash / restore
    /// orchestrators. Exposes the documented concurrent-wipe race
    /// window to integration tests.
    ///
    /// Field is always present (a `cfg(test)` gate would not reach
    /// integration tests in `tests/*.rs` — `--cfg test` is not
    /// propagated to dependencies). Default is `None`; production code
    /// never calls [`Self::install_mid_call_hook`], so production
    /// builds pay only one `Mutex` lock + `Option::is_none` check per
    /// `save_block` call. The installer is `pub` with `#[doc(hidden)]`
    /// so integration tests can reach it but it is invisible in
    /// generated docs and does not auto-cross the PyO3 / uniffi FFI
    /// boundary (which require explicit `#[pyo3]` / `#[uniffi::export]`
    /// annotations).
    ///
    /// Bound is `Fn() + Send` (no `+ Sync`): closures installed by
    /// tests typically capture `mpsc::Receiver<()>`, which is `Send`
    /// but not `Sync`. The wrapping `Mutex` already provides outer
    /// `Sync` for the field, so `+ Sync` on the closure itself is
    /// neither needed nor possible without forcing tests to use
    /// awkward `Arc<Condvar>` shapes.
    mid_call_hook: Mutex<Option<Box<dyn Fn() + Send>>>,
}
```

### Step 1.2: Initialize the new field in `Self::new`

- [ ] **Step 1.2**

Find (around line 46):
```rust
    pub(crate) fn new(inner: OpenVaultManifestInner) -> Self {
        Self {
            inner: Mutex::new(Some(inner)),
        }
    }
```

Replace with:
```rust
    pub(crate) fn new(inner: OpenVaultManifestInner) -> Self {
        Self {
            inner: Mutex::new(Some(inner)),
            mid_call_hook: Mutex::new(None),
        }
    }
```

### Step 1.3: Add `run_mid_call_hook` + `install_mid_call_hook` methods

- [ ] **Step 1.3**

Find the `wipe` method (around line 112):
```rust
    /// Drop the wrapped manifest now, zeroizing the IBK at exactly this
    /// moment. **Idempotent** — multiple calls do not panic.
    pub fn wipe(&self) {
        let _drop = lock_or_recover(&self.inner).take();
        // _drop goes out of scope here → OpenVaultManifestInner drops in
        // field-declaration order: identity_block_key (Sensitive<[u8; 32]>
        // — IBK zeroized first via ZeroizeOnDrop), then manifest,
        // manifest_file, owner_card.
    }
```

Immediately AFTER the closing `}` of `wipe` (i.e. before the next method `vault_folder`), insert two new methods:

```rust

    /// Fire the mid-call test hook if one is installed. Called by
    /// orchestrators between `core::*` and `replace_manifest_and_file`
    /// to expose the concurrent-wipe race window to integration tests.
    ///
    /// Production builds pay one `Mutex` lock + `Option::is_none` check
    /// per call (the hook is `None` unless
    /// [`Self::install_mid_call_hook`] has been called, and production
    /// code never calls that). Orchestrators opt into testability by
    /// adding a single `manifest.run_mid_call_hook();` call between the
    /// core invocation and the write-back. Today only
    /// `save::save_block` opts in; trash and restore can adopt the same
    /// shape in a follow-up.
    ///
    /// The hook closure must not recursively call `run_mid_call_hook`
    /// on the same `OpenVaultManifest` — the `mid_call_hook` mutex is
    /// held across the closure call and would deadlock. Test-only
    /// closures we install today only touch `mpsc` channel ends.
    #[inline]
    pub(crate) fn run_mid_call_hook(&self) {
        if let Some(f) = self
            .mid_call_hook
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
        {
            f();
        }
    }

    /// Install a closure fired by [`Self::run_mid_call_hook`].
    /// **Test-only — do not use in production.** Overwrites any
    /// previously-installed hook.
    ///
    /// `pub` so it is reachable from integration tests in `tests/*.rs`
    /// (where `--cfg test` is not propagated to dependencies, so a
    /// `#[cfg(test)]` gate would hide the method). `#[doc(hidden)]`
    /// keeps it out of generated rustdoc, and the method does not
    /// auto-cross the PyO3 / uniffi FFI boundary (those layers require
    /// explicit `#[pyo3]` / `#[uniffi::export]` annotations).
    #[doc(hidden)]
    pub fn install_mid_call_hook<F: Fn() + Send + 'static>(&self, f: F) {
        *self.mid_call_hook.lock().unwrap_or_else(|p| p.into_inner()) =
            Some(Box::new(f));
    }
```

### Step 1.4: Verify the manifest crate compiles and existing tests pass

- [ ] **Step 1.4: Build check**

Run:
```bash
cargo build --release --workspace --tests
```

Expected: clean build. **Two `dead_code` warnings are expected at this intermediate state** — `mid_call_hook` field is never read and `run_mid_call_hook` is never called (Task 2 adds the orchestrator call). `install_mid_call_hook` is also flagged (Task 3 adds the caller). Both go away after Tasks 2 + 3. Clippy with `-D warnings` would FAIL here; we only run it at step 3.6 once all three pieces are in place.

- [ ] **Step 1.5: Existing tests pass**

Run:
```bash
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{ for (i=1; i<=NF; i++) { if ($i == "passed;") p += $(i-1); if ($i == "failed;") f += $(i-1); if ($i == "ignored;") ig += $(i-1) } } END { printf("TOTAL: %d passed; %d failed; %d ignored\n", p, f, ig) }'
```

Expected: `TOTAL: 641 passed; 0 failed; 10 ignored`

If the count differs from 641 + 10, the new code has unintentionally affected an existing test — STOP and investigate.

---

## Task 2: Orchestrator opt-in for `save_block`

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/save/orchestration.rs`

**Rationale:** One unconditional call site. The hook is a no-op in release builds AND in test builds with no installed hook, so this is safe to add without any other change.

### Step 2.1: Insert the hook call in the `Ok(())` arm

- [ ] **Step 2.1**

Edit `ffi/secretary-ffi-bridge/src/save/orchestration.rs`.

Find (around line 114-125):
```rust
    match result {
        Ok(()) => {
            // Atomic write-back of the mutated manifest body and envelope.
            // The handle could have been wiped between Step 1 and now in a
            // theoretical concurrent-wipe race — if so, the on-disk write
            // already succeeded but the bridge state is no longer
            // authoritative; surface as CorruptVault.
            manifest
                .replace_manifest_and_file(open_vault.manifest, open_vault.manifest_file)
                .map_err(|e| FfiVaultError::CorruptVault {
                    detail: e.to_string(),
                })
```

Replace with:
```rust
    match result {
        Ok(()) => {
            // Test-only hook: exposes the concurrent-wipe race window
            // (lock NOT held between `core::save_block` succeeding and
            // `replace_manifest_and_file` taking the write-back lock) to
            // integration tests. Empty body in release builds; no-op in
            // test builds unless a hook was explicitly installed via
            // `OpenVaultManifest::install_mid_call_hook`. See issue #35
            // and tests::save_block::save_block_wipe_during_call_*.
            manifest.run_mid_call_hook();
            // Atomic write-back of the mutated manifest body and envelope.
            // The handle could have been wiped between Step 1 and now in a
            // theoretical concurrent-wipe race — if so, the on-disk write
            // already succeeded but the bridge state is no longer
            // authoritative; surface as CorruptVault.
            manifest
                .replace_manifest_and_file(open_vault.manifest, open_vault.manifest_file)
                .map_err(|e| FfiVaultError::CorruptVault {
                    detail: e.to_string(),
                })
```

### Step 2.2: Verify build + existing tests still pass

- [ ] **Step 2.2: Build**

Run:
```bash
cargo build --release --workspace --tests
```

Expected: clean build. **One `dead_code` warning remains** — `install_mid_call_hook` is never used; Task 3 adds the caller via the `MidCallRace` helper. The `run_mid_call_hook` and `mid_call_hook` warnings from step 1.4 are gone (orchestrator now calls them).

- [ ] **Step 2.3: Existing tests still pass**

Run:
```bash
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{ for (i=1; i<=NF; i++) { if ($i == "passed;") p += $(i-1); if ($i == "failed;") f += $(i-1); if ($i == "ignored;") ig += $(i-1) } } END { printf("TOTAL: %d passed; %d failed; %d ignored\n", p, f, ig) }'
```

Expected: `TOTAL: 641 passed; 0 failed; 10 ignored`

(`run_mid_call_hook` is a no-op without an installed hook; existing tests don't install one.)

---

## Task 3: Add `MidCallRace` helper + the race test

**Files:**
- Modify: `ffi/secretary-ffi-bridge/tests/save_block.rs`

**Rationale:** Helper encapsulates the two-channel handshake; the test body reads as plain English.

### Step 3.1: Add the mpsc imports

- [ ] **Step 3.1**

Edit `ffi/secretary-ffi-bridge/tests/save_block.rs`.

Find (lines 7-8):
```rust
use std::fs;
use std::path::{Path, PathBuf};
```

Replace with:
```rust
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
```

### Step 3.2: Append the `MidCallRace` helper at the bottom of the file

- [ ] **Step 3.2**

Append the following block at the END of `ffi/secretary-ffi-bridge/tests/save_block.rs` (after the last existing item — should be after the proptests / `arb_*` strategies).

```rust

// ---------------------------------------------------------------------------
// Mid-call wipe race (issue #35)
// ---------------------------------------------------------------------------

/// Test-only handshake helper that exposes the orchestrator's mid-call
/// hook to a parallel test thread. The worker thread running `save_block`
/// (or any other op that calls `manifest.run_mid_call_hook()`) blocks
/// at the hook until `release_worker` is called from the main thread.
/// In between, the main thread performs the racing action — typically
/// `manifest.wipe()`.
///
/// Single-use: `release_worker(self)` consumes the helper. Forgetting to
/// release the worker causes a `thread::scope` join to block on the
/// still-parked worker (the channel ends owned by `Self` live until end
/// of scope) — the test would hang, surfacing as a CI-job-level timeout
/// rather than a panic. Keep the test body between
/// `wait_for_worker_at_hook` and `release_worker` linear and short.
struct MidCallRace {
    rx_ready: Receiver<()>,
    tx_go: SyncSender<()>,
}

impl MidCallRace {
    fn install_on(manifest: &OpenVaultManifest) -> Self {
        let (tx_ready, rx_ready) = sync_channel::<()>(0);
        let (tx_go, rx_go) = sync_channel::<()>(0);
        manifest.install_mid_call_hook(move || {
            tx_ready
                .send(())
                .expect("test main thread still waiting on ready");
            rx_go
                .recv()
                .expect("test main thread dropped tx_go before signaling");
        });
        Self { rx_ready, tx_go }
    }

    fn wait_for_worker_at_hook(&self) {
        self.rx_ready
            .recv()
            .expect("worker never reached the mid-call hook");
    }

    fn release_worker(self) {
        self.tx_go
            .send(())
            .expect("worker no longer waiting on go signal");
    }
}
```

### Step 3.3: Append the test

- [ ] **Step 3.3**

Append the following test block at the END of `ffi/secretary-ffi-bridge/tests/save_block.rs`, AFTER the `MidCallRace` helper block from Step 3.2:

```rust

#[test]
fn save_block_wipe_during_call_returns_corrupt_vault_but_persists_on_disk() {
    let (tmp, identity, manifest) = fresh_writable_vault();
    let race = MidCallRace::install_on(&manifest);

    let input = BlockInput {
        block_uuid: NEW_BLOCK_UUID,
        block_name: "raced".to_string(),
        records: vec![RecordInput {
            record_uuid: NEW_RECORD_UUID,
            fields: vec![FieldInput {
                name: "k".to_string(),
                value: FieldInputValue::Text(SecretString::from("v")),
            }],
        }],
    };

    let result = std::thread::scope(|s| {
        let worker = s.spawn(|| {
            save_block(&identity, &manifest, input, DEVICE_UUID, NOW_MS_BASE)
        });
        race.wait_for_worker_at_hook();
        manifest.wipe();
        race.release_worker();
        worker.join().expect("worker panicked")
    });

    // (1) Mid-call wipe surfaces as the documented typed error.
    match result {
        Err(FfiVaultError::CorruptVault { detail }) => {
            assert!(
                detail.contains("closed during save"),
                "expected mid-call detail per ReplaceManifestError::HandleWiped \
                 Display impl; got: {detail}",
            );
        }
        other => panic!(
            "expected CorruptVault from mid-call wipe, got: {other:?}",
        ),
    }

    // (2) Documented partial-success-mid-race contract: on-disk state
    //     is updated even though the bridge handle is gone. Re-opening
    //     the vault decodes the re-signed manifest, lists the new
    //     block, and the block file decrypts back to the original input.
    let out = open_vault_with_password(tmp.path(), VAULT_001_PASSWORD)
        .expect("re-open after mid-call race");
    let summary = out
        .manifest
        .find_block(&NEW_BLOCK_UUID)
        .expect("new block visible on re-open after mid-call race");
    assert_eq!(summary.block_name, "raced");
    let output = read_block(&out.identity, &out.manifest, &NEW_BLOCK_UUID)
        .expect("read_block decrypts the persisted block");
    let r = output.record_at(0).expect("record present");
    assert_eq!(
        r.field_by_name("k").unwrap().expose_text().as_deref(),
        Some("v"),
        "field value survives the mid-call race round-trip",
    );
}
```

### Step 3.4: Run the new test on its own to confirm it passes

- [ ] **Step 3.4**

Run:
```bash
cargo test --release --workspace --test save_block save_block_wipe_during_call_returns_corrupt_vault_but_persists_on_disk -- --nocapture 2>&1 | tail -10
```

Expected (last lines):
```
test save_block_wipe_during_call_returns_corrupt_vault_but_persists_on_disk ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; <N> filtered out
```

If the test hangs: `Ctrl-C`, then verify Task 2 added the `manifest.run_mid_call_hook();` line (without it the worker never enters the hook, the main thread blocks on `rx_ready.recv()` forever).

If the test panics with "expected CorruptVault from mid-call wipe, got: Ok(())": the `manifest.wipe()` call landed too early or too late. Verify the orchestrator's `run_mid_call_hook()` call is between the `Ok(())` arm body's first statement and `replace_manifest_and_file`.

### Step 3.5: Run the full save_block test target to confirm sibling tests still pass

- [ ] **Step 3.5**

Run:
```bash
cargo test --release --workspace --test save_block 2>&1 | tail -5
```

Expected (last lines):
```
test result: ok. <N+1> passed; 0 failed; <some> ignored; 0 measured; 0 filtered out
```

The `<N+1>` is "previous save_block test count + 1". (Don't fixate on `<N>`; just verify the file-level test target is clean and the count is 1 higher than before this task.)

### Step 3.6: Confirm clippy is clean

- [ ] **Step 3.6**

Run:
```bash
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -5
```

Expected:
```
    Finished `release` profile [optimized] target(s) in <X>s
```

No warnings, no errors. If clippy complains about `dead_code` on `install_mid_call_hook` (because clippy only sees the test target it compiled), the warning is wrong — the new test DOES call it via `MidCallRace::install_on`. Re-run after `cargo clean -p secretary-ffi-bridge` and retry; if still warning, escalate.

### Step 3.7: Confirm `rustfmt` is clean

- [ ] **Step 3.7**

Run:
```bash
cargo fmt --all -- --check
```

Expected: no output, exit 0. If non-zero, run `cargo fmt --all` to fix.

---

## Task 4: Full verification gauntlet

**Rationale:** Before committing, confirm the full project test surface is unchanged. Mirrors the gauntlet from `NEXT_SESSION.md` (4).

### Step 4.1: Cargo test count

- [ ] **Step 4.1**

Run:
```bash
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{ for (i=1; i<=NF; i++) { if ($i == "passed;") p += $(i-1); if ($i == "failed;") f += $(i-1); if ($i == "ignored;") ig += $(i-1) } } END { printf("TOTAL: %d passed; %d failed; %d ignored\n", p, f, ig) }'
```

Expected: `TOTAL: 642 passed; 0 failed; 10 ignored`

(Was 641 + 10 before; +1 from the new test.)

### Step 4.2: Python conformance

- [ ] **Step 4.2**

Run:
```bash
uv run core/tests/python/conformance.py 2>&1 | tail -3
```

Expected: ends with a `PASS` line. (Conformance script reads the golden vault + KAT JSON; nothing in this PR touches either.)

### Step 4.3: Python spec-test-name freshness

- [ ] **Step 4.3**

Run:
```bash
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3
```

Expected: `PASS (96 / 0 / 2)` (or whatever the current baseline is — the new test name is NOT cited in `docs/*.md`, so the counts should match the baseline reported in the most recent `NEXT_SESSION.md`).

### Step 4.4: Swift smoke

- [ ] **Step 4.4**

Run:
```bash
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh 2>&1 | tail -3
```

Expected: ends with `OK` and ~38 PASS asserts. (Swift bindings are unchanged.)

### Step 4.5: Swift conformance KAT

- [ ] **Step 4.5**

Run:
```bash
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh 2>&1 | tail -3
```

Expected: `11/11 PASS`.

### Step 4.6: Kotlin smoke

- [ ] **Step 4.6**

Run:
```bash
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh 2>&1 | tail -3
```

Expected: ends with `OK` and ~39 PASS asserts.

### Step 4.7: Kotlin conformance KAT

- [ ] **Step 4.7**

Run:
```bash
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh 2>&1 | tail -3
```

Expected: `11/11 PASS`.

If any step in Task 4 fails, STOP and investigate. The expected behaviour is that nothing outside the bridge crate's save-path changes, so any conformance / smoke / Python check failing is an unexpected regression.

---

## Task 5: Implementation commit

### Step 5.1: Stage the three modified files

- [ ] **Step 5.1**

Run:
```bash
git add ffi/secretary-ffi-bridge/src/vault/manifest.rs \
        ffi/secretary-ffi-bridge/src/save/orchestration.rs \
        ffi/secretary-ffi-bridge/tests/save_block.rs
git status --short
```

Expected:
```
M  ffi/secretary-ffi-bridge/src/save/orchestration.rs
M  ffi/secretary-ffi-bridge/src/vault/manifest.rs
M  ffi/secretary-ffi-bridge/tests/save_block.rs
```

(Exactly three modified files staged, no untracked, no other modifications.)

### Step 5.2: Commit

- [ ] **Step 5.2**

Run:
```bash
git commit -m "$(cat <<'EOF'
test(ffi-bridge): exercise mid-call wipe race in save_block (closes #35)

Adds a deterministic integration test that exercises the documented
concurrent-wipe race between core::save_block succeeding and
replace_manifest_and_file taking the write-back lock. The orchestrator
returns the typed CorruptVault with the documented "closed during save"
detail; the on-disk vault carries the new block and decodes cleanly on
a fresh open_vault_with_password.

Mechanism: a test-only mid_call_hook field on OpenVaultManifest, an
always-present no-op-in-release run_mid_call_hook caller (one new line
in the save orchestrator's Ok arm), and a sync_channel(0) rendezvous
helper (MidCallRace) in tests/save_block.rs. Bound is Fn() + Send (no
+ Sync) because mpsc::Receiver is Send-but-not-Sync; the wrapping
Mutex provides outer Sync for the field.

Trash + restore use the same snapshot + write-back pattern and could
adopt the hook in a follow-up by adding one manifest.run_mid_call_hook()
line each. Out of scope for this PR.

Cargo test count: 641 + 10 → 642 + 10.

Design: docs/superpowers/specs/2026-05-16-issue-35-save-block-mid-call-wipe-race-design.md

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

Expected: a single new commit, status clean afterward.

### Step 5.3: Confirm commit landed

- [ ] **Step 5.3**

Run:
```bash
git log --oneline -3
git status --short
```

Expected:
```
<sha>     test(ffi-bridge): exercise mid-call wipe race in save_block (closes #35)
aa07c72   docs(specs): design for issue #35 (mid-call wipe race in save_block)
1b4a529   chore(b6): pre-v2 cleanup bundle (#60 #61 #62 #63) (#64)
```

`git status --short` returns no output (working tree clean).

---

## Task 6: README / ROADMAP touch-up check

### Step 6.1: README

- [ ] **Step 6.1**

`README.md` does NOT track per-test counts or internal hardening line items. No update expected. Confirm by:

```bash
grep -nE "save_block|wipe|race|cargo test|#35" README.md || echo "no relevant references"
```

Expected: `no relevant references` (or only general "passes the test suite" wording — leave untouched). If a specific test count is found, STOP and reconcile.

### Step 6.2: ROADMAP

- [ ] **Step 6.2**

`ROADMAP.md` tracks numbered sub-projects (B.4c, B.5, B.6, etc.) and counts. Issue #35 is internal hardening, not a roadmap milestone. Confirm:

```bash
grep -nE "#35|mid-call wipe|save_block race" ROADMAP.md || echo "no relevant references"
```

Expected: `no relevant references`. If ROADMAP cites the test count "641 + 10", update to "642 + 10" — but only if such a citation exists. Otherwise leave untouched.

If a count update is needed, edit the line and stage the change:
```bash
git add ROADMAP.md
git commit -m "docs(roadmap): bump cargo test count for issue #35

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Handoff update (NEXT_SESSION.md + docs/handoffs/ snapshot)

**Rationale:** Per `feedback_next_session_in_pr` — NEXT_SESSION.md rides inside the PR on the feature branch BEFORE push, so post-merge `main` carries a fresh baton.

### Step 7.1: Rewrite NEXT_SESSION.md

- [ ] **Step 7.1**

Overwrite `NEXT_SESSION.md` with the following content (replace `<COMMIT_SHA_FROM_5.3>` with the actual SHA from Step 5.3):

```markdown
# NEXT_SESSION.md

**Session date:** 2026-05-16 (issue #35 mid-call wipe race test)
**Status:** Branch `test/issue-35-save-block-mid-call-wipe-race` carries two commits on top of `1b4a529` (PR #64 merge). PR open against `main`. Gauntlet green: 642 cargo + 10 ignored / clippy clean / fmt OK / Python conformance + freshness PASS / Swift smoke 38 / Swift conformance 11/11 / Kotlin smoke 39 / Kotlin conformance 11/11.

## (1) What we shipped this session

| Commit | Type | What landed |
|---|---|---|
| `aa07c72` | docs(specs) | Design doc at [docs/superpowers/specs/2026-05-16-issue-35-save-block-mid-call-wipe-race-design.md](docs/superpowers/specs/2026-05-16-issue-35-save-block-mid-call-wipe-race-design.md). 8 sections + self-review fixes (corrected an inaccurate "cargo test 60s default timeout" claim, fixed a wrong "design holds the inner lock during core::save_block" claim, clarified that the "during core" window is observationally equivalent to the post-core window we test). |
| `<COMMIT_SHA_FROM_5.3>` | test(ffi-bridge) | Issue #35 closure. Test-only `mid_call_hook: Mutex<Option<Box<dyn Fn() + Send>>>` field on `OpenVaultManifest` + always-present `run_mid_call_hook` (empty body in release) + `#[cfg(test)] install_mid_call_hook`. One-line opt-in `manifest.run_mid_call_hook();` in `save_block` orchestrator's `Ok` arm. New test `save_block_wipe_during_call_returns_corrupt_vault_but_persists_on_disk` in `tests/save_block.rs` uses a `MidCallRace` helper (two `sync_channel(0)` rendezvous handshakes) to drive deterministic mid-call wipe, asserting (a) `CorruptVault` with the documented "closed during save" detail and (b) the partial-success-mid-race contract — re-open + `find_block` + `read_block` round-trip on the post-race on-disk state. Cargo test count: 641 + 10 → 642 + 10. |

### Final gauntlet at session close

| Check | Result |
|---|---|
| `cargo test --release --workspace --no-fail-fast` | **642 passed + 10 ignored** |
| `cargo clippy --release --workspace --tests -- -D warnings` | clean |
| `cargo fmt --all -- --check` | OK |
| `uv run core/tests/python/conformance.py` | PASS |
| `uv run core/tests/python/spec_test_name_freshness.py` | PASS (unchanged baseline) |
| `bash ffi/secretary-ffi-uniffi/tests/swift/run.sh` | 38 PASS asserts, OK |
| `bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh` | 11/11 PASS |
| `bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh` | 39 PASS asserts, OK |
| `bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh` | 11/11 PASS |

## (2) What's next

### Sub-project B.6 v2 design — lifecycle conformance KAT (issue [#59](https://github.com/hherb/secretary/issues/59))

Unchanged from the prior NEXT_SESSION. Top of the forward-progress queue. Three options on the `save_block` AEAD-nonce determinism question (cfg(test) RNG knob / shape-only assertions / dyn RngCore parameter) — start with `/brainstorm` before writing the v2 design doc.

### Optional follow-ups now unblocked by this session

- **Trash / restore mid-call wipe race tests.** Same hook, same `MidCallRace` helper. Each is one additional `manifest.run_mid_call_hook();` line in the respective orchestrator + one test file (lift `MidCallRace` to `tests/common/mid_call_race.rs` when the second consumer arrives). Not blocking B.6 v2; pick up if a sub-project C audit surfaces the need.

### Issues #37, #38, #45 (blocked on Sub-project C)

Unchanged from prior handoff. Not actionable until C starts.

## (3) Open decisions and risks

### Risks

- **`save_block` determinism design (B.6 v2 blocker).** Real architectural decision; spend a session brainstorming before writing code.
- **Future orchestrators must remember `run_mid_call_hook` to be testable for the same race.** Doc comment on the method names the contract; reviewer catch is the mitigation. No mechanical enforcement (over-engineering for 3-4 call sites).

### Issues still open from prior sessions

- **Issue #37** — design discipline reminder for Sub-project C; not actionable until C starts.
- **Issue #38** — proptest case budget (shared writable-vault fixture); not actionable until C.
- **Issue #45** — three `pub(crate) #[allow(dead_code)]` accessors on `OpenVaultManifest`; revisit when C starts.
- **Issue #59** — B.6 v2 lifecycle conformance KAT. Design + plan + impl. Next session candidate.
- **Issue #35** — closed this session by the PR (when it merges).

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git checkout main
git pull --ff-only origin main                       # after the PR merges
git fetch --prune origin
git status --short                                   # expect: clean
git branch -vv                                       # expect: only main (after local feature branch is deleted)
git worktree list                                    # expect: only the primary worktree

# Verify the test gauntlet still matches this session's closing numbers:
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{
  for (i=1; i<=NF; i++) {
    if ($i == "passed;") p += $(i-1)
    if ($i == "failed;") f += $(i-1)
    if ($i == "ignored;") ig += $(i-1)
  }
}
END { printf("TOTAL: %d passed; %d failed; %d ignored\n", p, f, ig) }'
# Expect: TOTAL: 642 passed; 0 failed; 10 ignored

cargo clippy --release --workspace --tests -- -D warnings    # Expect: clean
cargo fmt --all -- --check                                    # Expect: OK
uv run core/tests/python/conformance.py                       # Expect: PASS
uv run core/tests/python/spec_test_name_freshness.py          # Expect: PASS (unchanged baseline)

bash ffi/secretary-ffi-uniffi/tests/swift/run.sh              # Expect: OK; ~38 PASS asserts
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh  # Expect: 11/11 PASS
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh             # Expect: OK; ~39 PASS asserts
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh # Expect: 11/11 PASS

# Next forward-progress chunk — B.6 v2 design (recommended):
#   /brainstorm on the save_block determinism question (issue #59)
# or check the open backlog:
gh issue list --state open
```

---

## Closing inventory

- **Branch state on close:** `test/issue-35-save-block-mid-call-wipe-race` carries 2 commits on top of `1b4a529` — 1 design doc + 1 implementation. PR open against main.
- **Workspace tests:** **642 cargo + 10 ignored** (was 641 + 10). Conformance + Swift + Kotlin runners unchanged.
- **README:** unchanged (no specific test counts or internal hardening line items).
- **ROADMAP:** unchanged.
- **CLAUDE.md:** unchanged.
- **Files created:** [`docs/superpowers/specs/2026-05-16-issue-35-save-block-mid-call-wipe-race-design.md`](docs/superpowers/specs/2026-05-16-issue-35-save-block-mid-call-wipe-race-design.md), [`docs/superpowers/plans/2026-05-16-issue-35-save-block-mid-call-wipe-race.md`](docs/superpowers/plans/2026-05-16-issue-35-save-block-mid-call-wipe-race.md), [`NEXT_SESSION.md`](NEXT_SESSION.md) (this file, overwritten), [`docs/handoffs/2026-05-16-issue-35-save-block-mid-call-wipe-race.md`](docs/handoffs/2026-05-16-issue-35-save-block-mid-call-wipe-race.md) (frozen archive of this file).
- **Files modified:** [`ffi/secretary-ffi-bridge/src/vault/manifest.rs`](ffi/secretary-ffi-bridge/src/vault/manifest.rs) (+1 field on struct, +2 methods, +~12 lines of doc), [`ffi/secretary-ffi-bridge/src/save/orchestration.rs`](ffi/secretary-ffi-bridge/src/save/orchestration.rs) (+1 call site, +8 lines of comment), [`ffi/secretary-ffi-bridge/tests/save_block.rs`](ffi/secretary-ffi-bridge/tests/save_block.rs) (+1 import line, +~30 LOC helper, +~50 LOC test).
- **Issues filed this session:** none.
- **PR to open:** `test(ffi-bridge): mid-call wipe race in save_block (closes #35)` against `main`.
```

### Step 7.2: Snapshot the handoff under docs/handoffs/

- [ ] **Step 7.2**

Run:
```bash
cp NEXT_SESSION.md docs/handoffs/2026-05-16-issue-35-save-block-mid-call-wipe-race.md
```

Expected: file created at the snapshot path. (Per `nextsession` skill instructions: identical content to NEXT_SESSION.md, just frozen for audit.)

### Step 7.3: Commit the handoff

- [ ] **Step 7.3**

Run:
```bash
git add NEXT_SESSION.md docs/handoffs/2026-05-16-issue-35-save-block-mid-call-wipe-race.md
git status --short
```

Expected:
```
A  docs/handoffs/2026-05-16-issue-35-save-block-mid-call-wipe-race.md
M  NEXT_SESSION.md
```

Then:
```bash
git commit -m "$(cat <<'EOF'
docs: update NEXT_SESSION.md for issue #35 close + frozen handoff

Rolls the live handoff forward to record the issue #35 test landing and
its commit SHA. docs/handoffs/ snapshot mirrors the same content for
audit / learning per the nextsession skill convention.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
git log --oneline -4
```

Expected: a third commit on the branch, on top of the implementation commit + design doc commit.

---

## Task 8: Push + open PR

### Step 8.1: Push the branch

- [ ] **Step 8.1**

Run:
```bash
git push -u origin test/issue-35-save-block-mid-call-wipe-race
```

Expected: branch published to remote; tracking set up; output includes "Branch 'test/issue-35-save-block-mid-call-wipe-race' set up to track 'origin/test/issue-35-save-block-mid-call-wipe-race'."

### Step 8.2: Open the PR

- [ ] **Step 8.2**

Run:
```bash
gh pr create --title "test(ffi-bridge): mid-call wipe race in save_block (closes #35)" --body "$(cat <<'EOF'
## Summary

- Adds a deterministic integration test for the documented post-`core::save_block` / pre-`replace_manifest_and_file` concurrent-wipe race in [ffi/secretary-ffi-bridge/src/save/orchestration.rs:114-125](../../ffi/secretary-ffi-bridge/src/save/orchestration.rs#L114-L125). Closes #35.
- New surface: test-only `mid_call_hook` field on `OpenVaultManifest` + always-present no-op-in-release `run_mid_call_hook` caller + `#[cfg(test)] install_mid_call_hook` installer. One line opt-in in the `save_block` orchestrator's `Ok` arm. `MidCallRace` helper (two `sync_channel(0)` rendezvous handshakes) hides the worker→main / main→worker signalling so the test body reads as plain English.
- Cargo test count: 641 + 10 → 642 + 10. No new dependencies.

## Design + plan

- Spec: [`docs/superpowers/specs/2026-05-16-issue-35-save-block-mid-call-wipe-race-design.md`](../blob/test/issue-35-save-block-mid-call-wipe-race/docs/superpowers/specs/2026-05-16-issue-35-save-block-mid-call-wipe-race-design.md)
- Plan: [`docs/superpowers/plans/2026-05-16-issue-35-save-block-mid-call-wipe-race.md`](../blob/test/issue-35-save-block-mid-call-wipe-race/docs/superpowers/plans/2026-05-16-issue-35-save-block-mid-call-wipe-race.md)

## Test plan

- [x] `cargo test --release --workspace --no-fail-fast` → 642 passed; 0 failed; 10 ignored
- [x] `cargo clippy --release --workspace --tests -- -D warnings` → clean
- [x] `cargo fmt --all -- --check` → OK
- [x] `uv run core/tests/python/conformance.py` → PASS
- [x] `uv run core/tests/python/spec_test_name_freshness.py` → PASS (unchanged baseline)
- [x] `bash ffi/secretary-ffi-uniffi/tests/swift/run.sh` → OK, 38 PASS asserts
- [x] `bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh` → 11/11 PASS
- [x] `bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh` → OK, 39 PASS asserts
- [x] `bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh` → 11/11 PASS

## Out of scope (deferred)

- Trash + restore race tests. Same hook, one-line opt-in each, one test each. Lift `MidCallRace` to `tests/common/` when the second consumer arrives.
- `loom` model. Pinning one documented interleaving doesn't need exhaustive interleaving search.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

Expected: PR URL printed (e.g. `https://github.com/hherb/secretary/pull/65`). Capture the number and report.

### Step 8.3: Confirm PR is open

- [ ] **Step 8.3**

Run:
```bash
gh pr view --json number,title,url,state | head -20
```

Expected: `"state":"OPEN"` and the title from Step 8.2.

---

## Self-Review

### Spec coverage

| Spec section | Task |
|---|---|
| §1 Goal: deterministic test for the mid-call race | Task 3 (the test) |
| §3.1 Hook field + run_mid_call_hook + install_mid_call_hook | Task 1 (steps 1.1, 1.2, 1.3) |
| §3.2 Orchestrator opt-in (one line) | Task 2 (step 2.1) |
| §3.3 MidCallRace helper | Task 3 (step 3.2) |
| §3.4 The test itself | Task 3 (step 3.3) |
| §3.5 Deterministic synchronization | Task 3 (steps 3.4 verifies determinism — passes on first try means handshake works) |
| §4.1 Acceptance test | Task 3 (step 3.4) |
| §4.2 Regression coverage retained | Task 1 (step 1.5) + Task 2 (step 2.3) — count stays 641 |
| §4.3 Cross-language replay | Task 4 (steps 4.4–4.7) |
| §4.4 Spec freshness | Task 4 (step 4.3) |
| §4.5 Lints | Task 3 (step 3.6) + Task 3 (step 3.7) |
| §5 Risks | Mitigations embedded in step-level instructions (e.g. step 3.4 troubleshoots hang; step 1.4 confirms intermediate state compiles) |
| §6 Out of scope | Plan does not implement trash/restore tests, loom, or common/ lift (correct) |
| §8 Implementation order | Tasks 1–3 follow §8's TDD-staged order; reordered for safety (production-side first, test last) to avoid intermediate hang states |

Gaps: none.

### Placeholder scan

Grep-equivalent for "TBD", "TODO", "fill in" within the plan text: none found. Every code block is complete. Every command has an expected output. No "similar to Task N" references; the test body is repeated in full at step 3.3 even though it appears in the spec.

### Type consistency

- `OpenVaultManifest::run_mid_call_hook` (steps 1.3, 2.1, 3.2's MidCallRace) — same name throughout.
- `OpenVaultManifest::install_mid_call_hook` (steps 1.3, 3.2) — same name.
- `MidCallRace::install_on`, `wait_for_worker_at_hook`, `release_worker` (steps 3.2, 3.3) — same names; `release_worker(self)` consumes self in both places.
- `mid_call_hook` field name (steps 1.1, 1.2, 1.3) — consistent.
- `Fn() + Send` bound (steps 1.1, 1.3) — both occurrences consistent (`Box<dyn Fn() + Send>` in field, `F: Fn() + Send + 'static` in generic).

No inconsistencies.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-05-16-issue-35-save-block-mid-call-wipe-race.md`.
