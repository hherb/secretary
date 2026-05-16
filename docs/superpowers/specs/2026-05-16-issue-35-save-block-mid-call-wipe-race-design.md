# Issue #35 — Mid-call wipe race in `save_block`: design

**Status:** approved 2026-05-16
**Tracks:** [#35](https://github.com/hherb/secretary/issues/35) — `test(ffi-b4c): exercise mid-call wipe race in save_block`
**Branch (proposed):** `test/issue-35-save-block-mid-call-wipe-race`

## 1. Goal

Add a deterministic integration test that exercises the concurrent-wipe race window between `core::vault::save_block` succeeding and `OpenVaultManifest::replace_manifest_and_file` taking the write-back lock in [ffi/secretary-ffi-bridge/src/save/orchestration.rs:114-125](../../ffi/secretary-ffi-bridge/src/save/orchestration.rs#L114-L125), proving the documented partial-success-mid-race contract:

1. The orchestrator returns `FfiVaultError::CorruptVault` with the documented detail (`"vault manifest handle has been closed during save"`).
2. The on-disk vault is updated — the new block file is persisted **and** the manifest on disk has been re-signed with the new `block_uuid` entry, decoding cleanly on a fresh `open_vault_with_password` call.

The existing [save_block_on_wiped_manifest_returns_corrupt_vault](../../ffi/secretary-ffi-bridge/tests/save_block.rs#L217) only exercises the **pre-call** wipe (handle wiped before `snapshot_for_save_block`; orchestrator fast-fails at step 1). The mid-call race is observable to foreign callers and has no test today; a silent refactor that changed the contract (e.g. dropping the on-disk write instead of surfacing the in-memory loss) would slip through.

## 2. Non-goals

- **No production behaviour change.** `core::save_block`, `replace_manifest_and_file`, and the orchestrator semantics are unchanged. The only production-code edit is one line added to the orchestrator (`manifest.run_mid_call_hook();`) which compiles to an empty body in release builds.
- **No `loom` model.** The issue notes `loom` as an alternative; `loom` exhaustively searches the interleaving space, which over-shoots a test that pins one specific documented interleaving. Plain `std::sync::mpsc::sync_channel` deterministic handshake suffices.
- **No trash / restore race tests in this PR.** The same race window exists in [trash/orchestration.rs](../../ffi/secretary-ffi-bridge/src/trash/orchestration.rs) and [restore/orchestration.rs](../../ffi/secretary-ffi-bridge/src/restore/orchestration.rs) (both use `snapshot_for_save_block` + `replace_manifest_and_file`). The hook is **designed to be reusable** for them, but adding those tests is a follow-up. Issue #35 names `save_block` specifically; YAGNI for now.
- **No new dependencies.** All synchronization uses `std::sync::mpsc`, `std::sync::Mutex`, and `std::thread::scope` (stable since Rust 1.63).
- **No changes to FFI surface.** PyO3 and uniffi bindings are unchanged. `install_mid_call_hook` is `#[doc(hidden)] pub` on the bridge crate (required because `--cfg test` is not propagated to dependencies; see §3.1) but the FFI layers do not auto-expose Rust methods — they require explicit `#[pyo3]` / `#[uniffi::export]` annotations, which this method does not have. The hook never crosses the foreign-language boundary.

## 3. Design

### 3.1 Hook on `OpenVaultManifest`

Add a field carrying an optional closure, plus an unconditional caller (`pub(crate)`) and a `#[doc(hidden)] pub` installer. The pattern intentionally puts the call site in production code as a single unconditional method call. This keeps the three orchestrators (save / trash / restore) uniform and makes adding a fourth (whatever sub-project C produces) a one-line addition with no `#[cfg(...)]` block scattered into business logic.

**Why `#[doc(hidden)] pub` instead of `#[cfg(test)] pub(crate)`:** `--cfg test` is **not** propagated to dependencies — when the integration test binary at `tests/save_block.rs` compiles, it links against `secretary-ffi-bridge` compiled **without** `cfg(test)`, so `#[cfg(test)]` items in the lib would be invisible to it. `#[doc(hidden)] pub` is the standard workaround (used by `tokio`, `hyper`, `tracing` for analogous test hooks): the item is `pub` so integration tests can reach it, but `#[doc(hidden)]` hides it from generated rustdoc, and the method does not auto-cross the PyO3 / uniffi FFI boundary (those layers require explicit `#[pyo3]` / `#[uniffi::export]` annotations).

```rust
// ffi/secretary-ffi-bridge/src/vault/manifest.rs

use std::sync::Mutex;

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
    /// never calls `install_mid_call_hook`, so production builds pay
    /// only one `Mutex` lock + `Option::is_none` check per
    /// `save_block` call. The installer is `pub` with `#[doc(hidden)]`
    /// so integration tests can reach it but it is invisible in
    /// generated docs and does not auto-cross the PyO3 / uniffi FFI
    /// boundary.
    ///
    /// Bound is `Fn() + Send` (no `+ Sync`): closures installed by
    /// tests typically capture `mpsc::Receiver<()>`, which is `Send`
    /// but not `Sync`. The wrapping `Mutex` already provides outer
    /// `Sync` for the field, so `+ Sync` on the closure itself is
    /// neither needed nor possible without forcing tests to use
    /// awkward `Arc<Condvar>` shapes.
    mid_call_hook: Mutex<Option<Box<dyn Fn() + Send>>>,
}

impl OpenVaultManifest {
    pub(crate) fn new(inner: OpenVaultManifestInner) -> Self {
        Self {
            inner: Mutex::new(Some(inner)),
            mid_call_hook: Mutex::new(None),
        }
    }

    /// Fire the mid-call test hook if one is installed. Called by
    /// orchestrators between `core::*` and `replace_manifest_and_file`
    /// to expose the concurrent-wipe race window to integration tests.
    ///
    /// Production builds pay one `Mutex` lock + `Option::is_none` check
    /// per call (the hook is `None` unless `install_mid_call_hook` has
    /// been called, and production code never calls that).
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

    /// Install a closure fired by `run_mid_call_hook`.
    /// **Test-only — do not use in production.** Overwrites any
    /// previously-installed hook.
    ///
    /// `pub` so it is reachable from integration tests in `tests/*.rs`
    /// (where `--cfg test` is not propagated to dependencies, so a
    /// `#[cfg(test)]` gate would hide the method). `#[doc(hidden)]`
    /// keeps it out of generated rustdoc, and the method does not
    /// auto-cross the PyO3 / uniffi FFI boundary.
    #[doc(hidden)]
    pub fn install_mid_call_hook<F: Fn() + Send + 'static>(&self, f: F) {
        *self.mid_call_hook.lock().unwrap_or_else(|p| p.into_inner()) =
            Some(Box::new(f));
    }
}
```

**Lock discipline.** `run_mid_call_hook` holds the `mid_call_hook` mutex while the closure runs. This is safe because:

- The `inner` mutex (the one `wipe()` and `replace_manifest_and_file` contend on) is a **different** mutex; the hook does not block `wipe()`.
- The closure cannot recursively call `run_mid_call_hook` on the same manifest (it would deadlock on the hook mutex). The test-only closures we install only touch channel ends, never the manifest.
- Holding the hook mutex across the closure call means we cannot install a *new* hook while the current one is running; tests don't do this.

**Public-API surface.** `mid_call_hook` is a private field; `run_mid_call_hook` is `pub(crate)` (only called from same-crate orchestrators); `install_mid_call_hook` is `#[doc(hidden)] pub` so integration tests can reach it. It is invisible to rustdoc and does not cross the PyO3 / uniffi FFI boundary (those bindings require explicit annotations on every exposed method).

### 3.2 Call-site addition in `save_block` orchestrator

[ffi/secretary-ffi-bridge/src/save/orchestration.rs](../../ffi/secretary-ffi-bridge/src/save/orchestration.rs) — one line added between Step 5 (`core::save_block` returns `Ok`) and Step 6 (`replace_manifest_and_file`):

```rust
match result {
    Ok(()) => {
        // Test-only hook: exposes the concurrent-wipe race window
        // (lock NOT held between `core::save_block` succeeding and
        // `replace_manifest_and_file` taking the write-back lock) to
        // integration tests. Empty body in release builds.
        manifest.run_mid_call_hook();
        manifest
            .replace_manifest_and_file(open_vault.manifest, open_vault.manifest_file)
            .map_err(|e| FfiVaultError::CorruptVault {
                detail: e.to_string(),
            })
    }
    Err(e) => Err(map_core_vault_error(e)),
}
```

Trash and restore orchestrators are **not** modified in this PR. When a future PR adds race tests for them, each gains the same one-line `manifest.run_mid_call_hook();` between its `core::*` call and `replace_manifest_and_file`.

### 3.3 Test-only helper: `MidCallRace`

A small helper at the bottom of [ffi/secretary-ffi-bridge/tests/save_block.rs](../../ffi/secretary-ffi-bridge/tests/save_block.rs) hides the channel handshake. Two `sync_channel(0)` rendezvous channels carry "worker reached the hook" (worker → main) and "go" (main → worker) signals:

```rust
// ffi/secretary-ffi-bridge/tests/save_block.rs (test helper at file bottom)

use std::sync::mpsc::{sync_channel, Receiver, SyncSender};

/// Test-only handshake helper that exposes the orchestrator's mid-call
/// hook to a parallel test thread. The worker thread running `save_block`
/// (or any other op that calls `manifest.run_mid_call_hook()`) blocks
/// at the hook until `release_worker` is called from the main thread.
/// In between, the main thread performs the racing action — typically
/// `manifest.wipe()`.
///
/// Single-use: `release_worker(self)` consumes the helper. Forgetting
/// to release the worker causes a `thread::scope` join to block on the
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

### 3.4 The test itself

```rust
// ffi/secretary-ffi-bridge/tests/save_block.rs (with the existing #[test] block)

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

### 3.5 Why this synchronization is deterministic

The race we want is:

1. Worker: `core::save_block` succeeds (on-disk state is updated).
2. **Main: `manifest.wipe()` completes (in-memory state is gone).**
3. Worker: `replace_manifest_and_file` runs, takes the `inner` lock, sees `None`, returns `HandleWiped`.

Without the hook, step 1 → step 3 is a non-blocking sequence on the worker. A concurrent `wipe()` from the main thread could land at step 2 only by lucky timing — flaky on CI.

With the hook:

- After step 1 succeeds, worker calls `run_mid_call_hook`, which calls the installed closure: `tx_ready.send(())` blocks until main calls `rx_ready.recv()`.
- `sync_channel(0)` is a rendezvous (capacity zero): the `send` returns *only* when a `recv` is paired with it, and vice versa. Main's `wait_for_worker_at_hook` (`rx_ready.recv()`) completes simultaneously with worker's `tx_ready.send(())`.
- Worker now blocks on `rx_go.recv()`. Main does `manifest.wipe()` knowing the worker is parked inside the hook (past `core::save_block`, before `replace_manifest_and_file`).
- Main calls `release_worker(self)` → `tx_go.send(())` → worker's `rx_go.recv()` returns → hook returns → worker proceeds to `replace_manifest_and_file`, which now finds `inner` is `None`.

The handshake makes the interleaving exact: no `sleep`, no polling, no timing assumption. The test is deterministic on any platform with a working `std::sync::mpsc`.

## 4. Testing strategy

### 4.1 Acceptance tests

The single new test ([§3.4](#34-the-test-itself)) verifies the full documented contract: typed error variant, error detail substring, on-disk manifest re-sign, on-disk block file decryptable. **Not** a probabilistic / "run 100 times" test — the handshake is deterministic.

### 4.2 Regression coverage retained

All existing tests in `tests/save_block.rs` keep passing. The added `manifest.run_mid_call_hook()` call in the orchestrator is a no-op in release builds; in `cfg(test)` builds it is also a no-op unless a hook was explicitly installed. Existing tests do not install a hook, so they are unaffected.

### 4.3 Cross-language replay

The PyO3 and uniffi bindings expose `save_block` (and `wipe`) to foreign callers. Although the new hook is bridge-internal and never reaches foreign code, the integration smoke runners (`ffi/secretary-ffi-py/tests/test_smoke.py`, `ffi/secretary-ffi-uniffi/tests/swift/run.sh`, `ffi/secretary-ffi-uniffi/tests/kotlin/run.sh`) all exercise `save_block` end-to-end and verify the orchestrator's overall behaviour is unchanged. The conformance KAT replay (Rust + Swift + Kotlin) is also re-run as a sanity check.

### 4.4 Spec-conformance freshness

`core/tests/python/spec_test_name_freshness.py` scans `docs/*.md` for test-name citations. The new test name (`save_block_wipe_during_call_returns_corrupt_vault_but_persists_on_disk`) is not cited anywhere in `docs/` (this is an internal test, not a public spec invariant), so the freshness check is unaffected.

### 4.5 Lints

`cargo clippy --release --workspace --tests -- -D warnings` must stay clean. The `#[cfg(test)] pub(crate) fn install_mid_call_hook` is only compiled under `cfg(test)`; with `--tests`, clippy compiles the test targets, the new test calls `install_mid_call_hook` via the `MidCallRace` helper, and no `dead_code` warning fires. Without `--tests` the method does not exist, so there is nothing to warn about.

## 5. Risks

### 5.1 `mid_call_hook` field is always present (mild production overhead)

The field exists in production builds (a `cfg(test)` gate would not reach integration tests; see §3.1). Costs:

- ~24 bytes per `OpenVaultManifest` instance (a `Mutex<Option<Box<dyn Fn() + Send>>>`).
- One additional `Mutex` lock + `Option::is_none` check per `save_block` call (in `run_mid_call_hook`).

Both costs are negligible for the application's domain (one-or-few open vaults per process; `save_block` is not a hot path). Workspace-wide `#![forbid(unsafe_code)]` is unaffected (no raw-pointer reads of the struct), and the bridge type is heap-allocated through PyO3 / uniffi handles so the struct size is not pinned by any ABI trait.

### 5.2 Hook locked across closure call could deadlock if misused

`run_mid_call_hook` holds the `mid_call_hook` mutex while the closure runs. If a closure tried to recursively call `run_mid_call_hook` on the *same* manifest, it would deadlock. The closures we install only touch `mpsc` channels and never the manifest, so this is not exercised; the doc comment on `run_mid_call_hook` should mention the constraint anyway so future authors don't trip on it.

### 5.3 Test hang on test-logic bug

If the test panics between `race.wait_for_worker_at_hook()` and `race.release_worker()`, the worker stays blocked inside the hook. `std::thread::scope` would then block on join, presenting as a test hang rather than a panic.

Mitigations:

- The test body between these two calls is exactly **one line** (`manifest.wipe()`). `wipe()` is documented idempotent and infallible; it does not panic.
- `release_worker(self)` consumes `self`. The compiler does not catch a missing call (the variable is still used by `wait_for_worker_at_hook`), so this is a discipline check, not a type-system check.
- `cargo test` has no per-test timeout. A genuine hang would surface as a CI-job-level timeout (GitHub Actions: 6h default, typically much lower per-workflow), which is loud but slow. The mitigation above (linear infallible body between recv and release) is what actually keeps this from happening in practice.

A `Drop` impl on `MidCallRace` that sent `tx_go.send(())` on drop was considered but rejected: drop ordering with `thread::scope` is fragile, and we **want** "missing release" to be a loud failure during test development, not a silent auto-release that masks a forgotten step.

### 5.4 `Fn() + Send` (not `+ Sync`) closure bound is non-obvious

A reader may wonder why the closure bound omits `+ Sync`. The reason (`mpsc::Receiver<()>: Send + !Sync`; outer `Mutex` provides `Sync`) is documented in the field's doc comment. This is the cheapest workaround and avoids forcing test authors into `Arc<Condvar>` patterns.

### 5.5 Future orchestrators must remember to call `run_mid_call_hook`

If a new orchestrator (e.g. a hypothetical `delete_block` lifecycle op in sub-project C) uses the `snapshot_for_save_block` + `replace_manifest_and_file` pattern, it must call `manifest.run_mid_call_hook()` at the same point to be testable for the same race.

Mitigations:

- The doc comment on `run_mid_call_hook` explicitly names the contract (and the three orchestrators that already call it after this PR lands).
- Future PRs adding such orchestrators go through code review; the missing call is a reviewer catch.

No mechanical enforcement (typed checkpoint / linter rule) — over-engineering for three to four call sites.

### 5.6 Hook is race-window-specific

The hook only catches the race between `core::save_block` succeeding and `replace_manifest_and_file`. Other races (e.g. *inside* `core::save_block`, or between `snapshot_for_save_block` and `core::save_block`) would need different hooks.

Acceptable: the pre-call wipe race is covered by the existing `save_block_on_wiped_manifest_returns_corrupt_vault` test. The "inside `core::save_block`" window does not need a separate test because it is **observationally equivalent** to the post-core window from the foreign caller's perspective:

- `core::save_block` operates on the snapshot clones (`manifest_body`, `manifest_file`, `owner_card`, IBK clone, `vault_folder`) returned by `snapshot_for_save_block`. It does not touch the bridge's `inner: Option<Inner>` cell at all.
- A concurrent `wipe()` during `core::save_block` therefore has no effect on `core::save_block`'s execution — it just clears the bridge's in-memory state, which the worker re-encounters when it later calls `replace_manifest_and_file`.
- The end-state behaviour (orchestrator returns `CorruptVault`; on-disk state is whatever `core::save_block` managed to write before the orchestrator surfaced the failure) is identical to the post-core window we DO test.

The hook would still fire after `core::save_block` returns `Ok`, by which point any concurrent wipe has already landed (or not).

## 6. Out of scope (explicit deferral)

- **Trash / restore race tests.** Same hook, one more call-site each, one more test each. Deferred to a follow-up PR. The hook's reusability is preserved.
- **`loom` model.** Exhaustive interleaving search; not needed for pinning one documented interleaving.
- **`MidCallRace` lifted to `tests/common/`.** One consumer today (`tests/save_block.rs`). Lift when the second consumer (e.g. a `tests/trash_block.rs` race test) materializes; module structure should not anticipate users that may not arrive.
- **A typed-checkpoint pattern enforcing the hook call.** The "future orchestrator must remember `run_mid_call_hook`" risk is real but small; mechanical enforcement (e.g. requiring `replace_manifest_and_file` to take a `MidCallReadyToken` returned by `run_mid_call_hook`) is over-engineering for three to four call sites.

## 7. Open questions

None — all design choices were resolved during the brainstorming session.

## 8. Implementation order, summarised

One commit, structured as:

1. **`test(ffi-bridge): exercise mid-call wipe race in save_block (closes #35)`**
   - `src/vault/manifest.rs`: add `#[cfg(test)] mid_call_hook` field on `OpenVaultManifest`; add `pub(crate) fn run_mid_call_hook(&self)` with empty release body; add `#[cfg(test)] pub(crate) fn install_mid_call_hook(...)`.
   - `src/save/orchestration.rs`: add the one-line `manifest.run_mid_call_hook();` call between `Ok(())` arm and `replace_manifest_and_file`.
   - `tests/save_block.rs`: add `MidCallRace` helper + `save_block_wipe_during_call_returns_corrupt_vault_but_persists_on_disk` test.
   - Run the full gauntlet (`cargo test --release --workspace --no-fail-fast`, `cargo clippy --release --workspace --tests -- -D warnings`, `cargo fmt --all -- --check`, Python conformance, Python freshness, Swift / Kotlin smoke + conformance).

TDD order within the commit: write the test first against unmodified production code (it should fail because `run_mid_call_hook` does not yet exist) → add the field + methods (test still fails because the orchestrator does not call the hook) → add the orchestrator call site (test passes). Each intermediate state should compile so we can verify the failure mode is "expected hook to fire but it did not" before flipping the orchestrator line.

Expected final test count: **642 cargo + 10 ignored** (was 641 + 10; +1 new test in `tests/save_block.rs`). All four cross-language conformance runners (Swift smoke / Swift KAT 11/11 / Kotlin smoke / Kotlin KAT 11/11) unchanged.
