# B.4c — bridge layer complete; binding flavors pending

**Session date:** 2026-05-10
**Branch:** `feat/ffi-b4c-save-block` (NOT yet pushed; NOT yet a PR)
**Status:** Bridge surface for `save_block` shipped end-to-end with integration tests. Binding flavors (uniffi, PyO3) and docs remain.

## What shipped this session

| Commit | What landed |
|---|---|
| `4f06ffc` | Spec — `docs/superpowers/specs/2026-05-09-ffi-b4c-save-block-design.md` |
| `fb3ba20` | Plan — `docs/superpowers/plans/2026-05-09-ffi-b4c-save-block.md` |
| `bbbf2da` | Task 1.1: `FfiVaultError::SaveCryptoFailure` variant landed atomically across bridge / uniffi VaultError / PyO3 exception class. The downstream From-impls have exhaustive matches so the variant introduction had to be cross-crate; the per-flavor user-visible surface (UDL line, smoke tests) still ships in Tasks 3.x / 4.x. |
| `60e8742` | Task 1.2: `BlockInput` / `RecordInput` / `FieldInput` / `FieldInputValue` types in new `save/input.rs`. Plan-vs-reality: bridge re-uses core's existing `SecretString` / `SecretBytes` (no bridge newtype needed; the v2 zeroize gap CLAUDE.md flagged was already closed by PR #16, fixed in working-tree CLAUDE.md). |
| `127a3dc` | Task 1.3: `signer_secret_keys()` accessor on `UnlockedIdentity` returning Ed25519 + ML-DSA-65 SKs. Mirror of `reader_secret_keys` for the signing path. |
| `e5d9738` | Task 1.4: `snapshot_for_save_block()` accessor on `OpenVaultManifest` returning the 5-tuple (manifest, manifest_file, owner_card, IBK clone, vault_folder). |
| `d12567b` | Task 2.1: stub `save_block` returning `SaveCryptoFailure` unconditionally. |
| `1f99a78` | Task 2.2 + 2.3: real `save_block` implementation + first integration test (round-trip insert through `read_block`). New helpers: `clone_inner_bundle()` (explicit field-by-field IdentityBundle copy — the bundle deliberately doesn't derive Clone for security; this helper opts in for the brief save-time temp OpenVault construction) + `replace_manifest_and_file()` (atomic write-back of mutated manifest body + envelope). |
| `9fbac18` | Task 2.4: 6 additional integration tests — update / empty / persists / wiped-manifest / wiped-identity / cfg(unix) failure-invariant (chmod read-only, assert in-memory state unchanged). |

### Test counts at session close

| Surface | Baseline (post-PR-#33) | After this session | Delta |
|---|---|---|---|
| `cargo test --release --workspace` | 552 + 9 ignored | 569 + 9 ignored | +17 |
| `cargo clippy --release --workspace -- -D warnings` | clean | clean | — |
| `cargo fmt --all -- --check` | OK | OK | — |
| `pytest` (PyO3) | 40 | 40 | — (PyO3 surface untouched) |
| Conformance / spec freshness | PASS | PASS | — |
| Swift smoke / Kotlin smoke | 22 / 23 | 22 / 23 | — (uniffi surface untouched) |

### Bridge save_block integration tests

The 7 new tests live at `ffi/secretary-ffi-bridge/tests/save_block.rs`:

1. `save_block_insert_round_trips_through_read_block` — save → read returns identical text + bytes
2. `save_block_update_replaces_existing_entry_and_advances_clock` — same uuid replaces; `created_at_ms` preserved
3. `save_block_with_empty_records_succeeds` — empty `records` vec is allowed
4. `save_block_persists_to_disk_visible_to_fresh_open` — save → drop handles → re-open → block visible + readable
5. `save_block_on_wiped_manifest_returns_corrupt_vault` — typed error with "manifest" in detail
6. `save_block_on_wiped_identity_returns_corrupt_vault` — typed error with "identity" in detail
7. `save_block_failure_leaves_in_memory_manifest_unchanged` (cfg(unix)) — chmod read-only, save fails, manifest in-memory state unchanged

### Other in-passing fixes

- Updated CLAUDE.md ("Memory hygiene" section) to mark `RecordFieldValue` zeroize gap as closed (PR #16 already shipped the wrap; the doc was stale). CLAUDE.md is gitignored — fix is local-only.
- Updated stale variant-count comments in `ffi/secretary-ffi-bridge/src/error.rs` ("6-variant" → "8-variant") and `ffi/secretary-ffi-uniffi/src/errors.rs` ("7 variants" → "8 variants").

## What's next (binding flavors + docs)

The plan at `docs/superpowers/plans/2026-05-09-ffi-b4c-save-block.md` covers all of this in detail. Roughly:

| Task | Scope | Estimated effort |
|---|---|---|
| 2.5 | Add proptest for save_block round-trip (~30 LOC; cheap) | 30 min |
| 3.1 | uniffi `SaveCryptoFailure` variant pin test in `errors.rs` (the From-impl arm + Rust enum variant + UDL line are already in place from Task 1.1's atomic-introduction commit) | 15 min |
| 3.2 | uniffi save_block namespace fn — UDL declaration + Rust impl. Most complex remaining piece. The UDL adds `BlockInput`/`RecordInput`/`FieldInput` dictionaries + `FieldInputValue` tagged enum + the `save_block` namespace fn declaration. The Rust impl in `namespace.rs` converts uniffi-side flat types to bridge `SecretString` / `SecretBytes` wrappers and calls `secretary_ffi_bridge::save_block`. | 1.5–2 hr |
| 3.3 | Swift smoke tests (4 tests). Need to find and read the existing smoke harness invocation first. | 45 min |
| 3.4 | Kotlin smoke tests (4 tests, parallel structure). | 45 min |
| 4.2 | PyO3 surface — `#[pyclass]` for `PyBlockInput` / `PyRecordInput` / `PyFieldInput` / `PyFieldInputValue` + `#[pyfunction] save_block` + module registration. The exception class `VaultSaveCryptoFailure` and its From-impl arm are already in place from Task 1.1. | 1.5 hr |
| 4.3 | pytest (10 tests). Apply maturin/uv cache nuclear reset before adding (per the auto-memory note); the existing `fresh_open_vault` helper for B.4b's pytest file may need adapting. | 1 hr |
| 5 | Docs — README "Where we are", ROADMAP B.4c entry, NEXT_SESSION.md (rolls forward to B.4d), handoff under `docs/handoffs/`. NEXT_SESSION.md must ride inside the PR per the feedback memory. | 30 min |
| PR | Push branch + open PR titled `feat(ffi-b4c): save_block end-to-end through bridge + PyO3 + uniffi` | 5 min |

**Acceptance counts at session close (post all of the above):** 570+ cargo, 50+ pytest, 26+ Swift, 27+ Kotlin, clippy/fmt clean, conformance/freshness PASS.

## Open decisions / risks

### Risk: stale plan against current code

The plan at `docs/superpowers/plans/2026-05-09-ffi-b4c-save-block.md` was written before I'd read every relevant core type. Real bugs found mid-execution:

1. CLAUDE.md said `RecordFieldValue::{Text(String), Bytes(Vec<u8>)}` was the v2 gap — actually already closed (PR #16). The plan's Task 1.2 had the bridge add a NEW `SecretString` newtype; in reality it should re-use core's existing one. (Fixed: bridge `BlockInput` etc. now use `secretary_core::crypto::secret::{SecretString, SecretBytes}` directly.)
2. The plan's `BlockPlaintext` field shape was wrong (`created_at_ms`/`last_mod_ms`/`trash` don't exist; `block_version`/`schema_version` do). (Fixed: `BlockInput::into_block_plaintext` matches actual core shape.)
3. The plan's `Record.fields` was assumed to be `Vec<RecordField>` — actually `BTreeMap<String, RecordField>` (the field name is the map key, NOT a struct field). (Fixed: `RecordInput::into_core_record` builds the BTreeMap correctly with last-write-wins on duplicate names.)
4. `IdentityBundle` deliberately doesn't derive Clone (security design). The plan assumed it could be cloned. (Fixed: added `clone_inner_bundle()` with explicit field-by-field copy + `Sensitive::new` for each secret. Documented the brief temp-doubling of secret material.)
5. The plan's task structure said "Task 4.1: register VaultSaveCryptoFailure in pymodule" — that's done in Task 1.1 because the variant introduction is atomic across crates (otherwise the workspace doesn't build).

The remaining tasks (3.x, 4.x) may have similar plan-vs-reality discrepancies. **Read core / uniffi / PyO3 surfaces before pasting plan code; treat the plan as a sketch, not a recipe.**

### Risk: Swift / Kotlin smoke harness not yet inspected

Tasks 3.3 / 3.4 reference an existing Swift / Kotlin smoke harness from B.4b. **I haven't yet read its invocation pattern.** Before adding the 4 + 4 new tests, find:

```bash
find ffi/secretary-ffi-uniffi -name "*.swift" -o -name "*.kt" -o -name "*.sh" | head -10
cat ffi/secretary-ffi-uniffi/README.md
```

The PR-#31 commit message ("expose folder-based read_block through PyO3 + uniffi via shared bridge crate") covers the shape. The Plan at `docs/superpowers/plans/2026-05-09-ffi-b4c-save-block.md` Task 3.3 Step 1 has the discovery instruction.

### Risk: re-opening within the same test process can hit Argon2id cost

Each `fresh_writable_vault()` call costs ~1s (Argon2id at vault-creation strength). With 7 integration tests that's ~7s of test time. Acceptable for now; if pytest test count + Argon2id cost gets unwieldy, consider per-test-suite fixture sharing.

### Decision pending: should the proptest live in inline `mod tests` of `save/orchestration.rs` or in `tests/save_block.rs`?

Inline keeps it closer to the implementation; `tests/` matches the existing integration-test structure. Default (per plan) is inline; reconsider if proptest needs the same `fresh_writable_vault` fixture (which lives in tests/save_block.rs).

### Manifest re-sign cost (carried from spec §10)

Each save_block does ~5ms of Ed25519 + ML-DSA-65 signing for the manifest re-sign. Not measured this session. Capture as a follow-up GitHub issue if not done by end of B.4c.

## Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git checkout feat/ffi-b4c-save-block
git log --oneline -10  # Should show this session's 9 commits + the PR-#33 base

# Verify baseline:
cargo test --release --workspace 2>&1 | grep -E "^test result:" | python3 -c "
import sys, re
p=f=i=0
for line in sys.stdin:
    m = re.search(r'(\d+) passed.*?(\d+) failed.*?(\d+) ignored', line)
    if m: p+=int(m.group(1)); f+=int(m.group(2)); i+=int(m.group(3))
print(f'TOTAL: {p} passed; {f} failed; {i} ignored')"
# Expect: TOTAL: 569 passed; 0 failed; 9 ignored

cargo clippy --release --workspace -- -D warnings  # clean
cargo fmt --all -- --check                          # OK

# Continue with Task 2.5 (proptest) or skip to Task 3 (uniffi).
# Plan: docs/superpowers/plans/2026-05-09-ffi-b4c-save-block.md
```

## Closing inventory

- **Branch:** `feat/ffi-b4c-save-block` (NOT pushed yet; preserves work locally)
- **Total commits since branch base:** 9 (2 docs + 7 code/test commits)
- **Workspace tests:** 569 + 9 ignored (was 552 + 9; +17 from this session)
- **Pytest:** 40 (unchanged)
- **Swift smoke / Kotlin smoke:** 22 / 23 (unchanged)
- **Bridge integration tests for save_block:** 7
- **Bridge inline tests added:** 10 (1 SaveCryptoFailure + 6 input-types + 2 signer_secret_keys + 1 snapshot_for_save_block)
- **Files created:** `save/mod.rs`, `save/input.rs`, `save/orchestration.rs`, `tests/save_block.rs`
- **Files modified:** `error.rs` (variant), `identity.rs` (signer + clone), `vault.rs` (snapshot + replace), `lib.rs` (re-exports), uniffi `errors.rs` + `secretary.udl` (variant mirror), PyO3 `lib.rs` (exception class)
