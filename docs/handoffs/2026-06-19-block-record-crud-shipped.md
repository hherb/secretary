# NEXT_SESSION.md — Block CRUD tier ✅ (SHIPPED — all gates green; PR open)

**Session date:** 2026-06-19. Flow: `/nextsession` → prior baton (#261 FFI secret-residue fix, PR #265) had already been **squash-merged** (`main` @ `0a0e5f92`) → housekeeping (removed the merged `261-udl-take-secret-bytes` worktree + branch; left `hardcore-robinson` / `d4-browser-autofill` untouched) → chose the carried follow-up **Block CRUD tier** (create/rename block + move record between blocks) → brainstorm → spec → plan → subagent-driven execution (5 tasks, fresh implementer + two-stage review each, final whole-branch review) → this handoff.

**Status:** ✅ **code-complete; full gauntlet green.** Branch `feature/block-record-crud` (worktree `.worktrees/block-record-crud`). **`core/` and the on-disk format / crypto spec are untouched** — this is an FFI-surface (bridge + uniffi) change only. **PR not yet opened at time of writing** — see §4 to push + open it (or it is open if this baton was committed as part of the PR).

## (1) What we shipped this session

Three new write ops on the **uniffi** surface, composing the existing `core::vault::save_block` via the bridge's shared `save_plaintext` tail. The whole surface stays **caller-mints-UUIDs + void returns** (consistent with `append_record`).

| Op | What it does |
|---|---|
| **`create_block`** | Expose the pre-existing bridge `create_block` (empty block, caller-minted `block_uuid`) on the uniffi surface. |
| **`rename_block`** | New bridge primitive (`edit/rename.rs`): change ONLY `block_name`; every record + block/record/field `unknown` preserved. |
| **`move_record`** | New bridge primitive (`edit/move_record.rs`): **faithful move** — copy a live record into a target block under a caller-minted **fresh `record_uuid`** (preserving `created_at_ms`, per-field `last_mod`/`device_uuid`, values, and all `unknown`; only `record_uuid` + record-level `last_mod_ms` are fresh), then tombstone the source. **Copy-before-delete**: decrypt target before any write (missing target → `BlockNotFound`, source left LIVE); save target first, tombstone source second (reuses `tombstone_record`). |

**Layers:** bridge primitives (`ffi/secretary-ffi-bridge/src/edit/{rename,move_record}.rs` + shared `edit/test_support.rs`); uniffi wrappers + UDL (`ffi/secretary-ffi-uniffi/src/namespace/block_crud.rs`, `secretary.udl`); Swift+Kotlin smoke (`SmokeBlockCrud.{swift,kt}`). Spec + plan under `docs/superpowers/`.

**Branch commits** (squash-merge collapses to ONE commit on `main`; branched from `main` @ `0a0e5f92`):
`84ac50ea` spec · `759b0ca8` plan · `54df06d6` rename_block · `204df84f` move_record(v1) · `e67d096b` docs faithful-move align · `67360db9` move_record caller-mints+void · `b4ce0c23` move_record comment fix · `d1316ffb` uniffi expose 3 ops · `fe194f37` Swift+Kotlin smoke · `d4a658b` smoke uuid-assert + symmetric test · + the docs/handoff commit carrying this file.

### Acceptance (full gauntlet — ALL GREEN this session)
```
# From the worktree root (.worktrees/block-record-crud):
cargo test --release -p secretary-ffi-bridge -p secretary-ffi-uniffi   # 144 bridge + 55 uniffi + integration, 0 failed
cargo clippy --release --workspace --tests -- -D warnings              # clean
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh           # 27/27
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh          # 27/27
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh                       # OK: all assertions passed (incl. block-CRUD)
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh                      # OK: all assertions passed (incl. block-CRUD)
( cd android && ./gradlew :kit:test )                                  # BUILD SUCCESSFUL
bash ios/scripts/run-ios-tests.sh                                      # TEST SUCCEEDED — 172 tests, 0 failures

# Guardrail (core/spec untouched):
git diff main...HEAD --name-only | grep -E 'core/|crypto-design|vault-format'   → empty
```

### Deliberate decisions (so a future reader doesn't "fix" them)
- **Faithful move, not fresh-authorship.** The moved copy PRESERVES `created_at_ms` + per-field `last_mod`/`device_uuid` (the secret's age + per-field authorship survive a move). CRDT-safe because the fresh `record_uuid` means the copy never field-merges against the original. (The initial spec said "reset to now_ms"; the user chose faithful move — spec + plan updated to match in `e67d096b`.)
- **Caller-mints `new_record_uuid`, `move_record` returns void.** Consistent with `append_record`/`BlockInput`. (The first implementation minted internally and returned the uuid; reverted in `67360db9`.)
- **Same-block (`source==target`) + uuid-length checks live at the uniffi WRAPPER**, returning the existing `VaultError::InvalidArgument`. The bridge `move_record` trusts its caller (no guard) — exactly as the bridge trusts `[u8;16]` lengths. **NO new `FfiVaultError` variant.** (A first attempt added one + threaded it through 5 crates incl. pyo3/desktop/`core/` test helpers — fully reverted in `820cf5fc`/`204df84f`; see [[project_secretary_ffivaulterror_workspace_match]].) **Consequence:** if/when pyo3 projects these ops, it MUST add its own same-block guard (the bridge has none).
- **No README change.** README documents the write surface only at the architecture level, never op-by-op; the ROADMAP entry is the record. ROADMAP updated (Sub-project B, Block-CRUD tier ✅ 2026-06-19).

## (2) What's next
- **Open + squash-merge the PR** (§4), then housekeeping (remove this worktree + branch).
- **pyo3 projection of the three ops** — explicitly deferred this session ("we can do pyo3 later"). When added: wrap `create_block`/`rename_block`/`move_record` in `secretary-ffi-py`, add the same-block guard there (the bridge doesn't), mirror the wrapper uuid-length validation. **Acceptance:** pytest round-trip for each op + same-block→ValueError.
- **Wire the three ops into a UI** — they are FFI-only now (no iOS/Android/desktop affordance). Natural next: an Android/iOS "move record to another block" + "new/rename folder" affordance over the existing browse/edit infra. **Acceptance:** on-device create→move→read-back round-trip through the platform UI.
- **iOS biometric re-auth before a write** — separate follow-up (ROADMAP C.3 remaining).
- **On-device sync veto round-trip** still needs a seeded concurrent state ([[project_secretary_sync_veto_needs_seeded_state]]).

**Open follow-up issues (carried):** #224 / #234 / #192 / #193 / #190 / #189 / #186 / #161 / #162 / #167 / #251 / #252 / #255. (#251 — block-plaintext residency — is the decrypted-block lifetime, distinct from this slice.)

## (3) Open decisions and risks
- **No on-device run for the new ops.** They are pure vault-file logic (no enclave/biometric); the real generated bindings are exercised by the Swift+Kotlin smoke + conformance harnesses on both languages, plus the full iOS XCTest suite + Android `:kit` host build. A device smoke would add no signal the harnesses don't already give (the user chose host-only acceptance).
- **Transient duplicate on a crash mid-move.** A crash strictly between the target save and the source tombstone leaves the record live in BOTH blocks (the copy committed, the source not yet tombstoned). This is recoverable-by-design (re-run the move, or a later move/tombstone reconciles); no data loss. The reverse order (tombstone-first) would lose data on a crash and is rejected. Verified clean against the actual `save_plaintext`/`tombstone_record`/`decrypt_block_plaintext` primitives in the final whole-branch review.
- **Bridge `move_record` accepts same-block if called directly** (it would copy-then-tombstone within one block). Harmless (no corruption) but nonsensical; the uniffi wrapper rejects it. A direct bridge or future pyo3 caller is responsible for the guard.

## (4) Exact commands to resume
```bash
# This worktree (where the work is):
cd /Users/hherb/src/secretary/.worktrees/block-record-crud
pwd && git branch --show-current   # expect feature/block-record-crud

# Re-run the gauntlet (all green this session):
cargo test --release -p secretary-ffi-bridge -p secretary-ffi-uniffi
cargo clippy --release --workspace --tests -- -D warnings
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh
( cd android && ./gradlew :kit:test )
bash ios/scripts/run-ios-tests.sh
git diff main...HEAD --name-only | grep -E 'core/|crypto-design|vault-format'   # empty

# Push + open the PR (if not already done):
git push -u origin feature/block-record-crud
gh pr create --title "Block CRUD tier: create/rename block + move record between blocks" --body "<summary>"

# After merge, housekeeping (from the MAIN checkout):
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/block-record-crud && git branch -D feature/block-record-crud
git worktree prune && git worktree list   # leaves hardcore-robinson + d4-browser-autofill
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Authored once; the symlink is the pointer. `origin/main` did NOT move during this session (still `0a0e5f92`, the branch point), so the symlink retarget + this new handoff file merge cleanly. Both ride in the PR ([[feedback_next_session_in_pr]]). If you resume this branch for fixups, first `git fetch origin && git merge origin/main` (branch-version-wins on the handoff path) before editing ([[feedback_next_session_main_authoritative]]).

## Closing inventory
- **Branch on close:** `feature/block-record-crud` (worktree); branched from `main` @ `0a0e5f92`. Squash-merge → one commit on `main`.
- **Acceptance:** green — cargo (bridge 144 + uniffi 55 + integration), clippy `-D warnings` clean, Swift+Kotlin conformance 27/27 each, both smoke runners, Android `:kit` host, full iOS XCTest (172 tests, 0 failures). Guardrail empty (no `core/` / spec change).
- **README.md / ROADMAP.md:** ROADMAP updated (Block-CRUD tier ✅ 2026-06-19); README unchanged (never documented the write surface op-by-op).
- **NEXT_SESSION.md:** symlink retargeted to this file.
