# Post-PR-24 SHA-record cleanup (micro-session)

**Session date:** 2026-05-04 (post-merge fix-up on `main`)
**Status:** PR [#24](https://github.com/hherb/secretary/pull/24) was already squash-merged to `main` as `4d0fffc`, and `cedaccc` had landed the issue-#23 cargo-fmt sweep on top. This session was the post-merge SHA-record fix-up matching the same pattern that `36850ec` followed for PR #22 — fill in the squash-merge SHA in the live `NEXT_SESSION.md` and the archived handoff copy, refresh stale numbers, and tidy two open carry-overs.

## (1) What we shipped this session

| Action | Output |
|---|---|
| Verified post-merge gates on `main` | 479 cargo + 9 ignored, clippy `-D warnings` clean, `cargo fmt --all -- --check` exit 0, 10 pytest, conformance + freshness PASS, 7/7 Swift, 7/7 Kotlin |
| **Stale-dylib note (caught and recorded)** | First pytest run reported 7 failures (`AttributeError: module 'secretary_ffi_py' has no attribute 'open_with_password'`). Hash compare of `target/maturin/libsecretary_ffi_py.dylib` vs the venv's `secretary_ffi_py.cpython-312-darwin.so` matched (`7ed7343…`), so this wasn't the uv editable-install cache trap from the existing memory — this was both artifacts simply being older than current `main`. Running `( cd ffi/secretary-ffi-py && uv run maturin develop --release --uv )` rebuilt them in step with the merged source, after which all 10 pytests pass. The "Exact commands to resume" block now bakes that `maturin develop` step in before pytest. |
| **Test-count drift investigated** | NEXT_SESSION.md cited 477 + 9; actual is 479 + 9. The +2 came from `secretary-ffi-bridge` having 22 unit tests (11 in `error.rs` + 7 in `identity.rs` + 4 in `unlock.rs`), not the rounded-down "20" the closing inventory recorded. Records-only fix; no real test growth post-merge. |
| **`NEXT_SESSION.md` and `docs/handoffs/2026-05-04-b2-vault-unlock.md` edited in lock-step** | Status line flipped from "PR #24 open / merged" → "squash-merged as `4d0fffc`"; the table's `(this commit)` placeholder filled with `959ef1b` (then squash-merged as `4d0fffc`); two new rows added for the post-merge `cedaccc` (issue #23 close) and this commit's SHA-record fix-up; test counts 477 → 479; bridge-crate inventory line 20 → 22; #23 line struck-through with closure note; resume commands updated to include the maturin rebuild step + `cargo fmt --all -- --check`; routine status flipped from "Decide in the next session" → "Disabled". |
| **Top-level `README.md` + `ROADMAP.md` test counts** | 477 → 479 (and the matching "20 from the new bridge crate" → "22 from the bridge crate"). |
| **Companion routine `trig_018gYtGpiycgLXqUsDpV2NZD` retired** | `RemoteTrigger { action: update, body: { enabled: false } }` flipped the routine's `enabled` to `false` (HTTP 200). Programmatic delete isn't supported by the `RemoteTrigger` tool; the user can delete fully via https://claude.ai/code/routines/trig_018gYtGpiycgLXqUsDpV2NZD if desired. |
| **Fresh handoff** | This file — `docs/handoffs/2026-05-04-post-pr24-cleanup.md`. |

### Verification at session close

| Check | Result |
|---|---|
| `cargo test --release --workspace` | **479 passed + 9 ignored, 0 failed** |
| `cargo clippy --release --workspace -- -D warnings` | clean |
| `cargo fmt --all -- --check` | exit 0 |
| `uv run --directory ffi/secretary-ffi-py pytest` | **10 passed** (after `maturin develop --release --uv`) |
| `uv run core/tests/python/conformance.py` | **PASS** |
| `uv run core/tests/python/spec_test_name_freshness.py` | **PASS** |
| `bash ffi/secretary-ffi-uniffi/tests/swift/run.sh` | **7/7 PASS** |
| `bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh` | **7/7 PASS** |

## (2) What's next

Sub-project B.3 — `open_with_recovery` + `create_vault` exposed across PyO3 + uniffi via the bridge crate. The full B.3 brainstorm prompt, design questions, and acceptance criteria carry forward unchanged in `NEXT_SESSION.md` §(2) and §(3); read the deferred-items section of [`docs/superpowers/specs/2026-05-04-ffi-b2-vault-unlock-design.md`](../superpowers/specs/2026-05-04-ffi-b2-vault-unlock-design.md) before invoking `/brainstorm`.

## (3) Open decisions and risks

None new from this micro-session. The four B.3 design questions (mnemonic input shape, `WeakKdfParams` reachability, recovery-mnemonic output handling, error-variant count) carry forward in `NEXT_SESSION.md`.

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git checkout main
git pull --ff-only

# Verify post-merge state:
cargo test --release --workspace
cargo clippy --release --workspace -- -D warnings
cargo fmt --all -- --check

# Rebuild maturin dylib BEFORE pytest (else AttributeError on B.2 symbols):
( cd ffi/secretary-ffi-py && uv run maturin develop --release --uv )

uv run --directory ffi/secretary-ffi-py pytest
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh

# Then: /brainstorm  (for B.3)
```

## Closing inventory

- **Branch:** `main` (no feature branch this session — direct fix-up commit on `main`)
- **Workspace tests:** 479 + 9 ignored (was reported as 477 + 9 at PR #24 close — that was an undercount of the bridge crate's unit tests)
- **PR:** none — direct commit on `main` matching the `36850ec` precedent.
- **Open issues:** none.
- **Companion routine** `trig_018gYtGpiycgLXqUsDpV2NZD` is now disabled. The next-uniffi-major watch can be re-enabled or replaced when relevant.
