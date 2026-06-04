# NEXT_SESSION.md — D.1.10 ✅ revoke primitive (`revoke_block_recipient`, frozen-`core`, closes #177)

**Session date:** 2026-06-04 → 2026-06-05 (D.1.10 — the revoke / unshare primitive the whole D.1.6–D.1.9 share track was building toward). Authored spec + plan via `superpowers:brainstorming` → `superpowers:writing-plans`, executed all 8 tasks via `superpowers:subagent-driven-development` (fresh implementer per task + a spec-compliance review + a code-quality review after each + a final whole-branch security review).
**Status:** D.1.10 ✅ complete on branch `feature/d110-revoke`; **PR opened, not yet merged.** Full automated gauntlet **green**. Final whole-branch security review: **APPROVE on all 7 invariants**, zero security issues. This is a **frozen-`core` (Sub-project A/B) change**, not a D-phase UI slice — it implements the [#177](https://github.com/hherb/secretary/issues/177) primitive that every prior share slice noted was "deferred — needs a core primitive that does not exist." **No manual GUI smoke is required this session** (there is no UI in this slice — that's D.1.11).

## (1) What we shipped this session

`revoke_block_recipient` — the **inverse of `share_block`**. A user with an unlocked vault (the block's single-owner author) can now remove a recipient from a shared block via a **true content-key rotation**:
- **Re-key, not just a list edit.** A fresh block content key (BCK) is generated, the body is re-encrypted under it, and fresh §6.2 recipient wraps are produced for the **remaining** recipients only. The revoked party's wrap is absent from the new block, so they cannot decrypt any **future** version (forward-only — they keep whatever they already saw; documented as a boundary, not a bug).
- **Shared re-key engine.** `share_block`'s steps 7–18 (decrypt-as-author → fresh BCK → re-wrap → re-sign Ed25519 ∧ ML-DSA-65 → atomic block-then-manifest write) were extracted into a private `rewrite_block_with_recipients(...)` helper, parameterised by the final recipient set + an `Option<card_to_persist>` (share passes `Some`, revoke `None`). `share_block` was refactored onto it **behavior-preservingly** (the existing share suite is the guard). The "both halves sign / both halves wrap" property is now implemented once.
- **`CannotRevokeOwner` fail-fast guard (the design fix this session).** The original spec wrongly claimed the owner is never a recipient; in fact the owner is **always** a recipient (`share_block` decrypts under the author's reader identity and fails `NotARecipient` otherwise — and §6.2 rejects an owner-less recipient table as malformed). Revoking the owner would re-key the block **without** them and return a deceptive `Ok`, **bricking** it (no future re-key/re-share possible). The primitive now rejects `revoked_recipient_uuid == owner_uuid` **before any write** with a typed `CannotRevokeOwner`. Revoke-to-empty is therefore impossible (the owner always remains; "revoke the last recipient" = the last *non-owner*).
- **delete ≠ revoke stays honest, now with a real revoke.** Revoke drops the uuid from `manifest.BlockEntry.recipients`, so `shared_block_count` falls and the D.1.9 reverse map reflects it automatically. The contact card in `contacts/` is **not** deleted (a contact may receive other blocks; card deletion is the separate D.1.7 concern).
- **Bridge surface (bridge-only, per [#167](https://github.com/hherb/secretary/issues/167)).** `revoke_block` (orchestration) + `revoke_block_from` (contacts-by-uuid) mirror the share wrappers exactly — same zeroize discipline (byte-for-byte), same exhaustive `VaultError → FfiVaultError` mapping (no `_ =>` catchall), same mutation-path strictness (nothing swallowed). `revoke_block_from` reuses the both-halves-`verify_self` card loader (a card swapped on disk after import is rejected).
- **Two new typed errors threaded EVERYWHERE.** `RecipientNotPresent` + `CannotRevokeOwner` on `VaultError` → `FfiVaultError` → UDL → pyo3 → uniffi → desktop `AppError`/`map_ffi_error` → the conformance KAT helper **and** the Swift + Kotlin conformance harnesses. The UDL variants regenerated the Swift/Kotlin bindings, making their harness `switch`/`when` non-exhaustive — **a compile failure `cargo`/`clippy` cannot see, caught by the gauntlet** (see §(3b)).
- **Spec + clean-room proof.** `vault-format.md` §6.5.1 (revocation = re-key + drop recipient; same on-disk format, **no `format_version` bump**; owner always a recipient & cannot be revoked; forward-secrecy boundary) + `crypto-design.md` §7.3 (share AND revoke rotate the BCK; forward-only). A stdlib-only `conformance.py` `section_revoke_kat()` proves from `docs/` + the committed fixture alone that the revoked wrap is gone, the remaining recipient decaps+decrypts under the **new** BCK to the expected plaintext, and the body ciphertext changed (real re-key). A deterministic Rust KAT (`core/tests/data/revoke_kat/`) + an always-run guard pin it on every `cargo test`.

**Architecture: frozen-`core` change with full crypto rigor.** On-disk format unchanged (a revoke emits the same §6.1/§6.2 bytes as a share to a smaller set). The §9 block-first → manifest-second atomic order is preserved. `#![forbid(unsafe_code)]` holds (the only `unsafe` tokens added are two new `#![forbid(unsafe_code)]` attributes on the revoke modules).

Key commits on `feature/d110-revoke` (branched from `main` @ `862d51f`):

| Commit | What it landed |
|---|---|
| `ad9d11d` / `92b8d93` | D.1.10 design spec + 8-task implementation plan. |
| `3ff2f9e` (+`e808a12`) | **T1** — extract `rewrite_block_with_recipients` from `share_block` (behavior-preserving; share suite is the guard). |
| `d8ed7dc` (+`bdb620d`) | **T2** — typed `RecipientNotPresent` threaded through every workspace match site. |
| `8c7569d` | **T3** — `revoke_block_recipient` happy paths (round-trip, last-recipient→owner-only, re-sign verifies, manifest shrink). |
| `9cc00c6` | **spec correction** — owner is always a recipient; add `CannotRevokeOwner`; revoke-to-empty impossible. |
| `407bd23` (+`fbf5c36`) | **T3** — fail-fast `CannotRevokeOwner` guard + the error threaded across all 9 match sites + `revoke_block_owner_rejected`. |
| `3b98550` (+`1295dd9`) | **T4** — error-path tests (NotFound, NotAuthor, RecipientNotPresent vs MissingRecipientCard ordering). |
| `e2a57e9` (+`c851b27`) | **T5** — bridge `revoke_block` / `revoke_block_from` + full `revoke_block_from` coverage (happy, BlockNotFound, card-swap regression, ContactNotFound). |
| `45c826a` | **T6** — `vault-format` §6.5.1 + `crypto-design` §7.3 (revocation + forward-secrecy). |
| `dcad685` (+`353fc61`) | **T7** — deterministic revoke KAT fixture + generator + always-run guard. |
| `25c3d2a` (+`eb05402`) | **T8** — `conformance.py` `section_revoke_kat()` clean-room verifier + freshness citations. |
| `a7a9e26` | **gauntlet fix** — Swift + Kotlin conformance harnesses made exhaustive for the two new error variants (back to 22/22). |
| `db08e97` | review fix — operation-neutral manifest-write error context in the shared helper. |
| `57b8c38` | docs — README/ROADMAP marked D.1.10 ✅, "next" advanced to D.1.11. |
| _(ship)_ | this handoff + symlink retarget. |

**Process note:** one worktree (`.worktrees/d110-revoke`), one reviewed commit per task + inline review-fix commits. **One design escalation mid-flight** (the owner-revoke footgun) was surfaced to the user, resolved as a new typed guard, and the spec corrected before continuing — exactly the "Rust change reveals spec ambiguity → resolve explicitly" path. Every per-task spec + quality finding was fixed before proceeding.

### Automated gauntlet (re-run clean on `feature/d110-revoke` @ HEAD)

```
Rust:        PASSED 1189 FAILED 0 IGNORED 11   (+17 over the D.1.9 baseline of 1172:
             core revoke happy+error+owner tests, the revoke KAT guard, bridge
             revoke + revoke_block_from tests, the FFI error-mapping tests)
cargo clippy --release --workspace --tests -- -D warnings   → clean
cargo fmt --all -- --check                                  → clean
uv run core/tests/python/conformance.py                     → PASS  (incl. new Section R: revoke re-key)
uv run core/tests/python/spec_test_name_freshness.py        → PASS  (101 resolved / 0 unresolved)
Swift conformance:   22/22 PASS   (harness made exhaustive for the 2 new variants)
Kotlin conformance:  22/22 PASS
```
(No frontend/desktop test run needed — this slice adds **no desktop UI**. The desktop `AppError` variant was threaded for exhaustiveness only.)

## (2) What's next — D.1.11 (desktop revoke UI; brainstorm to confirm)

The revoke *primitive* exists; the revoke *verb* in the desktop is now a cheap, self-contained D-slice hanging off the already-revoke-ready surfaces:
- **The D.1.8 "Shared with" banner** (per-block recipients) — an ✕ per non-owner recipient row.
- **The D.1.9 ContactRow reverse map** (per-contact blocks) — an ✕ per block a contact receives.

**Acceptance criteria (D.1.11):**
- A desktop "Revoke" action (one of the two surfaces above, or both) that calls the bridge `revoke_block_from(block_uuid, revoked_recipient_uuid)` via a new IPC command.
- A confirm-on-destructive dialog (revoke is a mutation that re-keys + re-signs — make the irreversibility-for-future-versions clear; note the forward-secrecy boundary in the copy: the former recipient keeps what they already saw).
- **The mutation path must NOT reuse the read-only display's error leniency** (carried from D.1.9): every failure surfaces as a typed error to the user — a transient I/O fault is fine to fold to "no blocks" for a *display*, fatal for a *revoke*. The bridge already enforces this; the desktop command + UI must too.
- The owner is never offered as a revocable recipient (the UI must not present the owner's ✕ — and even if it did, `CannotRevokeOwner` rejects it).
- After a successful revoke, the banner / reverse map refreshes (the recipient is gone; `shared_block_count` dropped).
- Manual GUI smoke against a **temp copy** of a vault (per [[feedback_smoke_test_temp_copy_golden_vault]]) — this slice *does* mutate, so the temp-copy rule is mandatory.

Author the D.1.11 plan via `superpowers:brainstorming` → `superpowers:writing-plans`; it is a pure D-phase UI slice (no `core`/bridge change — the bridge `revoke_block_from` is done), so it does **not** carry crypto-review rigor — but it IS a mutation, so treat the confirm + error-surfacing with care.

## (3) Open decisions and risks

- **#177 is now CLOSED by this PR** (the core revoke primitive shipped). Update/close it when the PR merges.
- **Deferred-FFI [#167](https://github.com/hherb/secretary/issues/167) still open** — the revoke *functions* (`revoke_block` / `revoke_block_from`) are bridge-only, NOT exposed via uniffi/pyo3. The *error variants* are exposed (they're on the shared `FfiVaultError`/UDL). Wire the functions when D.3 (mobile) or a Python consumer needs revoke.
- **FfiVaultError variant churn has a cross-language tail `cargo` can't see.** Adding a UDL error variant regenerates the Swift/Kotlin bindings; the conformance *harnesses* (`ffi/secretary-ffi-uniffi/tests/{swift,kotlin}/ConformanceErrors.{swift,kt}`) `switch`/`when` exhaustively over the error enum and break to compile errors **invisible to `cargo build`/`clippy`**. The gauntlet's Swift+Kotlin runs are the only thing that catches this. **Any future error-enum change must run the Swift + Kotlin conformance scripts** (already in the resume gauntlet below). Consider noting this in CLAUDE.md if it recurs.
- **Manual GUI smoke is N/A this session** (no UI). It returns as the D.1.11 pre-merge gate.
- **Carry-forwards, all still live:** #153 (component styles in `theme.css`), #154 (emoji→inline SVG), #161 (L4 e2e — no tauri-driver on macOS WKWebView), #162 (PathPicker e2e hook), #164 (Esc-to-pop), #170 (`lock_session` hoist into `commands::shared` — still pending), #180 (a11y `aria-controls`).

### Verified non-issues (don't re-investigate)
- **Owner can't be orphaned:** `CannotRevokeOwner` fires fail-fast before any re-key (owner uuid == `open.identity.user_uuid`); pinned by `revoke_block_owner_rejected` (asserts block+manifest+contacts byte-identical after rejection).
- **Revoked party can't read the new body:** fresh BCK, no wrap emitted for them; `revoke_block_round_trip` proves they get `NotARecipient`, and `conformance.py` Section R proves it cross-language under the documented §7 construction.
- **share_block behavior preserved by the refactor:** the full pre-existing `share_block.rs` suite passes unchanged; the helper is a verbatim extraction (the security review confirmed line-for-line).
- **No silent swallow on the mutation path:** the bridge `map_core_vault_error_revoke` is exhaustive (no catchall); zeroize parity with share is byte-for-byte.

## (3b) ⚠️ Worktree-collision warnings observed this session (non-blocking, recovered)
Three subagents reported transient stale-view / "edit reverted" / detached-HEAD symptoms (the CLAUDE.md parallel-collision signature). Each was investigated: the final branch state is **clean and linear** (verified — 22 commits from `862d51f`, no merges/branches, `git status` clean), every commit landed on `feature/d110-revoke`, and no `git reflog` recovery was needed. If you see this again on this worktree, verify `git log --graph` linearity before any destructive op (as was done here).

## (4) Exact commands to resume (D.1.11)

```bash
# Merge the D.1.10 PR first (feature/d110-revoke), then:
cd /Users/hherb/src/secretary
git fetch --prune origin
git checkout main
git pull --ff-only origin main
git log -5 --oneline           # confirm the D.1.10 ship PR landed; #177 closed

# Re-baseline the automated gauntlet on fresh main (this is the FULL gauntlet —
# the Swift/Kotlin runs are load-bearing for any error-enum change, see §3):
cargo test --release --workspace --no-fail-fast 2>&1 | grep "^test result:" | awk '$3=="ok." {p+=$4; f+=$6; i+=$8} END {printf "Rust totals → PASSED %d FAILED %d IGNORED %d\n", p, f, i}'
# Expect: PASSED 1189 FAILED 0 IGNORED 11 (D.1.10 baseline)
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
uv run core/tests/python/conformance.py            # PASS, incl. Section R
uv run core/tests/python/spec_test_name_freshness.py
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh   2>&1 | tail -1   # 22/22
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh  2>&1 | tail -1   # 22/22
cd desktop && pnpm install && pnpm test && pnpm typecheck && pnpm svelte-check 2>&1 | tail -3 && pnpm lint && cd ..

# Author the D.1.11 plan (desktop revoke UI on the D.1.8 banner / D.1.9 ContactRow):
#   superpowers:brainstorming  → confirm which surface(s) get the Revoke ✕
#   superpowers:writing-plans  → mirror docs/superpowers/plans/2026-06-04-d110-revoke-block-recipient.md

# Then the first implementation worktree:
git worktree add .worktrees/d111-<slug> -b feature/d111-<slug> main
cd .worktrees/d111-<slug>/desktop && pnpm install
```

### Housekeeping (after the D.1.10 PR merges)
```bash
cd /Users/hherb/src/secretary
git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/d110-revoke 2>/dev/null && git branch -D feature/d110-revoke 2>/dev/null
git worktree prune && git worktree list
```

## (5) Handoff file model

`NEXT_SESSION.md` at the repo root is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Author the handoff once; the symlink is a pointer. To open D.1.11: author `docs/handoffs/<date>-d111-*.md` and `ln -snf docs/handoffs/<new>.md NEXT_SESSION.md`, committing both on the feature branch (per [[feedback_next_session_in_pr]]).

## Closing inventory

- **Branch on close:** `main` @ `862d51f`. `feature/d110-revoke` carries the spec + plan + 8 task commits + inline review-fix commits + the spec-correction (owner guard) + the gauntlet harness fix + docs + the ship commit (this handoff + symlink). Squash-merge collapses to one commit on `main`.
- **Automated gauntlet:** Rust **1189 / 0 / 11**; clippy clean; fmt clean; conformance PASS (incl. Section R); freshness 101/0; Swift 22/22; Kotlin 22/22.
- **Final whole-branch security review:** **APPROVE** on all 7 invariants (share refactor preserved behavior; both-halves sign/wrap; owner guard fail-fast; author-only/single-owner; no silent swallow; zeroize/no-unsafe; forward-secrecy documented + format unchanged). Adversarial pass found no brick/leak/forge/atomicity hole. Two Minor cosmetic notes (one fixed: neutral error string; one no-action: block-path recompute is equal-or-more-correct).
- **PR:** opened against `main` (`feature/d110-revoke`). No manual GUI smoke gate (no UI this slice).
- **README.md / ROADMAP.md:** D.1.10 ✅ (revoke primitive, closes #177); D.1.11 (desktop revoke UI) next.
- **CLAUDE.md / `docs/adr/`:** unchanged (no new architecture decision; the on-disk format is unchanged — revoke is a new *operation* over the frozen format, not a format change).
- **Issues:** #177 closed by this PR. #167 (FFI function exposure) stays open. No new issues filed.
- **NEXT_SESSION.md:** symlink retargeted to this file.
- **This file:** the live D.1.10 ship baton. The next slice opens with `docs/handoffs/<date>-d111-*.md`.
