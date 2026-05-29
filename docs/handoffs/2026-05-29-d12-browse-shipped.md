# NEXT_SESSION.md — D.1.2 ✅ read-only browse (block detail + field reveal)

**Session date:** 2026-05-29 (D.1.2 — the second Sub-project D feature slice, built on the D.1.1 walking skeleton). Authored spec + plan, then executed all 6 implementation tasks via subagent-driven development (fresh implementer per task + two-stage spec/quality review + a final whole-branch review).
**Status:** D.1.2 ✅ complete on branch `feature/d12-browse`; **PR pending** (see §(4)). All automated gates green. The one human gate left is the **manual GUI smoke** (§(3)) — it cannot run headless.

## (1) What we shipped this session

A user with an unlocked vault can now **browse read-only**: click a block → see its records (labelled by non-secret metadata) → click a record → see masked fields → reveal a field (lazy, stateless re-decrypt) → it auto-hides after 20 s → copy it (clipboard auto-clears after 30 s) → back-navigate at each level → and a vault lock clears any revealed state. Still strictly read-only (no create/edit/share).

All commits are on `feature/d12-browse` (branched from `main` @ `861d2de` via a `feature/d12-spec` base; the spec + plan ride on the same branch, so the ship PR carries everything):

| Commit | What it landed |
|---|---|
| `d83248d` | D.1.2 design spec (`docs/superpowers/specs/2026-05-29-d12-browse-design.md`, 16 sections, mirrors D.1.1) |
| `60adf01` | D.1.2 implementation plan (`docs/superpowers/plans/2026-05-29-d12-browse.md`, 6 tasks) |
| `9f2d90c` | **Task 1** — `dtos/` module split + browse DTOs (`BlockDetailDto`/`RecordDto`/`FieldMetaDto`/`RevealedFieldDto`) + pure `reveal.rs` (tombstone-filtered projection, locate-by-uuid, base64 encode that zeroizes the intermediate). Deps: `base64 = "0.22"`, `zeroize = "=1.8.2"`. |
| `b15a677` | **Task 2** — `read_block` IPC command (metadata-only DTO, tombstone-filtered, `output.wipe()`) + typed `AppError::BlockNotFound`/`RecordNotFound`/`FieldNotFound`. L3 test asserts no plaintext in the `read_block` DTO. |
| `ec7c7b1` | **Task 3** — `reveal_field` IPC command (stateless re-decrypt; `expose_text`/`expose_bytes`→base64; `output.wipe()` on **every** return path incl. errors) + L3 text-reveal tests + wire-shape tests. |
| `bd7eff5` | **Task 4** — browse-nav store (`lib/browse.ts`) + `Vault` level switch + clickable `BlockCard` + `RecordList`/`RecordRow` + `ipc.readBlock/revealField` + 3 TS error codes + `lib/format.ts` (extracted `formatShortDate`). |
| `627fde7` | **Task 5** — `FieldViewer`/`FieldRow` + reveal/mask + auto-hide + copy + pure `lib/reveal.ts` (fake-timer-tested). Revealed value lives only in component `$state`; unmount cancels timers. |
| `b951301` | **Task 6** — `tauri-plugin-clipboard-manager` registered with **write-only** capability (`clipboard-manager:allow-write-text`; no read); `vault-locked` resets browse nav so no revealed secret survives a lock. |
| (ship) | README + ROADMAP mark D.1.2 ✅; spec §12 `Esc`-deferred note (#164); this handoff + symlink retarget. |

**Process note (deviation from the plan's wording):** the plan described one worktree+branch per task; in this single-session subagent-driven run we used **one** worktree (`.worktrees/d12-browse`, branch `feature/d12-browse`) with one reviewed commit per task. Same review rigor (spec + quality review after each task, every finding fixed before proceeding), cleaner history, one PR. Per-task review findings fixed inline: Task 1 (field_count derive + locate tombstone), Task 4 (stale-state reset, typed error msg, format.ts extraction, field_not_found hint, Vault records-level test), Task 5 (unmount timer cancel + cancellable clipboard-clear + timer tests), Task 6 (comment accuracy).

### Automated gauntlet (final whole-branch review, run fresh on `feature/d12-browse`)

```
Rust:        PASSED 1069 FAILED 0 IGNORED 10   (+16 over the D.1.1 baseline of 1053)
cargo clippy --release --workspace --tests -- -D warnings   → clean
cargo fmt --all -- --check                                  → clean
uv run core/tests/python/conformance.py                     → PASS
uv run core/tests/python/spec_test_name_freshness.py        → PASS (97 resolved, 0 unresolved)

Frontend:    Vitest 231 / 0 (21 files; new: browse, reveal, RecordList, RecordRow,
             FieldViewer, FieldRow, format + additions to ipc/errors/BlockCard/Vault/App)
pnpm typecheck      → clean
pnpm svelte-check   → 267 files, 0 errors, 0 warnings
pnpm lint           → clean
```

### Secret-handling story (verified end-to-end by the final review)

- `read_block` returns **metadata only** — an L3 test asserts the golden password/username plaintext is absent from the serialized DTO.
- The **single** widening point is `RevealedFieldDto.value`, produced only on an explicit reveal click via stateless re-decrypt; `reveal_field_impl` wipes the `BlockReadOutput` on all 5 return paths.
- No secret is logged, stored, cached, or placed in the browse-nav store. Frontend holds it only in `FieldRow`'s `$state`; unmount (on mask/navigate/lock) drops it and cancels the auto-hide + clipboard-clear timers.
- Clipboard capability is **write-only** (the deliberate security choice — no clipboard read). This is the one item worth a human security glance on the PR.

## (3) ⚠️ Manual GUI smoke — the user's pre-merge gate (NOT run this session; headless)

> **⚠️ Smoke against a TEMP COPY of the vault, never the git-tracked fixture.** Opening the app against `core/tests/data/golden_vault_001/` would mutate a frozen KAT (D.1.1 stores settings *in* the vault). Copy first. See [[feedback_smoke_test_temp_copy_golden_vault]].

```bash
cd /Users/hherb/src/secretary/.worktrees/d12-browse/desktop
pnpm install
pnpm tauri build --debug
VAULT=$(mktemp -d) && cp -R ../core/tests/data/golden_vault_001/. "$VAULT/"   # disposable copy
./src-tauri/target/debug/secretary-desktop
```

Walk (spec §15): unlock (`correct horse battery staple`) → click **"Personal logins"** → see the `login` record row (type · `work` tag · "2 fields" · modified) → click it → fields masked (`username`, `password` shown as `••••••••`) → reveal `password` → shows `hunter2` → wait ~20 s → auto-re-masks → reveal + copy → paste elsewhere = `hunter2` → after ~30 s clipboard cleared → `←` back works at each level → **lock mid-reveal → returns to Unlock with no plaintext visible**. If any step fails it's a D.1.2 regression; don't merge until fixed. (The automated gauntlet is green, so a smoke failure would point at a real WebView/IPC/CSP/runtime issue the unit tests can't reach — exactly what the deferred L4 e2e #161 would catch automatically.)

## (2) What's next — D.1.3 (vault create wizard)

D.1.2 reads existing vaults. D.1.3 lets a user **create** a new vault from the desktop app — the first *write* slice. This makes the D.1.1 "Not a vault" picker hint (kept as anticipatory copy) actionable.

**Acceptance criteria (refine when authoring the D.1.3 plan — none exists yet):**
- A create flow: choose an empty folder → set a password (with the v1 Argon2id floor enforced as a typed error, `UnlockError::WeakKdfParams`) → generate identity + recovery mnemonic → write the initial vault (`vault.toml`, `identity.bundle.enc`, empty `manifest.cbor.enc`) atomically.
- Surface + confirm the recovery mnemonic (BIP-39) — the user must record it; this is the only recovery path.
- New IPC command(s) over the bridge's create-vault surface; mirror the D.1.1/D.1.2 thin-command + `*_impl` + DTO-serde-pin + typed-AppError pattern.
- Wire the "Not a vault" hint → an actionable "Create vault here" affordance.
- Gauntlet: Rust +N (create-vault IPC tests, ephemeral-tempdir vaults), Vitest +N (wizard components); all type-checks clean. No magic numbers, files < 500 LOC, pure modules, random crypto in tests, manual smoke against a tempdir (NOT the golden fixture).

Author the D.1.3 plan first via `superpowers:brainstorming` → `superpowers:writing-plans`, mirroring how D.1.1/D.1.2 were structured.

## (3b) Open decisions and risks

- **Manual GUI smoke is the pre-merge gate** (§(3)). Until #161's L4 e2e lands, every D.1.x ship leans on a human walk-through.
- **Clipboard is write-only by design** — copying a secret writes the clipboard; we deliberately did NOT request clipboard *read* (can't compare-before-clear), so the 30 s auto-clear is unconditional best-effort and may clobber newer external clipboard content. Documented tradeoff (spec §8).
- **`Esc`-to-pop deferred** → **#164** (spec §12 note added). Visible back buttons cover navigation; the keyboard affordance needs focus/dialog-interaction care.
- **Password handling at the IPC boundary is still not zeroize-typed** (carry-forward from D.1.1 Task 4). D.1.3 introduces a *new* password (vault create) at the boundary — the natural place to finally tackle this.
- Carry-forwards from D.1.1, all still live: **#153** (re-migrate component styles off `theme.css` once Vite 6 `preprocessCSS` is fixed — D.1.2 added more `.record-*`/`.field-*` blocks there), **#154** (emoji icons → inline SVG before external release; D.1.2 adds 👁/🙈/⧉ in FieldRow), **#161** (L4 e2e harness deferred), **#162** (PathPicker e2e hook), **#141** (bridge `RecordInput.record_type` — matters for D.1.4 edit, not D.1.3), **#144/#145/#158/#159** (unlock-time + auto-lock edge cases).

### Verified non-issues (don't re-investigate)
- **Duplicate field names** can't occur: `core::vault::record::Record.fields` is `BTreeMap<String, RecordField>` — names are unique map keys, so `field_by_name`-returns-first and the Svelte `(field.name)` keying are both safe.
- **Bytes-field reveal** is not L3-tested (golden vault has only text fields; it's a frozen KAT) — the base64 path is covered by `reveal.rs` unit tests, and a coverage-note comment marks the gap in `tests/ipc_integration.rs`.

## (4) Exact commands to resume (D.1.3)

```bash
# Merge the D.1.2 PR first (feature/d12-browse), then:
cd /Users/hherb/src/secretary
git fetch --prune origin
git checkout main
git pull --ff-only origin main
git log -5 --oneline           # confirm the D.1.2 ship PR landed

# Re-baseline the automated gauntlet on fresh main:
cargo test --release --workspace --no-fail-fast 2>&1 | grep "^test result:" | awk '$3=="ok." {p+=$4; f+=$6; i+=$8} END {printf "Rust totals → PASSED %d FAILED %d IGNORED %d\n", p, f, i}'
# Expect: PASSED 1069 FAILED 0 IGNORED 10 (D.1.2 baseline)
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py
cd desktop && pnpm install && pnpm test && pnpm typecheck && pnpm svelte-check && pnpm lint && cd ..
# Expect: Vitest 231 passing

# Author the D.1.3 plan (none exists yet):
#   superpowers:brainstorming  → scope the vault-create wizard
#   superpowers:writing-plans  → mirror docs/superpowers/plans/2026-05-29-d12-browse.md

# Then the first implementation worktree:
git worktree add .worktrees/d13-browse -b feature/d13-task-1 main   # (rename per your convention)
cd .worktrees/d13-task-1/desktop && pnpm install
```

### Housekeeping (after the D.1.2 PR merges)
```bash
cd /Users/hherb/src/secretary
git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/d12-browse 2>/dev/null && git branch -D feature/d12-browse 2>/dev/null
git worktree remove .worktrees/d12-spec   2>/dev/null && git branch -D feature/d12-spec   2>/dev/null
git worktree prune && git worktree list
```

## Closing inventory

- **Branch on close:** `main` @ `861d2de`. `feature/d12-browse` carries the spec + plan + 6 task commits + the ship commit (README/ROADMAP/spec-note/handoff/symlink). Squash-merge collapses to one commit on `main`.
- **Automated gauntlet:** Rust **1069 / 0 / 10**; clippy clean; fmt clean; conformance PASS; spec-freshness PASS (97/0); Vitest **231 / 0**; typecheck/svelte-check/lint clean.
- **Manual §15 GUI smoke + L4 e2e:** NOT performed (headless). Manual smoke is the user's pre-merge gate (§(3)); L4 e2e deferred (#161).
- **README.md / ROADMAP.md:** D.1.2 marked ✅; D.1.3 next.
- **CLAUDE.md / `docs/adr/`:** unchanged (no format/architecture change — D.1.2 consumes the frozen B.4b read surface).
- **Issues filed this session:** **#164** (`Esc`-to-pop deferred).
- **NEXT_SESSION.md:** symlink retargeted to this file.
- **This file:** the live D.1.2 ship baton. The next slice opens with `docs/handoffs/<date>-d13-*.md`.
