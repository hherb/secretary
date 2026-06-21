# NEXT_SESSION.md — Desktop write-gate coverage guard (#280) ✅ (code-complete; all gates green; PR to open)

**Session date:** 2026-06-21. Flow: `/nextsession` → the prior baton (**iOS write-reauth monotonic clock #282**) had **already been squash-merged** to `main` @ `6f806b68` by a parallel session (PR #283 MERGED; worktree + branch already gone), so that baton was fully discharged on arrival — nothing to push. I cleaned up its worktree (`.worktrees/ios-monotonic-reauth`) + branch, then (per your steer) picked **#280** — the centralized desktop write-reauth gate-coverage test deferred from the #278 review. Small, hardening-focused, test-only.

**Status:** ✅ **code-complete; all gates green.** Branch `feature/desktop-write-gate-coverage` (worktree `.worktrees/desktop-write-gate-coverage`), branched from `main` @ `6f806b68`. **Desktop + docs only** (`desktop/**` + `ROADMAP.md` + `docs/superpowers/**` + this handoff). `core/`, the crypto/vault spec, all `*.udl`, `ffi/`, `ios/`, `android/`, and the Rust backend are **untouched**. **PR not yet open** — push + open it (see §4).

## (1) What we shipped this session

**The problem (#280):** desktop write re-auth (#278) gates each mutating vault write behind `authorizeWrite(reason)` **at the Svelte call site** — there is no centralized enforcement, so a new mutating IPC wrapper can ship **ungated** if a contributor forgets the gate. The #278 review caught exactly this: `importContact` shipped ungated in `ShareDialog` even though a *sibling* handler in the same component (`confirmShare` → `shareBlock`) gated a different write. So any file-level "does this component gate anything" check would have **passed** while `importContact` stayed open — the detector has to work at **per-function** granularity.

**The fix — a test-only guard, three layers, no runtime change:**

| Layer / file | What it does |
|---|---|
| **Registry** `desktop/src/lib/writeCommands.ts` | Classifies every Tauri command **exactly once**, keyed by command string: 14 write/gated, 4 write/exempt (each with a `reason`), 4 session, 12 read = **34**. Pure helpers `classifiedCommandNames()` / `gatedWrappers()` / `exemptWritesMissingReason()`. The single source of truth. |
| **Scanner** `desktop/src/lib/writeGateScanner.ts` | Pure, dependency-free `findUngatedWrites(source, isSvelte, gatedWrappers, gate?)`. Brace-matched function bodies + innermost-containing-body attribution; flags any gated-write wrapper called without a preceding `authorizeWrite` **in the same handler**. String/comment/template-literal-aware brace & paren matching. |
| **Layer 1** (in `writeGateCoverage.test.ts`) | Parses the Rust `generate_handler![…]` in `src-tauri/src/main.rs` and asserts that command set === the registry keys (both directions). A newly-registered command that isn't classified → **fail**, forcing a conscious gate-vs-exempt decision. |
| **Layer 2** | For each write entry, asserts the named wrapper exists in `ipc.ts` **and is bound to that command** — scoped to the wrapper's own function body (not a whole-file search), so a wrapper bound to the wrong command can't pass. Also guarantees layer 3 never scans for a phantom wrapper name. |
| **Layer 3** | Runs the scanner over `src/**/*.{svelte,ts}` (excluding ipc.ts / writeCommands.ts / writeGateScanner.ts / `*.test.ts`); asserts zero ungated writes. **Anti-vacuous:** asserts the scanned set is non-empty + includes a known gated call site (`RecordEditor.svelte`), so a glob drift to `{}` fails loudly instead of silently disabling the guard. Layer 3b: every exempt write must carry a `reason`. |
| **Fixtures** `writeGateScanner.test.ts` (9) + `writeCommands.test.ts` (4) | Scanner cases incl. the synthetic sibling-gated-handler bug, gate-after-write, arrow vs `async function`, `saveRecord` vs `saveRecordEdit` word-boundary, `<top-level>` path; registry count/shape/invariants. |
| **Docs** | `ROADMAP.md` new #280 bullet + summary-bar; spec + plan under `docs/superpowers/`. README **not** touched (test-only internal hardening — README stays brief, mirroring #282). |

**Branch commits** (squash-merge → one commit on `main`):
- `f8aa922e` docs: design spec
- `cf449808` docs: implementation plan
- `420f4de4` test: pure write-gate source scanner
- `4d956135` test: report arrow-handler binding name in scanner diagnostics
- `9dc42856` feat: write-command classification registry
- `575adab2` test: centralized write-gate coverage guard (3 layers)
- `0946d3f8` test: harden against vacuous pass + scope layer-2 binding
- `33b0bc55` docs: ROADMAP note
- `1b58422` test: cover `<top-level>` scanner path + fix spec signature drift
- (+ this handoff + the retargeted `NEXT_SESSION.md` symlink — one more commit)

### Acceptance (all green this session)
```bash
cd /Users/hherb/src/secretary/.worktrees/desktop-write-gate-coverage/desktop && pnpm test   # 560 pass / 75 files
pnpm exec tsc --noEmit                                                                       # clean
```
The three new suites pass; layer 3 reports **zero** ungated writes on current `main` — confirming #278 gated all 14 call sites. Manual negative-proof was performed during Task 3 (delete a gate line → layer 3 fails naming the handler; add a fake `generate_handler!` command → layer 1 fails) and reverted; it leaves no committed artifact — the scanner fixtures are the durable regression coverage.

Guardrail (from worktree root):
```bash
git diff main...HEAD --name-only | grep -vE '^(desktop/|docs/(superpowers/(specs|plans)|handoffs)/|ROADMAP.md|NEXT_SESSION.md)'   # EMPTY
```

### Deliberate design decisions (so a future reader doesn't "fix" them)
- **Test-only guard, not a structural type-token / IPC chokepoint.** The gate is a presence-assurance UX layer for an unlocked-but-unattended session, **not** a hard boundary (an attacker with renderer code-exec already holds the in-memory plaintext). A compile-time `WriteAuthorization` token was considered and rejected as over-hardening that reworks the shipped #278 call-site UX. The guard enforces *a deliberate decision exists*, not a specific mechanism.
- **Registry keyed by command string**, not wrapper name — the command string is the token shared by both the Rust ident and the ipc.ts `call<…>('cmd')`, so layer 1 can diff directly against `generate_handler!`.
- **Per-function granularity** (brace-matched bodies + innermost attribution) — coarser (per-file) granularity would have *passed* the historical `importContact` bug.
- **Over-matching is fine.** The scanner doesn't skip wrapper-call-looking text in strings; over-matching only ever makes the guard *stricter* — a false positive is fixed by adding the gate or marking exempt, never by weakening.
- **`probe_create_target` classified `write/exempt`** (pre-unlock probe, no mutation) — a judgement call; `read` would be equally valid. The test only requires *a* decision.

### Review outcome
Final whole-branch review (opus): **READY TO MERGE — no Critical/Important.** Verified end-to-end that a new command + wrapper + ungated call site is caught (layer 1 if unclassified, layer 2 if wrapper mismatch, layer 3 if the call site is ungated), that a phantom wrapper name can't make layer 3 pass vacuously (layer 2 fails first), and that the two silent-rot vectors (vacuous glob, phantom name) are both closed by explicit assertions. Three Minor items:
- **Fixed this session:** spec signature drift (`findUngatedWrites` now shows the `isSvelte` param) + a missing `<top-level>` scanner fixture (commit `1b58422`).
- **Accepted by the reviewer as documented-by-design (not tech debt):** `arrowName` regex falls back to `<arrow>` for destructured/typed-nested-paren arrow params (diagnostic label only, never affects detection); `nextBodyBrace` skips comments but not string literals (benign — `parenClose` is already past the param list); `probe_create_target` write/exempt classification.

## (2) What's next
- **Push + open the PR** (§4), then after merge, housekeeping (remove this worktree + branch).
- **No README / on-device / manual-checklist follow-up** — test-only, zero user-visible behaviour change.
- **Natural next desktop write-reauth lineage items** (if you want to continue the thread): **#277** OS biometric on desktop (Touch ID / Windows Hello, mirroring the mobile presence-proof model — the largest remaining write-reauth piece); configurable/persisted grace-window settings; presence proof for password-only sessions with no device-secret enrollment (all platforms).

**Open follow-up issues (carried):** #286 (scanner method-shorthand gap — filed from this PR's review; doc-noted, not present-tense) / #277 (desktop OS biometric) / #279 (pre-existing ffi rustfmt drift on main) / #255 / #252 / #251 / #234 / #224 / #193 / #192 / #190 / #189 / #186 / #167 / #162 / #161.

## (3) Open decisions and risks
- **Presence layer, NOT a hard boundary** — same framing as #278/#281/#282. This guard protects the *coverage* of that UX layer; it does not change the trust model.
- **Guard self-defends against silent rot** — the anti-vacuous assertion (non-empty scan set + known gated call site present) is the one structural risk a future repo reorg could hit; if `import.meta.glob` ever resolves empty, layer 3 fails loudly rather than passing. Keep that assertion if you touch the glob.
- **Desktop + docs only** — guardrail empty by construction (verified); no cross-language / Rust / iOS / Android run needed.

## (4) Exact commands to resume
```bash
# 0) Push the branch + open the PR (worktree kept alive for PR iteration):
cd /Users/hherb/src/secretary/.worktrees/desktop-write-gate-coverage
git push -u origin feature/desktop-write-gate-coverage
gh pr create --base main --head feature/desktop-write-gate-coverage \
  --title "Desktop: centralized write-gate coverage test (no ungated mutating IPC) (#280)" --body "<summary>"

# Re-run the gates before merge:
cd desktop && pnpm test                 # 560 pass
pnpm exec tsc --noEmit                  # clean
cd /Users/hherb/src/secretary/.worktrees/desktop-write-gate-coverage
git diff main...HEAD --name-only | grep -vE '^(desktop/|docs/(superpowers/(specs|plans)|handoffs)/|ROADMAP.md|NEXT_SESSION.md)'   # empty

# 1) After the PR merges, housekeeping (from the MAIN checkout, not this worktree):
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/desktop-write-gate-coverage && git branch -D feature/desktop-write-gate-coverage
git worktree prune && git worktree list
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Authored once; the symlink is the pointer. Both this handoff + the retargeted symlink are committed on the feature branch ([[feedback_next_session_in_pr]]). If you resume this branch for fixups, first `git fetch origin && git merge origin/main` (branch-version-wins on the handoff path) before editing ([[feedback_next_session_main_authoritative]]). `origin/main` was at `6f806b68` (the branch point) at close, so no bind was needed this session.

## Closing inventory
- **Branch on close:** `feature/desktop-write-gate-coverage` @ `1b58422` + the handoff commit; `main`/`origin/main` @ `6f806b68`. PR to open. Squash-merge → one commit on `main`.
- **Acceptance:** green — desktop vitest 560/560 across 75 files; `tsc --noEmit` clean; layer 3 zero ungated writes on `main`. Guardrail desktop + docs only.
- **Reviews:** per-task reviews (each spec ✅ + quality approved, one fix round on Task 1 diagnostics + one on Task 3 vacuous-pass) + final whole-branch review (opus, READY TO MERGE, no Critical/Important; 2 Minor fixed, 3 accepted by design).
- **README.md / ROADMAP.md:** ROADMAP updated (#280 bullet + summary-bar); README intentionally unchanged (test-only, behaviour identical).
- **NEXT_SESSION.md:** symlink retargeted to this file.
