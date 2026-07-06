# NEXT_SESSION.md — #383 quick-xml audit re-triage ✅ SHIPPED (PR opening)

**Session date:** 2026-07-06. A short security-triage session: re-triaged the `#383` quick-xml DoS advisories (RUSTSEC-2026-0194/0195) that the `#354` `cargo audit --deny warnings` gate accepts. Also opened by cleaning up the merged `#374` slice (PR #390): removed worktree `.worktrees/repair-consent-374` + branch `feature/repair-consent-374`. Worktree `.worktrees/audit-quickxml-383`, branch `feature/audit-quickxml-triage-383` (cut from `main` @ `09ad4e9`).

## (1) What we shipped this session

**Housekeeping:** confirmed PR #390 (final #374 slice) MERGED; removed the stale `repair-consent-374` worktree + branch. `main` clean @ `09ad4e9`.

**#383 re-triage** (commit `fd7a9f5`, single `.cargo/audit.toml` rationale change — ignore IDs unchanged, audit gate stays green). The re-triage produced two evidence-backed findings that invalidated the original acceptance note:

- **Second consumer found.** quick-xml 0.39.4 enters the lock via TWO Tauri-only paths, not just plist. `cargo tree -i quick-xml` (macOS) shows only `plist → tauri`; `--target all` reveals `wayland-scanner v0.31.10` (build-time proc-macro) `→ wl-clipboard-rs → arboard → tauri-plugin-clipboard-manager` (Linux clipboard). It parses static Wayland protocol XML at compile time — trusted, still not attacker-reachable, but the rationale named only plist.
- **Exit criteria were insufficient.** plist **1.10.0** now requires quick-xml `^0.41` and Tauri accepts it (`plist ^1`) — so the original "drop once plist adopts >=0.41" condition is met, yet empirically `cargo update -p plist` ADDS quick-xml 0.41.0 while wayland-scanner keeps 0.39.4 (two copies verified in `Cargo.lock`, then reverted), so 0194/0195 still fire. Bumping plist alone = duplicate dep, zero audit benefit → deferred.
- **Corrected exit criteria** (now in `audit.toml`): drop both ids only when quick-xml 0.39.x is gone from `Cargo.lock` entirely — BOTH plist ≥0.41 (done upstream) AND wayland-scanner ≥0.41 (**pending**; 0.31.10 still pins `^0.39`). Then a single quick-xml 0.41 resolves and both ids drop in one step.
- Posted the full triage to #383 (comment) with the corrected checklist; **issue stays OPEN** pending the wayland-scanner side.

### Branch commits (off `main` @ `09ad4e9`)
`fd7a9f5` audit.toml re-triage → this docs/handoff commit.

### Acceptance (verified this session, from the worktree)
```bash
cd /Users/hherb/src/secretary/.worktrees/audit-quickxml-383
python3 -c "import tomllib; tomllib.load(open('.cargo/audit.toml','rb'))"   # TOML valid
cargo audit --deny warnings                                                 # exit 0, clean
# Proof the ignores are load-bearing (probe a copy without the config):
cp Cargo.lock /tmp/lock.probe && (cd /tmp && cargo audit --file lock.probe) # flags exactly 0194/0195
```

## (2) What's next

1. **Manual GUI smoke of the #374 consent flow** (human-only, carried from last session): `pnpm tauri dev` against a **temp copy** ([[feedback_smoke_test_temp_copy_golden_vault]]) of a vault with staged crashed-share residue (`core/tests/crash_recovery.rs::stage_crashed_share`). Confirm unlock → "Repair now?" → consent dialog renders the added recipient + grouped fingerprint → Cancel leaves vault untouched → Grant adopts the widened set.
2. **#376 remainder** — `trash_block` secure-overwrite fallback + legacy `fingerprint == None` trash-entry migration decisions (design-heavy).
3. **#388** — bridge `preview_repair` recovery/device-secret arm happy-path tests (cheap, mechanical). **#389** — desktop dialog aria-labelledby parity. Both #374 follow-ups.
4. **Housekeeping:** #387 (`:kit` NewApi lint), #379 (desktop `errors.rs` 726-line split), #290 (`spec_test_name_freshness.py` 3 pre-existing threat-model false-positives).
5. **Carried mobile:** iOS on-device Face ID spot-check; Android #338 on-device biometric cloud-open, #331 SAF custom-ROM, #334 native cloud-provider epic (ADR + threat-model first).

**#383 acceptance to fully close (future):** when `cargo tree -i quick-xml --target all` shows a single quick-xml ≥0.41 (both plist and wayland-scanner moved), drop RUSTSEC-2026-0194/0195 from `.cargo/audit.toml` and confirm `cargo audit --deny warnings` stays green. Re-check on every Tauri upgrade / any `cargo update` touching plist or the arboard/wayland clipboard chain.

## (3) Open decisions and risks

- **Do NOT `cargo update -p plist` in isolation.** It resolves in a second quick-xml (0.41 alongside 0.39.4) with no audit-gate benefit until wayland-scanner also moves. The audit.toml comment now spells this out; honor it.
- **The wayland-scanner quick-xml path is Linux/build-time only** and invisible to a macOS `cargo tree -i quick-xml` — use `--target all` when re-checking, or the next auditor will miss it again (as this issue's original note did).
- Both advisories remain **consciously accepted, not fixed** — trusted-input, desktop-only, outside the crypto core / FFI bridge / mobile clients. Enforcement is intact: `cargo audit --deny warnings` fails on any *new* advisory; these two are the only vulnerability-class entries in the ignore list.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After this PR merges, remove the worktree + branch:
#   git worktree remove .worktrees/audit-quickxml-383 && \
#   git branch -D feature/audit-quickxml-triage-383
git worktree list && git status -s
# Re-check the audit gate any time: cargo audit --deny warnings
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; the symlink is retargeted in the same commit on the feature branch (new path → no add/add conflict; `main` updates cleanly on merge). Per the baton convention the handoff rides inside the PR — do **not** sync to `main` during the pause window.

## Closing inventory
- **State on close:** PR opening on `feature/audit-quickxml-triage-383` (2 commits: `fd7a9f5` + this docs/handoff commit). Worktree `.worktrees/audit-quickxml-383`. #383 stays OPEN (exit criteria corrected, pending wayland-scanner ≥0.41 upstream). Merged #374 worktree/branch cleaned up.
- **Acceptance:** `.cargo/audit.toml` valid TOML; `cargo audit --deny warnings` exit 0; probe without the config flags exactly RUSTSEC-2026-0194/0195.
- **README / ROADMAP:** no update needed (neither references the audit gate, quick-xml, or #383 — verified by grep).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-07-06-audit-quickxml-triage-383-shipped.md`.
