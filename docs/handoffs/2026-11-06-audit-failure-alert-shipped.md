# NEXT_SESSION.md — a failed scheduled `cargo audit` now alerts (#707)

Branch `ci/audit-failure-alert`, worktree `.worktrees/audit-alert`, base
`9ced9751` (`main`, after #708 merged).

---

## (1) What shipped

| SHA | What |
|---|---|
| `9df33b46` | `audit.yml`: new `alert` job + `alert_on_failure` dispatch input |
| `2beff1e7` | TEMP: injected `exit 1` step for the dry run |
| `f2574e93` | Revert of `2beff1e7` (net diff vs `main`: `audit.yml` only) |
| (this commit) | ROADMAP line + this handoff + symlink retarget |

- **`alert` job** (`needs: cargo-audit`,
  `if: always() && needs.cargo-audit.result != 'success' && (github.event_name == 'schedule' || inputs.alert_on_failure)`).
  It is a separate job so `issues: write` never reaches the job that runs
  cargo. If a `cargo-audit`-labelled issue is open it adds a comment with the run
  URL. If not, it creates the label (`--force`, idempotent) and opens
  `[ci] Scheduled cargo audit failed on <branch>`, assigned to
  `$GITHUB_REPOSITORY_OWNER`. The assignment is what makes sure you get
  notified.
- Push/PR runs never alert, because their author already sees the red
  check. A manual run alerts only when dispatched with
  `alert_on_failure=true`.

### Proof (live runs on the branch, failure injected by `2beff1e7`)

| Run | Inputs | cargo audit | alert | Effect |
|---|---|---|---|---|
| 42042610857 | opt-in | failure | success | opened #711, assignee hherb |
| 42042719404 | opt-in | failure | success | commented on #711; still 1 open issue |
| 42042823196 | none | failure | **skipped** | no comment (negative control) |
| 42042938206 | opt-in | failure | success | opened #712 after #711 was closed (the reopen path; an accident, see below) |
| 42043081648 | opt-in | **success** | skipped | clean branch after the revert |

#711 and #712 are closed with explanatory comments. `actionlint` passes on
every committed state. The `schedule` arm is a plain string comparison and
can only be seen on `main`'s next Monday 06:00 UTC run.

Mishap, recorded honestly: my first revert command used `git revert -q`,
which isn't a valid flag, and the `;`-chained dispatch after it still ran
against the injected branch. That run opened #712. It did end up
exercising the "previous issue closed → open a new one" path for free.

## (2) What is next

1. **#709: 20 open Dependabot npm advisories** (desktop + browser extension;
   `devalue`/`source-map-js`/`vite` rated high). `devalue` comes in via
   `svelte`, whose runtime ships in the desktop bundle, so check
   reachability before dismissing anything as dev-only. Use pnpm only.
   Acceptance: `pnpm audit` clean (or each residual dismissed with a written
   reachability rationale) in `desktop/` and the extension; `pnpm test` +
   `svelte-check` green. Dependabot PR #710 (vite 6.4.4 → 6.4.5) overlaps
   with this, so land or close it as part of the slice.
2. Conformance backlog (`docs/handoffs/2026-09-22-token-compare-contact-card-shipped.md`
   §6): #641 (`bundle_file` / `vault_toml` token comparison), #693, review
   residuals #699–#705. **#700** (nothing pins a target's membership in
   `TOKEN_COMPARED_TARGETS`) has the most real impact.
3. Housekeeping: #659 is fixed in code (der 0.8.2, PR #656) but still open
   on the tracker, so close it. Close #707 once this PR merges (this repo
   cites `(#N)`, never `Closes #N`).

## (3) Open decisions / risks

- After merge, check the first scheduled run on `main` (Mon 2026-11-09 06:00
  UTC). It should be green with `alert` skipped. That is the only live
  evidence for the `schedule` arm of the condition.
- The alert relies on `GITHUB_TOKEN` being allowed to create labels and
  issues. It was, on the branch runs. A repo setting that restricts the
  workflow token would break it silently, because the alert job itself
  would fail with no one watching. Accepted as-is.
- **Review fix:** the first version used `failure()`. A job that hits its
  `timeout-minutes` cap concludes `cancelled`, not `failure` (this repo's own
  run 34761688040, PR #662: `cancelled` at cap+5 min), so a hung scheduled
  audit would have alerted nobody. The condition is now
  `needs.cargo-audit.result != 'success'`. Cost: a scheduled run cancelled by
  a concurrent push to `main` also alerts. That is rare, and a false alarm is
  the safe direction. Not re-dry-run: no live timeout was injected.
- **Review fix:** the label is `cargo-audit`, not `audit`, so it can't be
  confused with `[audit][Sev]` security-finding issues. The title names
  `$GITHUB_REF_NAME` instead of hardcoding `main`. The dry runs (#711/#712)
  used the old `audit` label, which is now unused.
- Inherited and unchanged: the `basic-toml` acceptance in `.cargo/audit.toml`;
  `ml-dsa` still a release candidate.

## (4) How to resume

```bash
cd /Users/hherb/src/secretary/.worktrees/audit-alert
pwd && git branch --show-current            # ci/audit-failure-alert
git fetch origin && git log --oneline HEAD..origin/main
actionlint .github/workflows/audit.yml
gh run list --workflow audit.yml --branch main --limit 3   # after Monday
```

For #709 start a fresh worktree from `origin/main`.

## (5) Where this document lives

This file. `NEXT_SESSION.md` at the repo root is a symlink to it,
retargeted in the same commit as this file's creation.
