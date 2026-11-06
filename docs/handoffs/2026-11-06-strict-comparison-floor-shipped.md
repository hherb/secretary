# NEXT_SESSION.md — strict token comparisons floored (#658)

Branch `test/strict-comparison-floor`, worktree `.worktrees/strict-floor`,
base `767468b2` (`main`, after #716 merged).

---

## (1) What shipped

| SHA | What |
|---|---|
| (no commit) | `ci wiring` added to `protect_main`'s required contexts (ruleset 15821032, now 25), with your OK; #657 closed with a comment |
| `d2b0e9c5` | `is_strict_comparison` + `MIN_STRICT_COMPARISONS` floor + strict count on each finish line |
| `8679b2f8` | CLAUDE.md, ROADMAP, `tolerance.rs` doc, protocol doc |
| (this commit) | This handoff + symlink retarget |

**How it works.** `token_coverage::is_strict_comparison(target, rust, python)`
is true when the target is token-compared, both sides rejected with a token,
and, on a `PHASE_DEPENDENT_TOLERANCE_TARGETS` target (`manifest_body`),
neither token is phase-dependent. That is the issue's "both-ordered"
definition. The replay loop counts these over COMMITTED inputs only (the
#656 lesson) and asserts `>= MIN_STRICT_COMPARISONS` per target.
`every_target_is_classified` requires the table to cover `TARGETS` exactly,
uncompared targets to be 0, and no strict floor to exceed its input floor.

Measured floors (from the finish lines): record 40, contact_card 22,
manifest_body 25, block_file 23, others 0.

**Mutation evidence (`scripts/mutate.py`, all RED_AS_EXPECTED, exit 0, tree
restored; gate `cargo test --release --locked -p secretary-core --features
differential-replay --test differential_replay`):**
- S1 `ManifestError::{WrongType,InvalidByteLength}` → `NonCanonicalUnclassified`
  in `core/src/vault/manifest/token.rs`: reds `differential_replay_full_corpus`
  with the strict-floor message (25 → 20). Checked by hand that with the
  `manifest_body` floor at 0 the same mutation leaves the binary GREEN, which
  is the #658 gap.
- S2 the predicate ignores the tolerance: reds
  `a_phase_dependent_token_on_either_side_is_not_strict_where_tolerated`.
- S3 the counter never increments: reds `differential_replay_full_corpus`.

**Gates run:** the replay test (57 passed), clippy `-p secretary-core
--features differential-replay --tests -D warnings`, `cargo fmt --check`,
rustdoc `-D warnings` on `secretary-core`, `check-ci-wiring.py`,
`mutate.py --self-test` 20/20. No Python or `src/` code changed, so
`conformance.py` and the full workspace suite were not re-run.

## (2) What is next

1. **Merge this PR.** CI's `cargo test (ubuntu-latest)` replay step must show
   the four strict counts on its finish lines. Then close #658 with a comment.
2. **#641 (`bundle_file`, `vault_toml`)**: needs Rust taxonomies.
   `differential_replay_full_corpus` reds when a target becomes ready; give
   it a non-zero `MIN_STRICT_COMPARISONS` row in the same PR.
3. **#646**: narrowing the tolerance. Raising the `manifest_body` strict
   floor is the measurable result.
4. Card review residuals #699, #701-#705 and the #693 spec question are
   unchanged (see `docs/handoffs/2026-09-22-token-compare-contact-card-shipped.md` §6).

## (3) Open decisions / risks

- **Definition choice.** "Strict" means both tokens are ordered. A pair like
  `rule4_tag_or_float`/`rule4_tag_or_float` counts as strict, though a Python
  move from it to `rule2_indefinite_length` would be tolerated (group C).
  The floor catches the Rust raise side moving, which is what #658 asks for.
  It does not floor Python-side moves onto phase-dependent tokens; Section
  RTV's corpus-token set check covers those.
- **Floor, not equality.** Adding seeds does not red; the table goes stale
  low until someone raises it. The finish line prints the live count.
- `sections/value_type_discipline.py` (849 lines) still over 500; backlog.
- `.worktrees/` still holds `d5-macos-mutation`, `d5-macos-trash-settings`,
  the merged `pin-token-compared` and `ci-wiring` worktrees, branch
  `backup-pre-reword-1787543234`, two detached `.claude/worktrees/`
  checkouts. Ask before deleting.
- First scheduled `audit.yml` run on `main` is Mon 2026-11-09 06:00 UTC, the
  only live evidence for #707's `schedule` arm.

## (4) How to resume

```bash
cd /Users/hherb/src/secretary/.worktrees/strict-floor
pwd && git branch --show-current     # test/strict-comparison-floor
git fetch origin && git log --oneline HEAD..origin/main
cargo test --release --locked -p secretary-core \
  --features differential-replay --test differential_replay
# mutation spec lived in the session scratchpad; rebuild from (1)
```

## (5) Where this document lives

This file. `NEXT_SESSION.md` at the repo root is a symlink to it, retargeted
in the same commit as this file's creation.
