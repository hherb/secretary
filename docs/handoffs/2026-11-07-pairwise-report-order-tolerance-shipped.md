# NEXT_SESSION.md — rule-token tolerance as a §4.2 pair relation (#646)

Branch `test/pairwise-report-order-tolerance`, worktree
`.worktrees/pairwise-tolerance`, base `98dccc4b` (`main`, after #720 merged).

---

## (1) What shipped

| SHA | What |
|---|---|
| (no commit) | #720 confirmed merged as `98dccc4b`. Its post-merge CI on `main` was still running at session start. |
| (no commit) | Four spec decisions taken by the user, all as recommended (below). |
| (no commit) | Filed **#721**: bind the committed single-fault `manifest_body` seeds to their expected token by label. |
| `07c586a8` | #646: §4.2 text, the pair relation, the pair-set test, the group-D witness, docs |
| `25f62377` | This handoff + symlink retarget |
| (review commit) | PR #722 review fixes (see "Review fixes" below) |

**User decisions (2026-11-07):**
- Group C: **rule 4 outranks §6.2 rules 1-3.** §4.2 had put them under ordering 1 and then called them unordered against "those two". The second sentence now reads "against ordering 2", and one added sentence says ordering 1 binds rules 1-3.
- Group D: **free.** Sort order against a repeated array value may be reported either way.
- Scope: **one general sentence.** A *re-encode-visible* fault (§6.2 rules 1-3, the five array sort disciplines, bytes trailing the map) is unordered against every other manifest rule except rule 4 and well-formedness. That settles groups A and D and the sort-vs-schema pairs.
- The strict floor is **a separate slice** (#721).

**Code** (`core/tests/differential_replay_helpers/tolerance.rs`): `tokens_agree`
is `r == p || report_order_is_free(target, r, p)`. A pair is free when one
member is re-encode-visible (`RuleToken::is_phase_dependent`, unchanged) and
both are in `FREELY_ORDERED_MANIFEST_RULES`. That set is the 10 manifest
rules other than rule 4, `malformed_cbor`, `unknown_field` and the
envelope/harness tokens. The result is 30 tolerated pairs on `manifest_body`,
down from 58. `grants_tolerance` (read by the strict-comparison floor) is
unchanged.

**Test**: `tolerance_admits_only_phase_dependent_pairs` (name kept, it is
cited) now asserts the exact tolerated set against a second declaration
written from §4.2 (the 6 pairs among 4 re-encode-visible strings plus 4 × 6
against interpretation-time strings, 30 in all, plus symmetry). It names the B, C and D pairs.

**Witness**: `core/tests/data/diff_regressions/manifest_body/arraysort_plus_repeated_block_uuid.bin`
is `uniq__blocks__duplicate_block_uuid` with `blocks` reversed by byte
surgery (`[b2, b2, b1]`). Rust says `repeated_array_value`, Python says
`array_sort_order` (checked with `diff_replay.replay_bytes`). Documented in
`diff_regressions/README.md`. `MIN_CORPUS_INPUTS["manifest_body"]` 58 → 59.
The committed corpus was 182 at this commit (184 after the review fixes).

**Mutation evidence** (`scripts/mutate.py`, `--self-test` 20/20 first, exit 0,
tree clean afterwards; spec in the session scratchpad as `m646.toml`):

| # | Mutation | Gate | Outcome | Reds |
|---|---|---|---|---|
| GD | drop `RepeatedArrayValue` from the free set | `--test differential_replay` | RED_AS_EXPECTED | `differential_replay_full_corpus`, `tolerance_admits_only_phase_dependent_pairs` |
| PT | restore the per-token predicate | same | RED_AS_EXPECTED | `tolerance_admits_only_phase_dependent_pairs` |

**Docs updated**: `docs/vault-format.md` §4.2, `RuleToken::is_phase_dependent`'s
doc + LIMITS (`core/src/vault/manifest/token.rs`), `rule_token_vocabulary.json`
`_comment`, Section RTV's comment, `diff_replay.py` docstring,
`differential-replay-protocol.md`, `targets.rs`, CLAUDE.md (four passages plus
corpus counts) and ROADMAP. README untouched, since it does not mention the
tolerance.

**Gates run, all exit 0:**
- `cargo test --release --locked -p secretary-core` (56 binaries)
- the replay test (60 passed; `manifest_body: 59 of 59 ... 25 committed strict`)
- clippy `-p secretary-core --features differential-replay --tests -D warnings`
- rustdoc `-D warnings -p secretary-core`; `cargo fmt --all --check`
- `conformance.py` (35/35)

`spec_test_name_freshness.py` exits 1 on `main` too (99 unresolved citations;
this branch has 98). That is the known #642.

**Not run locally:** full-workspace test/clippy/rustdoc. Only `core/tests/**`,
one `core/src` doc comment, Python comments, JSON and docs changed. CI runs
the rest.

**Review fixes (PR #722 review: code, comment and test reviewers):**
- §4.2's rules-1-3 paragraph still justified itself with "fixing an order
  between them and the two rules above would outlaw one design", which
  contradicted its own new last sentence. It now says "and ordering 2".
- `a_phase_dependent_pair_on_an_unlicensed_compared_target_disagrees` was
  vacuous: its pair (`container_malformed`) disagrees on `manifest_body` too.
  It now uses a pair §4.2 frees and asserts that it agrees there first.
- Two new committed inputs (corpus 182 → 184, `manifest_body` floors 59 → 61
  inputs and 25 → 26 strict):
  `repeated_block_uuid_plus_trailing_byte.bin` (group-A witness: Rust
  `repeated_array_value`, Python `non_canonical_unclassified`) and
  `rule4_float_plus_arraysort.bin` (both sides `rule4_tag_or_float`). The
  second pins the order #646 FIXED, in decoder behaviour, which the pair-set
  test cannot see.
- The pair-set test now requires its three declared lists to partition
  `RuleToken::ALL`, so a new token reds until it is classified. A call-site
  test pins rule 4 vs `array_sort_order` as a disagreement.
- Stale text fixed: `manifest_rules.py` quoted a §4.2 sentence this PR
  deleted; the protocol doc's agreement matrix still stated the per-token
  rule; CLAUDE.md "25 of 58" and "a committed WITNESS"; `token_coverage.rs`
  "any other mismatch"; "re-encode paragraph"/"only" paraphrases of §4.2's
  "general rule"/"may first detect"; ROADMAP "the pair"; this handoff's
  "4 × 6" and "440".
- Filed **#723** (pre-existing): Python's non-map manifest rejection is
  untokened.

## (2) What is next

1. **Merge this PR.** CI's replay step must print
   `manifest_body: 61 of 61 ... 26 committed strict token comparison(s)`.
2. **#721**: bind each committed single-fault `manifest_body` seed to its
   expected token (from the canonicality/uniqueness KAT fixtures or the seed
   label) and count it as strict even when the token is re-encode-visible.
   Acceptance: the 17 `NonCanonicalEncoding` seeds compare by equality,
   `MIN_STRICT_COMPARISONS["manifest_body"]` rises to about 42, and the two
   multi-fault tolerance witnesses (now three) are still scored by the pair
   relation.
3. **#677**: `bundle_file` / `manifest_file` value-type sweep. The first step
   is deciding what a sweep means for a binary envelope.
4. **#668 / #693**: report-order spec questions (block envelope + record;
   contact card). These are spec decisions, so ask the user.
5. **#699, #701-#705**: card review residuals.
6. **#649**: `differential_replay.rs` is **498** lines after the review
   fixes (467 at `07c586a8`), two under the 500-line split threshold. The
   next addition to it should split it.
7. **#723**: Python's non-map `manifest_body` rejection carries no token
   (found in this PR's review).

## (3) Open decisions / risks

- §4.2 leaves the order among interpretation-time checks (`wrong_type`
  against `missing_field`, a repeat against a type error) unstated. The
  harness compares those strictly as **parity**, not spec. If a clean-room
  reader differs there, that is a spec question, not a bug.
- No tolerance witness's Rust token is pinned by a direct decode test. If
  Rust started saying `array_sort_order` for the group-D witness, the pair
  would become equal and the witness would silently stop testing the
  tolerance. The `#621` witness had the same exposure before this slice. The
  review MEASURED all three Rust tokens once, by making `tokens_agree` strict
  equality in a scratch worktree: exactly the three tolerance witnesses
  disagreed, with the tokens their README entries name.
- `vault_toml` stays loose by decision (#641 closed without it).
- `sections/value_type_discipline.py` is still 849 lines (#683).
- Worktrees: `.worktrees/block-seeds` (merged #720), the two detached
  `.claude/worktrees/` checkouts, and branch `backup-pre-reword-1787543234`.
  Left alone; ask before deleting.
- The first scheduled `audit.yml` run on `main` is Mon 2026-11-09 06:00 UTC.

## (4) How to resume

```bash
cd /Users/hherb/src/secretary/.worktrees/pairwise-tolerance
pwd && git branch --show-current     # test/pairwise-report-order-tolerance
git fetch origin && git log --oneline HEAD..origin/main
cargo test --release --locked -p secretary-core \
  --features differential-replay --test differential_replay
uv run core/tests/python/conformance.py
```

## (5) Where this document lives

This file. `NEXT_SESSION.md` at the repo root is a symlink to it, retargeted
in the same commit that creates this file.
