# NEXT_SESSION.md — `bundle_file` token-compared (#641)

Branch `test/token-compare-bundle-file`, worktree `.worktrees/bundle-tokens`,
base `15d18963` (`main`, after #717 merged).

---

## (1) What shipped

| SHA | What |
|---|---|
| (no commit) | #658 closed with a comment: PR #717's CI replay step printed exactly the floors (record 40, contact_card 22, manifest_body 25, block_file 23) |
| `71f82db4` | `BundleFileError::rule_token()` + mapping test, typed Python §3 raises, 9 seeds, `bundle_file` moved into `TOKEN_COMPARED_TARGETS` |
| `d6841111` | CLAUDE.md, ROADMAP, protocol doc, `diff_replay.py` docstring, Section VT's mirror list |
| `587de5ca` | This handoff + symlink retarget |
| (review fix commit) | PR #718 review: 4 `_below` seeds, 3 bundle parity-order cases + Rust twins, RTS check 0, stale comments/counts |

**How it works.** `core/src/vault/rule_tokens/bundle_file.rs`:
`UnsupportedFormatVersion` → `unsupported_version`, the other five variants →
`container_malformed` (the same split as `BlockError`'s envelope arms).
`rule_tokens/tests/bundle_file.rs` declares the mapping a second time and
counts variants (6). Python's `wire/envelopes.py::parse_identity_bundle_envelope`
now raises `EnvelopeBadMagic` / `UnsupportedEnvelopeVersion` /
`EnvelopeWrongFileKind` / new `EnvelopeWrapLength` / `EnvelopeTrailingBytes`
(all `ParseError` subclasses, same messages). Truncations stay bare `ParseError`.

**The one divergence found.** Once the target was compared, the committed
corpus showed exactly one disagreement: `format_version`, where Rust said
`unsupported_version` and Python said `container_malformed`. Typing that raise
closed it. Before the Python half landed, #700's derived-membership check
already flagged `bundle_file` as fully tokened but uncompared, as designed.

**Seeds** (`core/tests/rule_token_seeds_helpers/bundle_file.rs`, planted into
`golden.bin`): bad_magic, wrong_file_kind, truncated_header, wrap_pw_ct_len,
wrap_rec_ct_len, truncated_bundle_ct, bundle_ct_len_exceeds_file,
trailing_bytes, format_version, plus (PR #718 review) a `_below` twin for
each equality check: format_version_below, wrong_file_kind_below,
wrap_pw_ct_len_below, wrap_rec_ct_len_below. Offsets are spelled from §3 field widths, and
`checked_base` asserts both wrap length prefixes read 32 before planting.
Section RTS pins each seed's Python class (`_BUNDLE_FILE_CLASSES`).

Floors: `MIN_CORPUS_INPUTS` bundle_file 14, `MIN_STRICT_COMPARISONS` 13
(10 / 9 before the review). Committed replay corpus 160 → 173. Full local
corpus (main checkout's `core/fuzz/corpus`, symlinked in temporarily, measured
before the review's seeds): 34 of 34 `bundle_file` inputs agree, and every
other target agrees too.

**Mutation evidence (`scripts/mutate.py`, `--self-test` 20/20 first; all
`RED_AS_EXPECTED`, exit 0, `git status` clean afterwards):**

| # | Mutation | Gate | Reds |
|---|---|---|---|
| B1 | Python `format_version` raise back to `ParseError` (the pre-slice defect) | replay test | `differential_replay_full_corpus` |
| B2 | Python `wrap_pw_ct_len` raise demoted to `ParseError` (same token) | `conformance.py` | Section RTS only |
| B3 | Rust `UnsupportedFormatVersion` arm → `ContainerMalformed` | `--lib --test rule_token_seeds --no-fail-fast` | mapping test + label-bound test |
| B4 | `bundle_file` strict floor 9 → 10 | replay test | `differential_replay_full_corpus` |

**PR #718 review fix round.** Four review agents (code, tests, comments,
silent failures) found no correctness bug, and three gaps confirmed by
mutation:

- Every seed moved its field UP by one, so `!=` loosened to `>` accepted every
  value below, in both languages, with every gate green. Fixed by the four
  `_below` seeds.
- `bundle_file` had no RTS check-5 parity case, so moving Python's (or Rust's)
  `format_version` check after `file_kind` made the two languages disagree on a
  compared target with nothing red. Fixed by three local two-fault cases
  (`rule_token_seeds_ordering._bundle_file_ordering_cases`: magic+version,
  version+kind, version+truncation) and Rust twins
  (`unlock/bundle_file.rs::*_outranks_*`, each asserting both single-fault
  controls). Not corpus rows: §3 fixes no order (#618).
- Deleting `bundle_file`'s `_TARGETS` row in Section RTS switched every check
  off for that target with the section green. New check 0
  (`_target_set_issues`) requires `_TARGETS` to equal the seed directories
  holding a vocabulary-token-labelled file, and the class tables and
  `_ORDERING_CASES` to cover exactly those keys.

Mutation evidence for the round (`--self-test` 20/20 first; all
`RED_AS_EXPECTED`, tree restored; F1/F2 needed a spec fix and a re-run, since
the first spec's `old` matched twice and its lambda probe could not see module
names):

| # | Mutation | Gate | Reds |
|---|---|---|---|
| F1 | Python `fmt != FORMAT_VERSION` → `>` | `conformance.py` | Section RTS |
| F2 | Python `format_version` check moved after `file_kind` | `conformance.py` | Section RTS (check 5) |
| F3 | `bundle_file` row deleted from RTS `_TARGETS` | `conformance.py` | Section RTS (check 0) |
| F4 | Rust `format_version != FORMAT_VERSION` → `>` | `--test rule_token_seeds` | `rule_token_seeds_are_committed_and_label_bound` |
| F5 | Rust `format_version` check moved after `file_kind` | `--lib unlock::bundle_file` | `bad_format_version_outranks_bad_file_kind` |

`block_file`'s seeds have the same one-direction gap; filed as #719 rather
than fixed here.

**Gates run, all exit 0:** `cargo test --release --locked -p secretary-core`,
the replay test (60 passed), clippy `-p secretary-core --features
differential-replay --tests -D warnings`, `cargo fmt --all --check`, rustdoc
`-D warnings` on `secretary-core`, `conformance.py` (35/35 registered),
payload-hygiene and secret-slot guards (with `--self-test`),
`check-ci-wiring.py`. **Not run locally:** full-workspace test/clippy (only
`core` and Python changed); CI runs them.

`spec_test_name_freshness.py` exits 1 with 99 unresolved citations, the same
on `main`. It's already tracked (#642, #574, #607) and isn't in CI.

## (2) What is next

1. **Merge this PR.** CI's `cargo test (ubuntu-latest)` replay step must print
   `bundle_file: 14 of 14 ... 13 committed strict token comparison(s)`.
2. **#641's last target, `vault_toml`.** It's crash-only (no re-encode), and
   the issue rates it "last, if at all". Acceptance: a Rust taxonomy for the
   `vault_toml` decoder error, typed Python raises in `codec/vault_toml.py`,
   the target moved into `TOKEN_COMPARED_TARGETS` with a non-zero
   `MIN_STRICT_COMPARISONS` row, and seeds (today it has 9 committed inputs, so
   check how many reject). Ask the user whether it's worth doing before
   starting. If they say no, close #641 with that reasoning.
3. **#646**: narrowing the tolerance. Raising the `manifest_body` strict floor
   is the measurable result.
4. **#677**: `bundle_file` / `manifest_file` were never value-type swept. This
   slice's seeds are envelope faults only; the substitution method still
   doesn't apply to a binary envelope.
5. **#719**: `block_file`'s seeds plant each equality check on one side only
   (the gap the PR #718 review closed for `bundle_file`). Small slice.
6. Card review residuals #699, #701-#705 and the #693 spec question are
   unchanged.

## (3) Open decisions / risks

- **Reuse versus new classes.** The bundle parser reuses the block
  `envelope_rules` classes where the two Rust enums draw the same distinction.
  Their docstrings now name both variants. If a future change wants different
  tokens per envelope, split them then.
- **No two-fault corpus rows.** §3 fixes no report order, and every seed
  plants one fault (the #618 rule). The three two-fault bodies live in RTS
  check 5 and its Rust twins as parity, not spec.
- `sections/value_type_discipline.py` is still 849 lines (the mirror edit was
  kept on one line so CLAUDE.md's figure holds); backlog.
- `.worktrees/` still holds `d5-macos-mutation`, `d5-macos-trash-settings`,
  the merged `pin-token-compared`, `ci-wiring` and `strict-floor` worktrees,
  branch `backup-pre-reword-1787543234`, and two detached `.claude/worktrees/`
  checkouts. Ask before deleting.
- The first scheduled `audit.yml` run on `main` is Mon 2026-11-09 06:00 UTC,
  still the only live evidence for #707's `schedule` arm.

## (4) How to resume

```bash
cd /Users/hherb/src/secretary/.worktrees/bundle-tokens
pwd && git branch --show-current     # test/token-compare-bundle-file
git fetch origin && git log --oneline HEAD..origin/main
cargo test --release --locked -p secretary-core \
  --features differential-replay --test differential_replay
uv run core/tests/python/conformance.py
# the mutation spec lived in the session scratchpad; rebuild it from the table in (1)
```

## (5) Where this document lives

This file. `NEXT_SESSION.md` at the repo root is a symlink to it, retargeted
in the same commit that creates this file.
