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
| (this commit) | This handoff + symlink retarget |

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
trailing_bytes, format_version. Offsets are spelled from §3 field widths, and
`checked_base` asserts both wrap length prefixes read 32 before planting.
Section RTS pins each seed's Python class (`_BUNDLE_FILE_CLASSES`).

Floors: `MIN_CORPUS_INPUTS` bundle_file 10, `MIN_STRICT_COMPARISONS` 9.
Committed replay corpus 160 → 169. Full local corpus (main checkout's
`core/fuzz/corpus`, symlinked in temporarily): 34 of 34 `bundle_file`
inputs agree, and every other target agrees too.

**Mutation evidence (`scripts/mutate.py`, `--self-test` 20/20 first; all
`RED_AS_EXPECTED`, exit 0, `git status` clean afterwards):**

| # | Mutation | Gate | Reds |
|---|---|---|---|
| B1 | Python `format_version` raise back to `ParseError` (the pre-slice defect) | replay test | `differential_replay_full_corpus` |
| B2 | Python `wrap_pw_ct_len` raise demoted to `ParseError` (same token) | `conformance.py` | Section RTS only |
| B3 | Rust `UnsupportedFormatVersion` arm → `ContainerMalformed` | `--lib --test rule_token_seeds --no-fail-fast` | mapping test + label-bound test |
| B4 | `bundle_file` strict floor 9 → 10 | replay test | `differential_replay_full_corpus` |

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
   `bundle_file: 10 of 10 ... 9 committed strict token comparison(s)`.
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
5. Card review residuals #699, #701-#705 and the #693 spec question are
   unchanged.

## (3) Open decisions / risks

- **Reuse versus new classes.** The bundle parser reuses the block
  `envelope_rules` classes where the two Rust enums draw the same distinction.
  Their docstrings now name both variants. If a future change wants different
  tokens per envelope, split them then.
- **No two-fault rows.** §3 fixes no report order, and every seed plants one
  fault (the #618 rule).
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
