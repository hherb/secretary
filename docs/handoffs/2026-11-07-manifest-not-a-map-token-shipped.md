# NEXT_SESSION.md: a non-map manifest_body carries a rule token (#723)

Branch `test/manifest-not-a-map-token`, worktree `.worktrees/not-a-map`,
base `a88cc268` (`main`, after #724 merged).

---

## (1) What shipped

| SHA | What |
|---|---|
| (no commit) | #724 (#721) confirmed merged as `a88cc268`. Its post-merge CI on `main` was still running at session start. |
| `53a3df6f` | #723: typed top-level map check, committed seed, floors, docs |
| (this commit) | This handoff + symlink retarget |

**The defect.** Rust reports a top-level `manifest_body` item that is not a
map as `ManifestError::NotAMap` (`wrong_type`). `py_decode_manifest` let
`_scan_map_entries`' untokened `ValueError` escape. On a token-compared
target that is a harness failure, so any fuzz-discovered non-map body would
red `differential_replay_full_corpus`. No committed input reached it.

**Fix** (`core/tests/python/conformance_lib/codec/manifest_decode.py`):
after `walk_body`, the decoder checks the top-level head and raises the
existing `WrongFieldType`. Rust checks at the same point, after its
well-formedness and rule-4 walks. No new class was needed, so RTV's
class table is unchanged. `record.py` already used this pattern, and
`card.py` translates afterwards. The scanner's shared raise is untouched.

Measured through `diff_replay.replay_bytes('manifest_body', ...)`:

| input | Python token now |
|---|---|
| `01`, `80`, `0100`, `40` | `wrong_type` (was `None` for all four) |
| `c101` (tag), `f90000` (float) | `rule4_tag_or_float` (unchanged) |
| `f7` (`undefined`) | `malformed_cbor` (unchanged) |

**Seed**: `core/fuzz/seeds/manifest_body/toplevel__integer.bin`, the one
byte `0x01`. Its prefix is deliberately **not** a vocabulary token. A first
attempt named it `wrong_type__not_a_map.bin`, and Section RTS check 0
treated that as `manifest_body` claiming to be an RTS-labelled target.
`toplevel__` matches no KAT prefix in `seed_binding`, so the seed is unbound.
It is strict anyway, since `wrong_type` is not phase-dependent.

**Floors** (`core/tests/differential_replay_helpers/targets.rs`):
`MIN_CORPUS_INPUTS["manifest_body"]` 61 → 62,
`MIN_STRICT_COMPARISONS["manifest_body"]` 43 → 44. The committed corpus
goes from 184 to 185.

**Mutation evidence** (`scripts/mutate.py`, `--self-test` 20/20 first, exit
0, tree restored; spec in the session scratchpad as `m723.toml`):

| # | Mutation | Gate | Outcome | Reds |
|---|---|---|---|---|
| P1-replay | `if (major := ...) != MAJOR_MAP:` → `if False and ...` | `--test differential_replay` (feature on) | RED_AS_EXPECTED | `differential_replay_full_corpus` |
| P1-rtv | same | `uv run core/tests/python/conformance.py` | RED_AS_EXPECTED | Section RTV |

The TDD red was also seen directly: with the seed committed and no fix,
RTV reported `toplevel__integer.bin: rejected by ValueError carrying no
rule token`.

**PR #726 review round.** The single `0x01` seed left two weaknesses
unpinned. Each was measured green on every gate:
- a check narrowed to `major == 0`;
- the check moved above `walk_body`. That makes Python answer `wrong_type`
  where Rust answers rule 4 or `malformed_cbor` (§4.2: both outrank a wrong
  type).

Section MSH now runs 11 top-level heads:
- eight non-map majors (`00 20 40 60 80 f4 f5 f6`), each requiring the
  `wrong_type` token;
- `81c101` and `81f90000`, requiring `rule4_tag_or_float`;
- `81f7`, requiring `malformed_cbor`.

This is a Python-local pin, so no corpus, floor or section count moves.
The harness results (spec in the scratchpad as `mutations.toml`):

| # | Mutation | Gate | Outcome | Reds |
|---|---|---|---|---|
| H1 | check moved above `walk_body` | `conformance.py` | RED_AS_EXPECTED | Section MSH |
| H2 | `!= MAJOR_MAP` → `== 0` | `conformance.py` | RED_AS_EXPECTED | Section MSH |

The review also corrected three docs:
- CLAUDE.md's line-count ranking: `manifest_decode.py` is 501, three files
  are past 500;
- this table's "first three" (the right figure is all four);
- RTV's docstring, which implied the map type check was now tokened. It
  stays untokened at nested positions.

The review's 49-input sweep through both decoders found no disagreement
this PR introduced. The one mismatch, `a001` (Rust `missing_field`, Python
`non_canonical_unclassified`), is identical on `main`, and §4.2 tolerates
it (trailing bytes against a schema fault).

**Docs updated**: CLAUDE.md (the corpus count in the Commands block and the
residual-scope bullet, and the strict-floor figures in two places), RTV's
module docstring, and ROADMAP (new ✅ entry). README is untouched, since it
does not mention the replay corpus.

**Gates run, all exit 0:**
- `cargo test --release --locked -p secretary-core` (56 binaries, 0 not ok)
- the replay test (70 passed; `manifest_body: 62 of 62 ... 44 committed strict`)
- `cargo fmt --all --check`
- `conformance.py` (35/35)

**Not run locally:** clippy, rustdoc, full workspace. Only one Rust doc
comment, two constants and Python changed. CI runs the rest.

**Filed:** #725. `codec/manifest_decode.py` is now 501 lines, one past the
threshold. #683 covers only the two Section VT files.

## (2) What is next

1. **Merge this PR.** CI's replay step must print
   `manifest_body: 62 of 62 ... 44 committed strict token comparison(s)`.
2. **#725**: split `codec/manifest_decode.py`. The seam is
   `_validate_manifest_shape` and its helpers. Acceptance: no check
   reordered, and byte-identical `--diff-replay` output over the committed
   corpus before and after.
3. **#649**: `differential_replay.rs` is at 500 lines. The next addition
   to it must split it. This slice did not touch it.
4. **#677**: `bundle_file` / `manifest_file` envelope sweep. The first step
   is deciding what a sweep means for an offset-read binary envelope.
5. **#668 / #693**: report-order spec questions. These are spec decisions,
   so ask the user.
6. **#699, #701-#705**: card review residuals.

## (3) Open decisions / risks

- **Nested non-map values on the manifest path are not covered.**
  `codec/manifest_schema.py` still holds untokened `ValueError` sites, as
  RTV's docstring records. They were not measured in this slice. If a
  fuzzed body reaches one, the replay reds it as a harness failure (loud,
  fail-closed). A sweep of nested positions would size it.
- The seed is unbound (no generator, no Rust test naming `NotAMap` for the
  file). The replay's strict comparison requires both sides to say
  `wrong_type`. Rust's `NotAMap` → `wrong_type` mapping is pinned in
  `manifest/token/tests/mapping.rs`.
- Carried over, unchanged: the label binding is Rust-test-side only; §4.2
  states no order among interpretation-time checks; and
  `sections/value_type_discipline.py` is still 849 lines (#683).
- Worktrees: `.worktrees/block-seeds`, `.worktrees/pairwise-tolerance`,
  `.worktrees/strict-seeds` (all merged), the two detached
  `.claude/worktrees/` checkouts, and branch `backup-pre-reword-1787543234`.
  All left alone; ask before deleting.
- The first scheduled `audit.yml` run on `main` is Mon 2026-11-09 06:00 UTC.

## (4) How to resume

```bash
cd /Users/hherb/src/secretary/.worktrees/not-a-map
pwd && git branch --show-current     # test/manifest-not-a-map-token
git fetch origin && git log --oneline HEAD..origin/main
cargo test --release --locked -p secretary-core \
  --features differential-replay --test differential_replay
uv run core/tests/python/conformance.py
```

## (5) Where this document lives

This file. `NEXT_SESSION.md` at the repo root is a symlink to it, retargeted
in the same commit that creates this file.
