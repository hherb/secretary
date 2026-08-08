# Guard Residual Closeout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close all four documented residuals of the `#474`/`#480` error-payload hygiene guard (#486, #482, #487, #488), after first splitting the 5035-line guard into a package.

**Architecture:** Phase 1 is pure code motion — `scripts/check-error-payload-hygiene.py` becomes a PEP 723 entry point over a new `scripts/payload_guard/` package, gated on a planted-violation output diff rather than a green self-test. Phase 2 generalizes rule E3 from *one candidate form in one root* to *four candidate forms in three roots*, adds rule E5 (`format!` confinement in the binding wrapper crates), and adds the missing fail-open control P40.

**Tech Stack:** Python 3.11+ (stdlib only, PEP 723 inline metadata, run via `uv`), Rust (stable, pinned 1.97.0), `thiserror`, `pyo3`, `uniffi`.

**Spec:** `docs/superpowers/specs/2026-08-08-486-guard-residual-closeout-design.md`

## Global Constraints

- **Python runs via `uv` exclusively — never `pip` / `pip3` / `python -m pip`.**
- Guard invocations, unchanged throughout: `uv run scripts/check-error-payload-hygiene.py --self-test` and `uv run scripts/check-error-payload-hygiene.py`.
- The entry-point path `scripts/check-error-payload-hygiene.py` MUST NOT change — CLAUDE.md, `.github/workflows/test.yml:265-268` and `core/tests/error_payload_hygiene_parity.rs` all reference it.
- The guard has **zero third-party dependencies** (`dependencies = []` in the PEP 723 header). Do not add any.
- `#![forbid(unsafe_code)]` is a workspace lint. Do not introduce `unsafe`.
- Clippy must stay clean with `-D warnings` (`cargo clippy --release --workspace --tests -- -D warnings`).
- **No `.udl` diff.** `git diff main... -- ffi/secretary-ffi-uniffi/src/secretary.udl` must be EMPTY at every commit.
- **No new `FfiVaultError` variant or field**, and no KAT regeneration.
- Allowlist growth budget for the whole branch: **at most 2 entries**. More than that is a signal the rule is mis-shaped — stop and escalate rather than absorbing them.
- Every new self-test control MUST be **mutation-verified**: break the rule (or the specific arm) it pins, confirm exactly that control goes red, restore. A control that stays green under its own mutation is not a control.
- Commit trailer on every commit: `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`
- Work in the worktree: `/Users/hherb/src/secretary/.worktrees/486-guard-residual-closeout`, branch `feature/486-guard-residual-closeout`. Verify with `pwd && git branch --show-current` before any `cargo` / `git` command.

## Baseline (must hold before Task 1)

```
self-test: OK (40 positive / 18 negative / 35 bridge positive / 18 bridge negative)
error-payload hygiene: OK
```

---

## Phase 1 — Split the guard into a package

### Task 1: Build the identity harness (before any motion)

The split is only safe if it is provably inert. A green self-test is too weak — it would stay green if a whole rule silently stopped running. This task builds the evidence *first*.

**Files:**
- Create: `scripts/dev/payload_guard_identity.sh` (dev-only harness, not wired into CI)

**Interfaces:**
- Produces: `scripts/dev/payload_guard_identity.sh <outfile>` — writes a deterministic transcript of guard behaviour (self-test output + real-scan output + planted-violation scan output) to `<outfile>`. Task 5 diffs two such transcripts.

- [ ] **Step 1: Write the harness**

```bash
#!/usr/bin/env bash
# Dev-only: capture a deterministic transcript of the error-payload guard's
# OBSERVABLE BEHAVIOUR, for proving the #486 package split is inert.
#
# A green self-test is NOT sufficient evidence for code motion: it would stay
# green if a whole rule stopped running. This transcript additionally plants
# one violation per rule into a scratch copy of the tree and records the
# guard's full stderr — exercising the finding formatter, line numbers,
# allowlist keys and rule routing.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="${1:?usage: payload_guard_identity.sh <outfile>}"
GUARD="scripts/check-error-payload-hygiene.py"

# Plant one violation per rule. Paths are relative to a scratch tree copy.
# E1: a core variant interpolating a runtime String.
PLANT_E1_FILE="core/src/zz_identity_probe.rs"
PLANT_E1='#[derive(thiserror::Error, Debug)]
pub enum ZzIdentityProbe {
    #[error("planted E1: {leak}")]
    Leak { leak: String },
}
'
# E2: a bridge declaration with an ungated String field.
PLANT_E2_FILE="ffi/secretary-ffi-bridge/src/zz_identity_probe.rs"
PLANT_E2='#[derive(thiserror::Error, Debug)]
pub enum ZzProbeError {
    #[error("planted E2")]
    Leak { not_a_gated_name: String },
}
'
# E3: a gated field built from an unsanctioned expression.
PLANT_E3_FILE="ffi/secretary-ffi-bridge/src/zz_identity_probe_e3.rs"
PLANT_E3='fn zz_probe(e: &std::io::Error) -> crate::error::vault::FfiVaultError {
    crate::error::vault::FfiVaultError::CorruptVault { detail: format!("planted E3: {e}") }
}
'
# E4: an impl GatedDetail outside detail.rs.
PLANT_E4_FILE="ffi/secretary-ffi-bridge/src/zz_identity_probe_e4.rs"
PLANT_E4='impl crate::error::detail::GatedDetail for secretary_core::vault::VaultError {}
'

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
# Copy only what the guard reads, so the transcript is fast and stable.
mkdir -p "$scratch/scripts" "$scratch/core" "$scratch/ffi"
cp -R "$REPO_ROOT/scripts/." "$scratch/scripts/"
cp -R "$REPO_ROOT/core/src" "$scratch/core/src"
cp -R "$REPO_ROOT/ffi/." "$scratch/ffi/"

{
  echo "=== self-test ==="
  (cd "$scratch" && uv run "$GUARD" --self-test 2>&1) || true
  echo "exit=$?"

  echo "=== real scan, clean tree ==="
  (cd "$scratch" && uv run "$GUARD" 2>&1) || true

  printf '%s' "$PLANT_E1" > "$scratch/$PLANT_E1_FILE"
  printf '%s' "$PLANT_E2" > "$scratch/$PLANT_E2_FILE"
  printf '%s' "$PLANT_E3" > "$scratch/$PLANT_E3_FILE"
  printf '%s' "$PLANT_E4" > "$scratch/$PLANT_E4_FILE"

  echo "=== real scan, four planted violations ==="
  (cd "$scratch" && uv run "$GUARD" 2>&1) || true
} > "$OUT"

echo "wrote $OUT ($(wc -l < "$OUT") lines)"
```

- [ ] **Step 2: Capture the pre-split baseline**

Run:
```bash
cd /Users/hherb/src/secretary/.worktrees/486-guard-residual-closeout
chmod +x scripts/dev/payload_guard_identity.sh
bash scripts/dev/payload_guard_identity.sh /tmp/guard-identity-BEFORE.txt
```
Expected: the transcript contains `self-test: OK (40 positive / 18 negative / 35 bridge positive / 18 bridge negative)`, a clean `error-payload hygiene: OK`, and a planted-violation section reporting **exactly 4 violations**, one per rule E1/E2/E3/E4.

- [ ] **Step 3: Verify the harness is discriminating (mutation check)**

Temporarily comment out the `findings += scan_bridge_gated_detail_impls(...)` call in `run_real_scan`, re-run the harness to `/tmp/guard-identity-MUTANT.txt`, and confirm `diff /tmp/guard-identity-BEFORE.txt /tmp/guard-identity-MUTANT.txt` is NON-empty (the E4 planted violation disappears). Restore the line and re-confirm the diff is empty.

Expected: mutation produces a diff; restore produces none. If the mutation does NOT produce a diff, the harness is not discriminating and Task 5's gate is worthless — fix the harness before proceeding.

- [ ] **Step 4: Commit**

```bash
git add scripts/dev/payload_guard_identity.sh
git commit -m "test(guard): identity harness for the #486 package split

Captures the guard's OBSERVABLE behaviour — self-test output, clean-tree
scan, and a scan with one planted violation per rule E1-E4 — so the package
split can be gated on behavioural identity rather than merely a green
self-test, which would stay green if a whole rule stopped running.

Mutation-verified: dropping the scan_bridge_gated_detail_impls call from
run_real_scan changes the transcript.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Extract config, lexer, and types

Pure motion. Move symbols verbatim; the only edits permitted are `import` lines and the docstring paragraphs that move with their symbol.

**Files:**
- Create: `scripts/payload_guard/__init__.py`, `scripts/payload_guard/config.py`, `scripts/payload_guard/lexer.py`, `scripts/payload_guard/types.py`
- Modify: `scripts/check-error-payload-hygiene.py`

**Interfaces:**
- Produces: `payload_guard.config` exports `REPO_ROOT`, `SCAN_ROOT`, `BRIDGE_SCAN_ROOT`, `DETAIL_MODULE_REL`, `ALLOWLIST_PATH`, `DATA_FREE_TYPES`, `GATED_FIELD_NAMES`, `LOCAL_USE_ROOTS`.
- Produces: `payload_guard.lexer` exports `KIND_DELIM`, `KIND_LITERAL`, `lex_spans`, `render_view`, `strip_comments`, `discovery_view`, `balanced_slice`, `balanced_braces`, `string_literal_token_ends`, `LEXER_SAMPLE`.
- Produces: `payload_guard.types` exports `Finding`, `strip_visibility`, `normalize_type`, `strip_field_attrs`, `is_data_free`, `_is_data_free_core`, `is_bridge_field_safe`, `alias_shadowed_names`.

- [ ] **Step 1: Create the package skeleton**

```python
# scripts/payload_guard/__init__.py
"""The error-payload hygiene guard (#474, #480, #486).

Split out of the former single-file `scripts/check-error-payload-hygiene.py`
in #486. That file remains the ONE documented entry point — CLAUDE.md, CI
(`.github/workflows/test.yml`) and `core/tests/error_payload_hygiene_parity.rs`
all name it, and it keeps the PEP 723 header. This package holds the
implementation.

Read `scripts/check-error-payload-hygiene.py`'s module docstring first: it
carries the WHY and the LIMITS, and points at the module holding each detail.
"""
```

- [ ] **Step 2: Move `config.py`**

Move, verbatim, from `check-error-payload-hygiene.py`: `REPO_ROOT`, `SCAN_ROOT`, `BRIDGE_SCAN_ROOT`, `DETAIL_MODULE_REL`, `ALLOWLIST_PATH` (currently lines 320-332), `DATA_FREE_TYPES` (336-349), `GATED_FIELD_NAMES` (359-383), and `LOCAL_USE_ROOTS` (find it with `grep -n 'LOCAL_USE_ROOTS' scripts/check-error-payload-hygiene.py`). Keep every comment.

`REPO_ROOT` must resolve identically. In the entry point it was `Path(__file__).resolve().parent.parent`; in `payload_guard/config.py` the file is one level deeper, so it becomes:

```python
# `scripts/payload_guard/config.py` -> repo root is three parents up.
# (It was two in the pre-#486 single-file entry point at `scripts/`.)
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
```

- [ ] **Step 3: Move `lexer.py` and `types.py`**

`lexer.py` takes lines 1229-1428 (`_ident_char`, `lex_spans`, `_lex_quoted`, `render_view`, `strip_comments`, `discovery_view`) plus `balanced_slice` (1460-1482), `balanced_braces` (2978-3000), `string_literal_token_ends` (2402-2437), and `LEXER_SAMPLE`. Add `from .config import ...` only where a moved symbol referenced one.

`types.py` takes lines 384-615 (`strip_visibility`, `normalize_type`, `strip_field_attrs`, `_is_data_free_core`, `alias_shadowed_names`, `is_data_free`, `is_bridge_field_safe`) plus the `Finding` dataclass (1430-1459).

- [ ] **Step 4: Import them from the entry point**

At the top of `scripts/check-error-payload-hygiene.py`, after the PEP 723 header and docstring, replace the moved definitions with:

```python
from payload_guard.config import (
    ALLOWLIST_PATH, BRIDGE_SCAN_ROOT, DATA_FREE_TYPES, DETAIL_MODULE_REL,
    GATED_FIELD_NAMES, LOCAL_USE_ROOTS, REPO_ROOT, SCAN_ROOT,
)
from payload_guard.lexer import (
    LEXER_SAMPLE, balanced_braces, balanced_slice, discovery_view, lex_spans,
    render_view, string_literal_token_ends, strip_comments,
)
from payload_guard.types import (
    Finding, alias_shadowed_names, is_bridge_field_safe, is_data_free,
    normalize_type, strip_field_attrs, strip_visibility,
)
```

- [ ] **Step 5: Verify behaviour is unchanged**

Run:
```bash
uv run scripts/check-error-payload-hygiene.py --self-test
uv run scripts/check-error-payload-hygiene.py
```
Expected: `self-test: OK (40 positive / 18 negative / 35 bridge positive / 18 bridge negative)` and `error-payload hygiene: OK`.

- [ ] **Step 6: Commit**

```bash
git add scripts/payload_guard scripts/check-error-payload-hygiene.py
git commit -m "refactor(guard): extract config, lexer and types into payload_guard/ (#486)

Pure code motion, no behaviour change. Entry-point path, PEP 723 header and
both documented invocations are unchanged.

REPO_ROOT gains a third .parent — config.py sits one level deeper than the
former single-file entry point.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Extract discovery and allowlist

**Files:**
- Create: `scripts/payload_guard/discovery.py`, `scripts/payload_guard/allowlist.py`
- Modify: `scripts/check-error-payload-hygiene.py`

**Interfaces:**
- Consumes: `payload_guard.config`, `payload_guard.lexer`, `payload_guard.types` from Task 2.
- Produces: `payload_guard.discovery` exports `non_module_block_spans`, `cfg_test_spans`, `discovery_cfg_test_spans`, `_inside`, `find_type_aliases`, `find_consts`, `find_const_shadows`, `resolve_consts`, `top_level_mod_names`, `_use_bound_names`, `foreign_use_names`, `_looks_like_use_tree`, `_scan_use_bindings`, `module_path_segments`, `discover_declarations`, `enclosing_enum_names`, `_owning_enum_name`, `discover_error_struct_declarations`, `discover_error_struct_names`, `discover_scanned_error_type_names`, `_discover_tier_inputs`.
- Produces: `payload_guard.allowlist` exports `load_allowlist`.

- [ ] **Step 1: Move the symbols**

`discovery.py` takes lines 616-1228 (span passes through `discover_declarations`), 1911-1962 (`enclosing_enum_names`, `_owning_enum_name`), 2195-2220 (`discovery_cfg_test_spans`), 2883-2977 (`discover_error_struct_declarations`, `discover_error_struct_names`), and 3036-3140 (`_discover_tier_inputs`, `discover_scanned_error_type_names`). `allowlist.py` takes 3001-3035 (`load_allowlist`).

- [ ] **Step 2: Update the entry point's imports**

```python
from payload_guard.allowlist import load_allowlist
from payload_guard.discovery import (
    _discover_tier_inputs, _inside, cfg_test_spans, discover_declarations,
    discover_scanned_error_type_names, discovery_cfg_test_spans,
    enclosing_enum_names, find_consts, find_type_aliases, foreign_use_names,
    module_path_segments, non_module_block_spans, resolve_consts,
    top_level_mod_names,
)
```

- [ ] **Step 3: Verify**

Run: `uv run scripts/check-error-payload-hygiene.py --self-test && uv run scripts/check-error-payload-hygiene.py`
Expected: `40 / 18 / 35 / 18` and `OK`.

- [ ] **Step 4: Commit**

```bash
git add -A scripts/
git commit -m "refactor(guard): extract discovery and allowlist into payload_guard/ (#486)

Pure code motion, no behaviour change.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Extract the four rules and the scan driver

**Files:**
- Create: `scripts/payload_guard/rules/__init__.py`, `rules/e1.py`, `rules/e2.py`, `rules/e3.py`, `rules/e4.py`, `scripts/payload_guard/scan.py`
- Modify: `scripts/check-error-payload-hygiene.py`

**Interfaces:**
- Produces: `rules.e1` exports `scan_source`, `skip_attributes`, `parse_fields`, `split_top_level`, `extract_placeholders`, and the E1 regexes.
- Produces: `rules.e2` exports `bridge_declaration_findings`, `_bridge_plain_enum_variant_findings`, `_bridge_plain_struct_findings`, `scan_bridge_plain_declarations`.
- Produces: `rules.e3` exports `sanctioned_constructor_names`, `initializer_end`, `initializer_is_gated`, `scan_bridge_construction_sites`, `GATED_INIT_RE`, `DETAIL_CALL_RE`.
- Produces: `rules.e4` exports `is_detail_module`, `impl_header_before`, `impl_target_text`, `scan_bridge_gated_detail_impls`, `IMPL_GATED_ANCHOR_RE`, `SCANNED_IMPL_ROOTS`, and the six `E4_*` reason codes.
- Produces: `payload_guard.scan` exports `run_real_scan`.

- [ ] **Step 1: Move the rules**

`rules/e1.py`: lines 1483-1621 (`skip_attributes`, `parse_fields`, `split_top_level`, `extract_placeholders`) and 1622-1910 (`scan_source`). `rules/e2.py`: 1963-2194 and 2221-2342. `rules/e3.py`: 2343-2400 (`sanctioned_constructor_names`, `GATED_INIT_RE`, `DETAIL_CALL_RE`) and 2438-2621. `rules/e4.py`: 2624-2882.

`rules/__init__.py` stays empty except for a one-line docstring:

```python
"""One module per rule. E1 scans both roots; E2/E3/E4 are bridge rules.
See the entry point's docstring for the full four-rule statement."""
```

- [ ] **Step 2: Move `run_real_scan` into `scan.py`**

Move lines 3141-3256 verbatim.

- [ ] **Step 3: Update the entry point's imports**

```python
from payload_guard.rules.e1 import scan_source
from payload_guard.rules.e2 import scan_bridge_plain_declarations
from payload_guard.rules.e3 import (
    sanctioned_constructor_names, scan_bridge_construction_sites,
)
from payload_guard.rules.e4 import scan_bridge_gated_detail_impls
from payload_guard.scan import run_real_scan
```

- [ ] **Step 4: Verify**

Run: `uv run scripts/check-error-payload-hygiene.py --self-test && uv run scripts/check-error-payload-hygiene.py`
Expected: `40 / 18 / 35 / 18` and `OK`.

- [ ] **Step 5: Commit**

```bash
git add -A scripts/
git commit -m "refactor(guard): extract rules E1-E4 and the scan driver (#486)

Pure code motion, no behaviour change. One module per rule, so the #486
additions (three new E3 candidate forms, rule E5) land in a file a reviewer
can hold in context.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Extract the controls and self-test; prove identity

**Files:**
- Create: `scripts/payload_guard/controls/__init__.py`, `controls/core.py`, `controls/bridge.py`, `scripts/payload_guard/selftest.py`
- Modify: `scripts/check-error-payload-hygiene.py`, `core/tests/error_payload_hygiene_parity.rs`

**Interfaces:**
- Produces: `controls.core` exports `POSITIVE_CONTROLS`, `NEGATIVE_CONTROLS`. `controls.bridge` exports `BRIDGE_POSITIVE_CONTROLS`, `BRIDGE_NEGATIVE_CONTROLS`, `SELF_TEST_DETAIL_SRC`.
- Produces: `payload_guard.selftest` exports `run_self_test`, `scan_control`, `scan_bridge_control`, `ControlExpectation`, `_finding_matches`, `check_view_invariants`, `check_key_shape`, `check_bridge_key_distinctness`.

- [ ] **Step 1: Move the control corpora and the harness**

`controls/core.py`: lines 3263-~4400 (`POSITIVE_CONTROLS`, `NEGATIVE_CONTROLS`). `controls/bridge.py`: the `BRIDGE_*` lists plus `SELF_TEST_DETAIL_SRC` (4824-4845). `selftest.py`: 4681-4823 and 4848-5029.

- [ ] **Step 2: Reduce the entry point to a dispatcher**

The entry point keeps its PEP 723 header, the WHY-THIS-EXISTS narrative, THE RULE, THE BRIDGE RULES and the LIMITS summary — with each LIMIT naming the module that owns it — and ends with:

```python
import sys

from payload_guard.scan import run_real_scan
from payload_guard.selftest import run_self_test

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        sys.exit(run_self_test())
    sys.exit(run_real_scan())
```

- [ ] **Step 3: Fix the parity test's module loader**

`spec_from_file_location` does NOT put the script's directory on `sys.path`, so the entry point's `from payload_guard...` imports would raise `ModuleNotFoundError`. In `core/tests/error_payload_hygiene_parity.rs`, replace the embedded probe script with:

```python
import importlib.util as u, pathlib, sys
# #486: the guard is now a package under scripts/. `spec_from_file_location`
# does not add the script's directory to sys.path, so the entry point's
# `from payload_guard...` imports would fail without this line.
sys.path.insert(0, str(pathlib.Path(sys.argv[1]).resolve().parent))
spec = u.spec_from_file_location("guard", sys.argv[1])
mod = u.module_from_spec(spec)
sys.modules["guard"] = mod
spec.loader.exec_module(mod)
entries = mod.load_allowlist(pathlib.Path(sys.argv[2]))
print("YES" if sys.argv[3] in entries else "NO")
```

The entry point must therefore keep re-exporting `load_allowlist` (`from payload_guard.allowlist import load_allowlist`) so `mod.load_allowlist` still resolves.

- [ ] **Step 4: Run the identity gate — the whole point of Phase 1**

Run:
```bash
bash scripts/dev/payload_guard_identity.sh /tmp/guard-identity-AFTER.txt
diff /tmp/guard-identity-BEFORE.txt /tmp/guard-identity-AFTER.txt && echo "IDENTICAL"
```
Expected: `IDENTICAL` — an empty diff. A non-empty diff means the motion changed behaviour; find and fix the difference before committing. Do NOT update the baseline to match.

- [ ] **Step 5: Run the parity test**

Run: `cargo test --release --workspace --test error_payload_hygiene_parity`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add -A scripts/ core/tests/error_payload_hygiene_parity.rs
git commit -m "refactor(guard): extract controls and self-test; entry point is now a dispatcher (#486)

Completes the package split. Behavioural identity PROVEN, not assumed: the
identity harness transcript (self-test + clean scan + one planted violation
per rule E1-E4) diffs to empty across the whole split.

error_payload_hygiene_parity.rs's probe needed a sys.path.insert —
spec_from_file_location does not add the script's directory to sys.path, so
the entry point's package imports would have raised ModuleNotFoundError.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Phase 2 — The four closures

### Task 6: #482 — pin the fail-open half of `foreign_use_names`

**Files:**
- Modify: `scripts/payload_guard/discovery.py` (docstring), `scripts/payload_guard/controls/core.py` (add P40)
- Modify: `docs/superpowers/plans/2026-08-05-474-error-payload-hygiene.md` (companion 2)
- Modify: `scripts/check-error-payload-hygiene.py` (LIMIT 4 enumeration, companion 1)

**Interfaces:**
- Consumes: `controls.core.POSITIVE_CONTROLS` from Task 5.

- [ ] **Step 1: Write the failing control**

Append to `POSITIVE_CONTROLS` in `scripts/payload_guard/controls/core.py`:

```python
    (
        "P40 an INLINE block comment inside a use tree must not hide the "
        "`use` from the withdrawal pass. P38/P39 pin the RAW half of "
        "`foreign_use_names`' union; this pins the COMMENTS-BLANKED half, "
        "which was the one direction the self-test did not cover (#482). "
        "The raw read returns [] for this shape — an inline comment breaks "
        "`_looks_like_use_tree`'s adjacency filter — so the blanked read is "
        "solely load-bearing here. Pointing the pass at the raw source "
        "ALONE left the entire self-test green at exit 0, which is "
        "fail-OPEN in the one pass where hiding text GRANTS trust",
        '''
        mod local {
            #[derive(thiserror::Error, Debug)]
            pub enum Error {
                #[error("inner failure code {code}")]
                Failure { code: u32 },
            }
        }

        use std::/*why*/io::Error;

        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("io: {0}")]
            BareIoError(#[from] Error),
        }
        ''',
        {"variant": "BareIoError", "field": "0", "field_type": "#[from] Error"},
    ),
```

- [ ] **Step 2: Verify it passes at baseline and fails under the mutation**

Run: `uv run scripts/check-error-payload-hygiene.py --self-test`
Expected: `self-test: OK (41 positive / 18 negative / 35 bridge positive / 18 bridge negative)` — P40 fires at baseline.

Then mutate `foreign_use_names` in `discovery.py` to the raw read alone:

```python
    names = _scan_use_bindings(raw, local_roots, require_use_tree=True)
    # MUTATION (temporary): blanked half removed.
```

Run the self-test again. Expected: FAIL, with exactly `POSITIVE control did not fire: P40 …` and nothing else. Restore the union.

- [ ] **Step 3: Verify the symmetric mutation still breaks only P38/P39**

Mutate `foreign_use_names` to the comments-blanked read alone. Run the self-test. Expected: FAIL naming exactly P38 and P39 — NOT P40. Restore.

This two-sided result is the acceptance criterion in #482: neither half's removal may leave the self-test green, and each breaks a distinct control.

- [ ] **Step 4: Amend the `foreign_use_names` docstring for polarity**

In `discovery.py`, replace the paragraph beginning `THIS PASS DELIBERATELY READS THE RAW SOURCE` — keep its existing text and append:

```
    BOTH HALVES OF THE UNION ARE LOAD-BEARING, AND BOTH ARE NOW PINNED.
    P38/P39 fail if this pass reads the BLANKED view alone (an unterminated
    block comment runs to end-of-input and swallows the `use`). P40 fails if
    it reads the RAW source alone (`use std::/*why*/io::Error;` — the inline
    comment breaks `_looks_like_use_tree`'s adjacency filter, so the raw read
    returns nothing). Until #482 only the first direction was covered, and
    the uncovered one is the fail-OPEN direction: this is the single pass in
    this guard where HIDING text GRANTS trust rather than withholding it, so
    "blanking can only ever HIDE text, therefore discovery is fail-closed" —
    true for the three CREDIT registries — is FALSE here. That asymmetry is
    exactly what made the missing control easy to miss.
```

- [ ] **Step 5: Fix companion 1 — LIMIT 4's wrong enumeration**

In `scripts/check-error-payload-hygiene.py`'s LIMITS section, the text reading `Note that rustc closed only the type usize = String; costume of this (non_camel_case_types, a -D warnings error here); CborFault is already CamelCase and compiled clean.` is wrong on the enumeration. Replace with:

```
  Note that rustc closes only the LOWERCASE costumes of this:
  `type usize = String;` and `type bool = String;` both trip
  `non_camel_case_types` (a `-D warnings` error here). A CamelCase shadow
  — `type CborFault = String;` — is lint-invisible and compiled clean,
  which is the shape that matters. P34-P36 pin all three.
```

- [ ] **Step 6: Fix companion 2 — the stale #478 plan citations**

`docs/superpowers/plans/2026-08-05-474-error-payload-hygiene.md` says at `:1222`, `:2438` and `:2531` that #478 owns the whole bridge-unscanned gap. PR #479 corrected every live site and PR #489 closed #478. Add a dated correction note at each of the three sites:

```markdown
> **Correction (2026-08-08, #486):** this passage predates PR #479/#489.
> #478 was closed the broad way by #480 — `ffi/secretary-ffi-bridge/src/**`
> is a scan root, gated by rules E2/E3/E4. The remaining unscanned crates
> were the two BINDING WRAPPERS, which #486 closes. This plan is a
> historical execution artifact; it is not updated in place.
```

- [ ] **Step 7: Run and commit**

Run: `uv run scripts/check-error-payload-hygiene.py --self-test && uv run scripts/check-error-payload-hygiene.py`
Expected: `41 / 18 / 35 / 18` and `OK`.

```bash
git add -A scripts/ docs/
git commit -m "fix(guard): pin the fail-open half of foreign_use_names — control P40 (#482)

foreign_use_names WITHDRAWS credits, so hiding a `use` from it RESTORES one.
Its union of a raw and a comments-blanked read had only the raw half pinned:
P38/P39 fail if the pass reads the blanked view alone, but the symmetric
mutation — reading the raw source alone — left the entire self-test GREEN at
exit 0, in the one pass whose failure direction is fail-open.

P40 pins the other half with the shape #482 names: `use std::/*why*/io::Error;`
(raw read yields [], blanked read yields ['Error']). Mutation-proven both
ways — raw-only breaks exactly P40, blanked-only breaks exactly P38/P39.

Also corrects LIMIT 4's enumeration (`type bool = String;` warns too; only
CamelCase shadows are lint-invisible) and dates three stale #478 citations
in the #474 plan.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: #488 — `let` and assignment become E3 candidates

Closes laundering shapes 1, 2 and 3 with no dataflow: a `let` binding to a gated name is *itself* a construction of a gated value, so gating its initializer catches the launder at the point it happens.

**Files:**
- Modify: `scripts/payload_guard/rules/e3.py`
- Modify: `scripts/payload_guard/controls/bridge.py`
- Modify: `scripts/error-payload-hygiene-allowlist.txt` (1 entry — budget: 2 for the branch)
- Modify: `scripts/check-error-payload-hygiene.py` (LIMITS)

**Interfaces:**
- Consumes: `rules.e3.scan_bridge_construction_sites`, `initializer_is_gated`, `initializer_end` from Task 4.
- Produces: `rules.e3.GATED_LET_RE`, `rules.e3.GATED_ASSIGN_RE`.

- [ ] **Step 1: Write the failing controls**

Append to `BRIDGE_POSITIVE_CONTROLS` in `controls/bridge.py`:

```python
    (
        "BP36 #488 shape 2/3: a `let` binding to a gated name launders any "
        "expression through E3's arm 4. The `let` is ITSELF a construction "
        "of a gated value, so it is a candidate in its own right — no "
        "dataflow needed",
        ''' fn f(e: &std::io::Error) -> String { let detail = format!("{e}"); detail } ''',
        {"rule": "E3", "field": "detail"},
    ),
    (
        "BP37 #488 shape 2/3 with `mut` — the binding form must not be a "
        "bypass",
        ''' fn f(e: &std::io::Error) -> String { let mut detail = format!("{e}"); detail } ''',
        {"rule": "E3", "field": "detail"},
    ),
    (
        "BP38 #488 shape 1: post-construction assignment is a WRITE, which "
        "the initializer-position rule never saw",
        ''' fn f(x: &mut E, e: &std::io::Error) { x.detail = format!("{e}"); } ''',
        {"rule": "E3", "field": "detail"},
    ),
```

Append to `BRIDGE_NEGATIVE_CONTROLS`:

```python
    (
        "BN19 #488: a `let` bound to a SANCTIONED constructor call is the "
        "legitimate shape and must not fire",
        ''' fn f(e: &impl GatedDetail) -> String { let detail = detail::gated(e); detail } ''',
    ),
    (
        "BN20 #488: a PATTERN binding is the legitimate re-wrap the design "
        "mandates — it is not a `let`, and arm 4 keeps serving it",
        '''
        fn f(e: FfiVaultError) -> FfiVaultError {
            match e {
                FfiVaultError::CorruptVault { detail } => FfiVaultError::CorruptVault { detail },
            }
        }
        ''',
    ),
    (
        "BN21 #488: `==` is not an assignment — the assign rule must not "
        "match a comparison",
        ''' fn f(x: &E, s: &str) -> bool { x.detail == s } ''',
    ),
```

- [ ] **Step 2: Run to verify BP36-BP38 fail**

Run: `uv run scripts/check-error-payload-hygiene.py --self-test`
Expected: FAIL with three `POSITIVE control did not fire: BP36 / BP37 / BP38` lines, and no negative-control failures.

- [ ] **Step 3: Add the two candidate forms**

In `rules/e3.py`, beside `GATED_INIT_RE`:

```python
# #488 shapes 2 and 3: a `let` binding to a gated name. E3's arm 4 accepts an
# initializer that is the field's own name, which means
# `let detail = format!("{x}"); E::V { detail: detail }` — and the shorthand
# `E::V { detail }`, which produces no `detail:` token at all — launder any
# expression through a local variable.
#
# The closure needs no dataflow: a `let` binding to a gated name IS a
# construction of a gated value, so its initializer is gated by the same test
# as a field's. The launder becomes the candidate. Pattern bindings
# (`FfiVaultError::X { detail } =>`) and function parameters produce no `let`
# and are untouched — which is what lets arm 4 stay as it is.
#
# `(?!=)` excludes `==`; `let` cannot introduce a comparison, but the same
# guard on GATED_ASSIGN_RE below genuinely matters, so both carry it for
# symmetry and to keep a future edit from splitting the behaviour.
GATED_LET_RE = re.compile(
    r"\blet\s+(?:mut\s+)?(" + "|".join(sorted(GATED_FIELD_NAMES)) + r")\s*=(?!=)"
)
# #488 shape 1: post-construction assignment. `e.detail = format!("{x}")` is a
# WRITE, and the initializer-position rule never saw a write. `(?!=)` is
# load-bearing here — `x.detail == s` is a comparison, not a construction, and
# matching it would produce a false positive on every equality test.
GATED_ASSIGN_RE = re.compile(
    r"\.\s*(" + "|".join(sorted(GATED_FIELD_NAMES)) + r")\s*=(?!=)"
)
```

- [ ] **Step 4: Make `scan_bridge_construction_sites` sweep all three forms**

Replace the single `for m in GATED_INIT_RE.finditer(depth_view):` loop with a loop over the three regexes, keeping the body identical:

```python
    findings: list[Finding] = []
    # THREE candidate forms, one shared gate (#480 initializer, #488 let and
    # assignment). Ordering is by match offset so findings stay in source
    # order regardless of which form produced them.
    candidates = sorted(
        [
            (m.start(), m.end(), m.group(1))
            for regex in (GATED_INIT_RE, GATED_LET_RE, GATED_ASSIGN_RE)
            for m in regex.finditer(depth_view)
        ]
    )
    for m_start, m_end, name in candidates:
        if _inside(m_start, excluded):
            continue
        start, end = m_end, initializer_end(depth_view, m_end)
        while start < end and src[start] in " \t\r\n":
            start += 1
        while end > start and src[end - 1] in " \t\r\n":
            end -= 1
        if initializer_is_gated(src, start, end, name, literal_ends, sanctioned):
            continue
        expr = " ".join(src[start:end].split()) or "<empty>"
        findings.append(
            Finding(
                path=path_label,
                line=src.count("\n", 0, m_start) + 1,
                source_line=" ".join(f"{name}: {expr}".split()),
                variant="<construction site>",
                field=name,
                field_type=expr,
                rule="E3",
            )
        )
    return findings
```

- [ ] **Step 5: Run to verify the controls pass**

Run: `uv run scripts/check-error-payload-hygiene.py --self-test`
Expected: `self-test: OK (41 positive / 18 negative / 38 bridge positive / 21 bridge negative)`.

- [ ] **Step 6: Mutation-verify each new form independently**

Remove `GATED_LET_RE` from the `candidates` comprehension; re-run. Expected: exactly BP36 and BP37 fail. Restore.
Remove `GATED_ASSIGN_RE`; re-run. Expected: exactly BP38 fails. Restore.
Drop the `(?!=)` from `GATED_ASSIGN_RE`; re-run. Expected: BN21 fires. Restore.

- [ ] **Step 7: Run the real scan and allowlist the one test-module site**

Run: `uv run scripts/check-error-payload-hygiene.py`
Expected: exactly ONE new E3 finding, at `ffi/secretary-ffi-bridge/src/repair/tests/mod.rs:205`.

That file is a test module gated in its PARENT (`#[cfg(test)] mod tests;`), which the guard's documented per-file `#[cfg(test)]` LIMIT cannot see from inside. Add to `scripts/error-payload-hygiene-allowlist.txt`, in Section 3 (highest review weight), the entry the LIMIT itself prescribes — read the finding's exact `source_line` from the guard's output and use it verbatim as column 3:

```
ffi/secretary-ffi-bridge/src/repair/tests/mod.rs	E3	<exact source_line from the guard output>	TEST-ONLY FILE: `mod tests` is #[cfg(test)]-gated in the PARENT (repair/mod.rs), which this guard cannot see from inside — the remedy its own per-file cfg(test) LIMIT prescribes. The RHS is format_uuid_hyphenated(&block_uuid), a data-free renderer over a [u8; 16] (hex digits and hyphens only). Never reaches a platform.
```

Re-run. Expected: `error-payload hygiene: OK`.

- [ ] **Step 8: Update the LIMITS docstring**

In `scripts/check-error-payload-hygiene.py`, the LIMITS entry beginning `RULE E3 IS A SYNTACTIC MATCH ON INITIALIZER POSITION` currently enumerates three open shapes. Replace the enumeration with:

```
- RULE E3 READS THREE CANDIDATE POSITIONS — a gated field's INITIALIZER
  (`detail: <expr>`), a `let` BINDING to a gated name
  (`let detail = <expr>`), and an ASSIGNMENT to one
  (`x.detail = <expr>`) — plus the `io::Error` payload position (see
  below). #488's three laundering shapes are closed by the second and
  third: a `let` binding to a gated name is ITSELF a construction of a
  gated value, so gating its initializer catches the launder where it
  happens, and no dataflow is required.
  WHAT REMAINS is arm 4's PARAMETER case: `fn f(detail: String) -> E {
  E::V { detail } }` trusts the name of a value this guard did not watch
  being built. The design mandates the re-wrap form and pattern bindings
  (`FfiVaultError::X { detail } =>`) take it legitimately, so the arm
  stays; the residual has shrunk from "any local binding" to "a function
  parameter named exactly like the field", and closing THAT needs
  interprocedural analysis, not a construction-site matcher.
```

- [ ] **Step 9: Commit**

```bash
git add -A scripts/
git commit -m "feat(guard): close #488's laundering shapes without dataflow (#488)

E3 gated one candidate position — a gated field's initializer — so three
ordinary Rust shapes laundered any expression past it: a post-construction
assignment (never an initializer), and a local `let` bound to a gated name
reaching the field by shorthand or by arm 4's same-name accept.

The issue framed these as needing dataflow. They do not. A `let` binding to
a gated name is ITSELF a construction of a gated value, so gating its
initializer catches the launder at the point it happens. Shapes 2 and 3
collapse into one new candidate form; shape 1 into a second.

Pattern bindings and function parameters produce no `let`, so the legitimate
re-wrap the design mandates is untouched and arm 4 stays.

Tree-wide cost: one site, a test module gated in its parent (allowlisted per
the remedy that LIMIT prescribes). BP36-BP38 / BN19-BN21 added, each
mutation-verified independently.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: #487 — the `io::Error` payload position

**Files:**
- Modify: `scripts/payload_guard/rules/e3.py`
- Modify: `scripts/payload_guard/controls/bridge.py`
- Modify: `ffi/secretary-ffi-bridge/src/error/detail.rs`, `ffi/secretary-ffi-bridge/src/repair/orchestration.rs`
- Modify: `scripts/error-payload-hygiene-allowlist.txt` (reason-column update only, no new entry)

**Interfaces:**
- Consumes: `rules.e3` candidate machinery from Task 7.
- Produces: `rules.e3.IO_ERROR_NEW_RE`, `rules.e3.IO_ERROR_OTHER_RE`, `rules.e3.IO_PAYLOAD_FIELD` (the synthetic candidate name).
- Produces: `detail::io_gated(context: &'static str, e: &impl GatedDetail) -> std::io::Error`.

- [ ] **Step 1: Write the failing controls**

Append to `BRIDGE_POSITIVE_CONTROLS`:

```python
    (
        "BP39 #487: `io::Error` is E4-allowlisted as a CARRIER — its Display "
        "renders whatever it was built with. A bridge site can mint one from "
        "a format!, hand it to core's VaultError::Io { source }, and reach a "
        "gated field through the allowlisted impl, bypassing E3 entirely "
        "because E3 gated the BRIDGE's initializer, not what feeds core's",
        ''' fn f(p: &std::path::Path) -> std::io::Error {
                std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{}", p.display()))
            } ''',
        {"rule": "E3", "field": "<io::Error payload>"},
    ),
    (
        "BP40 #487: the `other` constructor takes the payload as its FIRST "
        "argument — a distinct argument position from `new`",
        ''' fn f(e: &SomeError) -> std::io::Error { std::io::Error::other(e.to_string()) } ''',
        {"rule": "E3", "field": "<io::Error payload>"},
    ),
```

Append to `BRIDGE_NEGATIVE_CONTROLS`:

```python
    (
        "BN22 #487: a LITERAL payload is the shape the four production "
        "io::Error sites already use and must not fire",
        ''' fn f() -> std::io::Error { std::io::Error::new(std::io::ErrorKind::NotFound, "missing") } ''',
    ),
    (
        "BN23 #487: a payload built through a sanctioned constructor passes, "
        "which is what makes the rewrite of repair/orchestration.rs possible",
        ''' fn f(e: &impl GatedDetail) -> std::io::Error {
                std::io::Error::new(std::io::ErrorKind::InvalidData, detail::gated(e))
            } ''',
    ),
```

- [ ] **Step 2: Run to verify BP39/BP40 fail**

Run: `uv run scripts/check-error-payload-hygiene.py --self-test`
Expected: FAIL naming BP39 and BP40.

- [ ] **Step 3: Add the io payload candidate form**

In `rules/e3.py`:

```python
# #487: `std::io::Error` is E4-allowlisted as a CARRIER — unlike ParseIntError,
# its Display renders whatever it was CONSTRUCTED with, so its safety is a
# claim about producers, not about the type. A bridge site can mint one from a
# runtime string, fold it into core's `VaultError::Io { source }`, and reach a
# gated field via that impl — a path E3's initializer rule never crossed,
# because it gates the BRIDGE's own `detail:` expression, not what feeds
# core's.
#
# The payload argument therefore becomes a candidate position in its own
# right. `new` takes it SECOND (after the ErrorKind); `other` takes it FIRST.
#
# LIMIT, inherited from every rule here: this matches the trait/type spelled
# out. `use std::io::Error;` followed by a bare `Error::new(...)` is invisible,
# the same aliasing blind spot rule E4 records for `GatedDetail`.
IO_ERROR_NEW_RE = re.compile(
    r"(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*io\s*::\s*Error\s*::\s*new\s*\("
)
IO_ERROR_OTHER_RE = re.compile(
    r"(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*io\s*::\s*Error\s*::\s*other\s*\("
)
# The synthetic `field` name reported for an io payload finding. Deliberately
# NOT a valid Rust identifier: `initializer_is_gated`'s arm 4 (and shape 5)
# compare the expression against the field NAME, and an io payload has no
# field name to re-wrap, so a name no expression can equal keeps those arms
# structurally unreachable here rather than relying on them happening not to
# match.
IO_PAYLOAD_FIELD = "<io::Error payload>"


def io_payload_candidates(depth_view: str) -> list[tuple[int, int, str]]:
    """`(match_start, payload_start, IO_PAYLOAD_FIELD)` for every
    `io::Error::new(kind, PAYLOAD)` and `io::Error::other(PAYLOAD)` in
    `depth_view` (#487).

    For `new`, the payload begins after the first top-level comma inside the
    call — located with `initializer_end`, which stops at exactly that comma.
    A call with no top-level comma (a macro-built argument list, a `new` with
    one argument that does not compile) yields NO candidate rather than a
    mis-sliced one; that is the fail-closed reading for a helper whose job is
    to find a slice, since a wrong slice would be classified as some OTHER
    expression and could be accepted.
    """
    out: list[tuple[int, int, str]] = []
    for m in IO_ERROR_OTHER_RE.finditer(depth_view):
        out.append((m.start(), m.end(), IO_PAYLOAD_FIELD))
    for m in IO_ERROR_NEW_RE.finditer(depth_view):
        comma = initializer_end(depth_view, m.end())
        if comma >= len(depth_view) or depth_view[comma] != ",":
            continue
        out.append((m.start(), comma + 1, IO_PAYLOAD_FIELD))
    return out
```

Then extend the `candidates` list in `scan_bridge_construction_sites`:

```python
    candidates = sorted(
        [
            (m.start(), m.end(), m.group(1))
            for regex in (GATED_INIT_RE, GATED_LET_RE, GATED_ASSIGN_RE)
            for m in regex.finditer(depth_view)
        ]
        + io_payload_candidates(depth_view)
    )
```

- [ ] **Step 4: Run the self-test**

Run: `uv run scripts/check-error-payload-hygiene.py --self-test`
Expected: `41 / 18 / 40 / 23`.

- [ ] **Step 5: Mutation-verify**

Remove `+ io_payload_candidates(depth_view)`; re-run. Expected: exactly BP39 and BP40 fail. Restore.
In `io_payload_candidates`, change `IO_ERROR_NEW_RE`'s payload start from `comma + 1` to `m.end()` (i.e. gate the ErrorKind instead of the payload); re-run. Expected: BN22 fires (the `ErrorKind::NotFound` path is not an accepted shape). Restore.

- [ ] **Step 6: Add the sanctioned constructor**

In `ffi/secretary-ffi-bridge/src/error/detail.rs`, after `counted`:

```rust
/// Build a `std::io::Error` whose payload is gated (#487).
///
/// `std::io::Error` is allowlisted for `GatedDetail` as a CARRIER: its
/// `Display` renders whatever it was constructed with, so — unlike
/// `ParseIntError` — its safety is a claim about every construction site,
/// not about the type. Guard rule E3 treats the payload argument of
/// `io::Error::new` / `io::Error::other` as a construction site for exactly
/// that reason, and this is the sanctioned way to satisfy it.
pub(crate) fn io_gated(
    kind: std::io::ErrorKind,
    context: &'static str,
    e: &impl GatedDetail,
) -> std::io::Error {
    std::io::Error::new(kind, gated_with_context(context, e))
}
```

Add a unit test in that file's `mod tests`, asserting on message CONTENT (per #475's discipline — asserting only on error TYPE is how the #472 wrapper regression shipped unnoticed):

```rust
    #[test]
    fn io_gated_renders_context_and_display() {
        let inner = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let e = io_gated(std::io::ErrorKind::InvalidData, "read state", &inner);
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(e.to_string(), "read state: gone");
    }
```

- [ ] **Step 7: Rewrite the one production site**

`ffi/secretary-ffi-bridge/src/repair/orchestration.rs:137-147` currently builds
`std::io::Error::new(ErrorKind::InvalidData, format!("{e}; state file path: {}; ...", path.display()))`.

Read the exact current expression first (`sed -n '130,150p' ffi/secretary-ffi-bridge/src/repair/orchestration.rs`). Replace the `format!` with a `detail::io_gated` call carrying a `&'static str` context. The state-dir path was part of the old message; `io_gated` takes no path, so if the path is judged necessary for diagnosis, add a second constructor taking `(&'static str, &Path, &impl GatedDetail)` — a `Path` is the already-disclosed class per allowlist Section 2, and adding it is a reviewed decision to record in the commit message. Otherwise drop it.

- [ ] **Step 8: Update the E4 allowlist reason column**

In `scripts/error-payload-hygiene-allowlist.txt`, the `impl GatedDetail for std::io::Error` entry's reason says the orchestration.rs site is "currently safe, but producer-dependent like Section 3, not type-safe" and names re-review on any NEW io::Error construction site as its trigger. Amend it: the in-root half is now CI-enforced by rule E3's io-payload candidate position (#487), so the trigger is discharged for `ffi/secretary-ffi-bridge/src/**`; `cli/src/daemon.rs:424` remains outside every scan root and unreachable from any gated fold. Keep the CARRIER claim itself — the rule gates producers in the bridge, not in `core`.

- [ ] **Step 9: Run the gates and commit**

Run:
```bash
uv run scripts/check-error-payload-hygiene.py --self-test && uv run scripts/check-error-payload-hygiene.py
cargo test --release -p secretary-ffi-bridge
cargo clippy --release --workspace --tests -- -D warnings
```
Expected: self-test `41 / 18 / 40 / 23`; real scan `OK`; tests and clippy green.

```bash
git add -A scripts/ ffi/secretary-ffi-bridge/
git commit -m "feat(guard): gate the io::Error payload position (#487)

std::io::Error is E4-allowlisted as a CARRIER: its Display renders whatever
it was built with, so its safety is a claim about producers. A bridge site
could mint one from a runtime string, fold it into core's VaultError::Io {
source }, and reach a gated field through that impl — E3 gated the bridge's
own `detail:` expression, never what fed core's.

The payload argument is now a candidate position: second for io::Error::new,
first for io::Error::other. detail::io_gated is the sanctioned way to satisfy
it. The four production sites passing string literals are accepted unchanged;
repair/orchestration.rs — the exact site #487 names — is rewritten.

cli/src/daemon.rs:424 is the same shape outside every scan root and
unreachable from any gated fold; it stays out of scope and the E4 allowlist
reason column now says so.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 9: #486 (guard half) — scan roots, shape 5, and the `ScanRoot` model

This task extends the guard only. It is EXPECTED to end with the real scan RED at 14 findings; Task 10 turns it green. Commit the red state — it is the burn-down meter, exactly as #480's three rewrite waves were.

**Files:**
- Create: `scripts/payload_guard/roots.py`
- Modify: `scripts/payload_guard/config.py`, `scripts/payload_guard/scan.py`, `scripts/payload_guard/rules/e3.py`, `scripts/payload_guard/selftest.py`, `scripts/payload_guard/controls/` (new `wrapper.py`)

**Interfaces:**
- Produces: `payload_guard.roots.ScanRoot` and `payload_guard.roots.SCAN_ROOTS: tuple[ScanRoot, ...]`.
- Produces: `rules.e3.initializer_is_gated(..., allow_field_access: bool)` and `scan_bridge_construction_sites(..., allow_field_access: bool = False)`.
- Produces: `selftest.scan_wrapper_control(src, path_label=..., detail_src=...)`.

- [ ] **Step 1: Define the root model**

```python
# scripts/payload_guard/roots.py
"""Which rules run over which source tree, and with what settings (#486).

Before #486 the roots were two module-level constants and `run_real_scan`
open-coded which rules applied to each. Adding the two binding wrapper crates
made that untenable — they take E1/E2/E3 and the NEW rule E5, but NOT E4, and
they take an E3 acceptance (shape 5) the bridge deliberately does not get.
Spelling each root's rule set out as data keeps "which rules apply here" a
thing a reviewer reads rather than infers.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .config import REPO_ROOT


@dataclass(frozen=True)
class ScanRoot:
    """One scanned source tree and the rules that apply to it."""

    label: str
    """Human-readable name, used in self-test failure messages only."""

    path: Path
    """Tree to walk for `*.rs`."""

    detail_module_rel: str | None
    """Repo-relative path of this root's sanctioned-constructor module, or
    `None` when the root has none (core). A root whose module is MISSING
    yields an EMPTY sanctioned set and therefore denies every `detail::*`
    call — `sanctioned_constructor_names`' fail-closed hinge, preserved
    per-root."""

    bridge_mode: bool
    """Rule E1's carve-out plus rule E2's two declaration sweeps."""

    construction_sites: bool
    """Rule E3."""

    gated_detail_impls: bool
    """Rule E4. Bridge only: `GatedDetail` is `pub(crate)` in the bridge, so
    no other crate can implement it even if a future author tried, and E4's
    premise — the set of types a detail string can be built from is exactly
    the set of impls in one reviewed file — is unaffected by the new roots."""

    format_confinement: bool
    """Rule E5 (#486). Wrapper crates only — see `rules/e5.py` for why the
    bridge is excluded (its `format!` mostly builds filenames)."""

    allow_field_access: bool
    """Rule E3 shape 5: accept `a.uuid_hex` for field `uuid_hex`. Wrapper
    roots only. It is a new ACCEPTANCE, so granting it where nothing needs it
    would open a laundering door for free — all four DTO pass-through sites
    are in the wrapper crates."""


SCAN_ROOTS: tuple[ScanRoot, ...] = (
    ScanRoot(
        label="core",
        path=REPO_ROOT / "core" / "src",
        detail_module_rel=None,
        bridge_mode=False,
        construction_sites=False,
        gated_detail_impls=False,
        format_confinement=False,
        allow_field_access=False,
    ),
    ScanRoot(
        label="bridge",
        path=REPO_ROOT / "ffi" / "secretary-ffi-bridge" / "src",
        detail_module_rel="ffi/secretary-ffi-bridge/src/error/detail.rs",
        bridge_mode=True,
        construction_sites=True,
        gated_detail_impls=True,
        format_confinement=False,
        allow_field_access=False,
    ),
    ScanRoot(
        label="ffi-py",
        path=REPO_ROOT / "ffi" / "secretary-ffi-py" / "src",
        detail_module_rel="ffi/secretary-ffi-py/src/detail.rs",
        bridge_mode=True,
        construction_sites=True,
        gated_detail_impls=False,
        format_confinement=True,
        allow_field_access=True,
    ),
    ScanRoot(
        label="ffi-uniffi",
        path=REPO_ROOT / "ffi" / "secretary-ffi-uniffi" / "src",
        detail_module_rel="ffi/secretary-ffi-uniffi/src/detail.rs",
        bridge_mode=True,
        construction_sites=True,
        gated_detail_impls=False,
        format_confinement=True,
        allow_field_access=True,
    ),
)
```

- [ ] **Step 2: Rewrite `run_real_scan` over `SCAN_ROOTS`**

Replace the two hand-written loops in `scan.py` with one loop over `SCAN_ROOTS`. Discovery stays PER ROOT — a wrapper-local alias/const/enum must not vouch for a bridge or core field, or vice versa. Rule E4's registry keeps reading core + bridge sources only.

```python
def run_real_scan() -> int:
    allowlist = load_allowlist(ALLOWLIST_PATH)
    sources: dict[str, list[tuple[str, str]]] = {
        r.label: [
            (str(rs.relative_to(REPO_ROOT)), rs.read_text(encoding="utf-8"))
            for rs in sorted(r.path.rglob("*.rs"))
        ]
        for r in SCAN_ROOTS
    }
    # Pass 1, ONCE PER ROOT — see `_discover_tier_inputs`. Cross-root vouching
    # is exactly what this separation exists to prevent.
    tiers = {label: _discover_tier_inputs(srcs) for label, srcs in sources.items()}

    # Rule E4's registry stays CORE + BRIDGE: the impls in error/detail.rs name
    # core types far more often than bridge-local ones, and no wrapper crate
    # can implement the `pub(crate)` trait at all.
    core_enums = tiers["core"][0]
    bridge_enums = tiers["bridge"][0]
    scanned_error_type_names = discover_scanned_error_type_names(
        sources["core"], sources["bridge"], core_enums, bridge_enums
    )

    violations: list[Finding] = []
    for root in SCAN_ROOTS:
        enums, aliases, consts = tiers[root.label]
        detail_src = (
            next(
                (
                    raw
                    for label, raw in sources[root.label]
                    if label.replace("\\", "/") == root.detail_module_rel
                ),
                None,
            )
            if root.detail_module_rel
            else None
        )
        sanctioned = sanctioned_constructor_names(detail_src)
        for label, raw in sources[root.label]:
            foreign = foreign_use_names(raw)
            findings = scan_source(
                label, raw, enums, aliases, consts, foreign,
                bridge_mode=root.bridge_mode,
            )
            if root.bridge_mode:
                findings += scan_bridge_plain_declarations(
                    label, raw, enums, aliases, foreign
                )
            if root.construction_sites:
                findings += scan_bridge_construction_sites(
                    label, raw, sanctioned,
                    allow_field_access=root.allow_field_access,
                )
            if root.gated_detail_impls:
                findings += scan_bridge_gated_detail_impls(
                    label, raw, scanned_error_type_names
                )
            for f in findings:
                if f"{f.path}\t{f.rule}\t{f.source_line}" in allowlist:
                    continue
                violations.append(f)
    # ... existing reporting block, unchanged ...
```

- [ ] **Step 3: Write the failing controls for shape 5**

Create `scripts/payload_guard/controls/wrapper.py` with `WRAPPER_POSITIVE_CONTROLS` / `WRAPPER_NEGATIVE_CONTROLS` lists, and add a `scan_wrapper_control` to `selftest.py` that runs the wrapper-root rule set (`bridge_mode=True`, `construction_sites=True` with `allow_field_access=True`, no E4). Wire both lists into `run_self_test` with the same fired/not-fired logic the bridge lists use, and extend the count line to report them.

```python
WRAPPER_POSITIVE_CONTROLS: list[tuple] = [
    (
        "WP1 shape 5 trusts the FINAL SEGMENT only: a field access whose "
        "last segment is NOT the gated field's own name is not a "
        "pass-through and must deny",
        ''' fn f(a: &A) -> E { E::V { uuid_hex: a.some_other_field } } ''',
        {"rule": "E3", "field": "uuid_hex"},
    ),
    (
        "WP2 a hand-rolled format! into a gated field denies in a wrapper "
        "root exactly as it does in the bridge — shape 5 widens the accepted "
        "set, it does not disable the rule",
        ''' fn f(n: usize) -> E { E::V { detail: format!("got {n}") } } ''',
        {"rule": "E3", "field": "detail"},
    ),
]

WRAPPER_NEGATIVE_CONTROLS: list[tuple] = [
    (
        "WN1 shape 5: the DTO pass-through `uuid_hex: a.uuid_hex` is the "
        "shape all four live sites take. It is arm 4's name-trust one level "
        "deeper — it trusts that a field named `uuid_hex` was gated where "
        "ITS type declared it, which rules E2/E3 in the bridge do establish "
        "for these four",
        ''' fn f(a: A) -> E { E::V { uuid_hex: a.uuid_hex } } ''',
    ),
]
```

Also add a BRIDGE control pinning that shape 5 does NOT leak into the bridge root:

```python
    (
        "BP41 #486: E3 shape 5 (field access) is scoped to the WRAPPER roots "
        "and must still DENY in the bridge, where nothing needs it. A new "
        "acceptance granted where it is not required is a laundering door "
        "for free",
        ''' fn f(a: A) -> E { E::V { uuid_hex: a.uuid_hex } } ''',
        {"rule": "E3", "field": "uuid_hex"},
    ),
```

- [ ] **Step 4: Run to verify WN1 and BP41 fail**

Run: `uv run scripts/check-error-payload-hygiene.py --self-test`
Expected: FAIL — `NEGATIVE control fired: WN1` (shape 5 not implemented yet) and BP41 passing already. WP1/WP2 should already pass.

- [ ] **Step 5: Implement shape 5**

In `rules/e3.py`, add the parameter and the arm:

```python
# Rule E3 shape 5 (#486): a FIELD ACCESS whose final segment is the gated
# field's own name — `uuid_hex: a.uuid_hex`. Wrapper roots only.
FIELD_ACCESS_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)+$")
```

In `initializer_is_gated`, add the `allow_field_access` parameter and, after arm 4:

```python
    # (5) a field access ending in the gated name — the DTO pass-through
    #     (#486). WRAPPER ROOTS ONLY.
    #
    #     THIS ARM TRUSTS A NAME, one level deeper than arm 4 does: it claims
    #     that a field spelled `uuid_hex` on some OTHER type was gated where
    #     THAT type declared it. For the four live sites that claim holds —
    #     the source is a bridge DTO whose field rules E2/E3 gate — but it is
    #     a trust RELATION, not provenance, and this comment says so rather
    #     than dressing it up. It is scoped to the wrapper roots because all
    #     four sites are there; granting it in the bridge would open the same
    #     door for nothing in return (BP41 pins that).
    if allow_field_access and FIELD_ACCESS_RE.match(stripped):
        if stripped.split(".")[-1].strip() == name:
            return True
```

- [ ] **Step 6: Run the self-test, then the real scan**

Run: `uv run scripts/check-error-payload-hygiene.py --self-test`
Expected: OK, with the wrapper counts now included in the count line.

Run: `uv run scripts/check-error-payload-hygiene.py`
Expected: **RED — exactly 10 E3 findings**, all `InvalidArgument` construction sites in `ffi/secretary-ffi-uniffi/src/namespace/{mod,repair}.rs`. The four DTO sites are now accepted by shape 5. If the count is not 10, reconcile against §1.1 of the spec before continuing.

- [ ] **Step 7: Mutation-verify shape 5's scoping**

Change `allow_field_access=True` to `False` for both wrapper roots in `roots.py`; re-run the self-test. Expected: WN1 fires. Restore.
Change the bridge root's `allow_field_access` to `True`; re-run. Expected: BP41 stops firing (a positive control that did not fire). Restore.

- [ ] **Step 8: Commit the red state**

```bash
git add -A scripts/
git commit -m "feat(guard): scan the binding wrapper crates; E3 shape 5 (#486)

Roots become data (payload_guard/roots.py) rather than two constants plus
open-coded rule selection in run_real_scan, because the wrapper crates take
E1/E2/E3 and E5 but NOT E4, and take an E3 acceptance the bridge does not.

Shape 5 accepts a field access whose final segment is the gated field's own
name — the DTO pass-through. #486 predicted these already passed via arm 4;
they do not (a.uuid_hex is not the token uuid_hex), which is one of four
ways its census was wrong. Scoped to the wrapper roots: all four live sites
are there, and a new acceptance granted where nothing needs it is a
laundering door for free (BP41 pins the bridge still denying).

Real scan is RED at 10 findings — the InvalidArgument construction sites in
the uniffi namespace layer. Task 10 turns it green. Committing red on
purpose: the burn-down is the progress meter, as in #480.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 10: #486 (Rust half) — wrapper `detail.rs` modules and `&'static str`

**Files:**
- Create: `ffi/secretary-ffi-uniffi/src/detail.rs`, `ffi/secretary-ffi-py/src/detail.rs`
- Modify: `ffi/secretary-ffi-uniffi/src/lib.rs`, `ffi/secretary-ffi-py/src/lib.rs` (module declarations)
- Modify: `ffi/secretary-ffi-uniffi/src/namespace/mod.rs`, `namespace/repair.rs`

**Interfaces:**
- Produces: `detail::arg_len(field: &'static str, expected: usize, got: usize) -> String`
- Produces: `detail::indexed_arg_len(field: &'static str, index: usize, expected: usize, got: usize) -> String`
- Produces: `detail::range(context: &'static str, min: u32, max: u32) -> String`
- Produces: `uuid_from_vec(bytes: &[u8], field: &'static str)`, `array32_from_vec(bytes: &[u8], field: &'static str)`

- [ ] **Step 1: Write the uniffi detail module with its tests**

```rust
// ffi/secretary-ffi-uniffi/src/detail.rs
//! The ONLY place in this crate permitted to build an error detail string.
//!
//! #480 pinned the BRIDGE's detail strings to one reviewed file. This crate
//! sat outside that gate: `uuid_from_vec(bytes: &[u8], field: &str)` took a
//! `&str`, so its 45 call sites could hand it any runtime value, and two of
//! them already passed a `format!`. Nothing leaked — the interpolated values
//! were loop indices — but the SIGNATURE admitted a decrypted field name,
//! which is structurally what #481 was.
//!
//! Every constructor here takes `&'static str`, integers, or an
//! already-gated bridge value. There is no parameter through which a runtime
//! string can enter. Guard rules E3 and E5 enforce that this module is the
//! only source of these strings (`scripts/check-error-payload-hygiene.py`).

/// `<field> must be <expected> bytes, got <got>`.
pub(crate) fn arg_len(field: &'static str, expected: usize, got: usize) -> String {
    format!("{field} must be {expected} bytes, got {got}")
}

/// `arg_len` for an element of a caller-supplied list: the INDEX is an
/// integer this crate computed, never caller-supplied text.
pub(crate) fn indexed_arg_len(
    field: &'static str,
    index: usize,
    expected: usize,
    got: usize,
) -> String {
    format!("{field}[{index}] must be {expected} bytes, got {got}")
}

/// `<context>: [<min>, <max>]` — a bounds violation carrying only integers.
pub(crate) fn range(context: &'static str, min: u32, max: u32) -> String {
    format!("{context}: [{min}, {max}]")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arg_len_renders_field_and_both_lengths() {
        assert_eq!(arg_len("device_uuid", 16, 3), "device_uuid must be 16 bytes, got 3");
    }

    #[test]
    fn indexed_arg_len_renders_the_index() {
        assert_eq!(
            indexed_arg_len("approvals.block_uuid", 2, 16, 5),
            "approvals.block_uuid[2] must be 16 bytes, got 5"
        );
    }

    #[test]
    fn range_renders_both_bounds() {
        assert_eq!(range("settings out of range", 1, 90), "settings out of range: [1, 90]");
    }
}
```

- [ ] **Step 2: Tighten the two validator signatures and rewrite their bodies**

In `ffi/secretary-ffi-uniffi/src/namespace/mod.rs`:

```rust
/// Validate a 16-byte UUID slice; surface wrong length as
/// [`VaultError::InvalidArgument`] with the field name in the detail.
///
/// `field` is `&'static str`, not `&str` (#486): the detail string reaches
/// both platform UIs and their logs, so the parameter must be incapable of
/// carrying a runtime value. Two callers used to pass `&format!(...)`.
pub(crate) fn uuid_from_vec(bytes: &[u8], field: &'static str) -> Result<[u8; 16], VaultError> {
    bytes.try_into().map_err(|_| VaultError::InvalidArgument {
        detail: crate::detail::arg_len(field, 16, bytes.len()),
    })
}

pub(crate) fn array32_from_vec(bytes: &[u8], field: &'static str) -> Result<[u8; 32], VaultError> {
    bytes.try_into().map_err(|_| VaultError::InvalidArgument {
        detail: crate::detail::arg_len(field, 32, bytes.len()),
    })
}
```

- [ ] **Step 3: Rewrite the four indexed call sites**

`namespace/repair.rs:52`, `:55`, `:59`, `:65` pass `&format!("approvals[{idx}].block_uuid")` and similar. Those four are the reason `field` was `&str`. They need the index carried as an integer instead. Add index-aware wrappers beside the validators in `namespace/mod.rs`:

```rust
/// [`uuid_from_vec`] for an element of a caller-supplied list. The index is
/// an integer this crate computed; it never becomes caller-supplied text.
pub(crate) fn uuid_from_vec_at(
    bytes: &[u8],
    field: &'static str,
    index: usize,
) -> Result<[u8; 16], VaultError> {
    bytes.try_into().map_err(|_| VaultError::InvalidArgument {
        detail: crate::detail::indexed_arg_len(field, index, 16, bytes.len()),
    })
}

/// [`array32_from_vec`] for an element of a caller-supplied list.
pub(crate) fn array32_from_vec_at(
    bytes: &[u8],
    field: &'static str,
    index: usize,
) -> Result<[u8; 32], VaultError> {
    bytes.try_into().map_err(|_| VaultError::InvalidArgument {
        detail: crate::detail::indexed_arg_len(field, index, 32, bytes.len()),
    })
}
```

Rewrite the four sites to call these with `"approvals.block_uuid"` / `"approvals.file_fingerprint"` / `"approvals.committed_fingerprint"` / `"approvals.added_recipients"` and the loop index. The nested `added_recipients[j]` site carries two indices; use `indexed_arg_len` with `j` and fold `idx` into the `&'static str`? No — that would need a runtime string. Instead pass `j` as the index and use the static label `"approvals.added_recipients"`; losing the outer index is acceptable and must be stated in the commit message as a deliberate diagnostic reduction, since recovering it would require exactly the runtime-string parameter this task removes.

- [ ] **Step 4: Rewrite the settings-bounds site**

`namespace/mod.rs:818-822` builds `format!("settings out of range: [{}, {}]", e.min, e.max)`. Replace with `crate::detail::range("settings out of range", e.min, e.max)`. Check `e.min`/`e.max`'s actual types first (`grep -n 'struct SettingsBoundsError' -A6 -r ffi/secretary-ffi-bridge/src/`) and match `range`'s signature to them.

- [ ] **Step 5: Declare the module**

Add `mod detail;` to `ffi/secretary-ffi-uniffi/src/lib.rs`.

- [ ] **Step 6: Run the guard and the build**

Run:
```bash
uv run scripts/check-error-payload-hygiene.py
cargo test --release -p secretary-ffi-uniffi
cargo clippy --release --workspace --tests -- -D warnings
git diff main... -- ffi/secretary-ffi-uniffi/src/secretary.udl
```
Expected: guard `OK` (10 findings → 0); tests and clippy green; **the `.udl` diff EMPTY**.

- [ ] **Step 7: Build the downstream Kotlin module**

Per `project_secretary_conformance_scripts_dont_compile_kit`, a uniffi return-shape change can pass conformance yet break the `:kit` Gradle module. No signature crossing the FFI boundary changed here, but run it anyway:

```bash
cd android && ./gradlew :vault-access:test :kit:compileDebugKotlin
```
Expected: green.

- [ ] **Step 8: Commit**

```bash
git add -A ffi/ scripts/
git commit -m "fix(uniffi): route InvalidArgument details through a sanctioned module; &'static str (#486)

uuid_from_vec/array32_from_vec took `field: &str`, so their 45 call sites
could hand any runtime value into a detail string that reaches both platform
UIs and their logs. Two callers already passed a format!. Nothing leaked —
the interpolated values were loop indices — but the signature admitted a
decrypted field name, which is structurally what #481 was, one layer out
from where #480 closed it.

New crate-local detail.rs takes &'static str and integers only; there is no
parameter through which a runtime string can enter. The four indexed sites
get *_at variants carrying the index as an integer.

Deliberate diagnostic reduction: the nested added_recipients site loses its
OUTER loop index, because recovering it needs exactly the runtime-string
parameter this commit removes.

Guard: 10 findings -> 0. No .udl diff.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 11: Rule E5 — `format!` confinement in the wrapper crates

**Files:**
- Create: `scripts/payload_guard/rules/e5.py`, `ffi/secretary-ffi-py/src/detail.rs`
- Modify: `scripts/payload_guard/scan.py`, `selftest.py`, `controls/wrapper.py`, `ffi/secretary-ffi-py/src/*.rs`, `ffi/secretary-ffi-py/src/lib.rs`

**Interfaces:**
- Produces: `rules.e5.scan_wrapper_format_confinement(path_label, raw, detail_module_rel) -> list[Finding]`.

- [ ] **Step 1: Census the `.to_string()` receivers (the spec's open scope boundary)**

Run:
```bash
grep -rn '\.to_string()' ffi/secretary-ffi-py/src/ ffi/secretary-ffi-uniffi/src/ --include='*.rs' | grep -v '/tests' 
```
For each hit, record the receiver's type. Expected per the spec: every receiver in an error-mapping path is a bridge error type this guard already scans (`e: &FfiVaultError` and friends). **If any receiver is NOT an already-gated type, widen E5 to cover `.to_string()` on that shape and say so in the commit message.** Write the census into the commit message either way — this is the spec's one explicitly-open scope decision and it must be resolved by evidence, not assumption.

- [ ] **Step 2: Write the failing controls**

Append to `WRAPPER_POSITIVE_CONTROLS`:

```python
    (
        "WP3 rule E5: a hand-rolled format! anywhere in a wrapper crate "
        "outside its sanctioned detail.rs is a finding. This is the class E3 "
        "structurally CANNOT see — ffi-py's platform sink is "
        "`VaultNotAuthor::new_err(format!(...))`, a function ARGUMENT, not a "
        "gated-field initializer, so no extension of E3's initializer model "
        "reaches it. 30/30 production format! sites in these crates are "
        "error-bound, which is what makes confinement cost zero legitimate-"
        "use allowlist entries",
        ''' fn f(a: &str, b: &str) -> PyErr { VaultNotAuthor::new_err(format!("{a}/{b}")) } ''',
        {"rule": "E5"},
    ),
```

Append to `WRAPPER_NEGATIVE_CONTROLS`:

```python
    (
        "WN2 rule E5: format! INSIDE the sanctioned detail module is the "
        "whole point of having one",
        ''' pub(crate) fn arg_len(field: &'static str, n: usize) -> String { format!("{field}: {n}") } ''',
        {"path_label": "ffi/secretary-ffi-py/src/detail.rs"},
    ),
    (
        "WN3 rule E5: a #[cfg(test)] format! never reaches a platform — the "
        "10 `let rendered = format!(\"{err}\")` assertion sites in the uniffi "
        "errors/ modules are exactly this shape",
        '''
        #[cfg(test)]
        mod tests {
            #[test]
            fn renders() { let rendered = format!("{err}"); assert!(!rendered.is_empty()); }
        }
        ''',
    ),
```

- [ ] **Step 3: Run to verify WP3 fails**

Run: `uv run scripts/check-error-payload-hygiene.py --self-test`
Expected: FAIL with `POSITIVE control did not fire: WP3`.

- [ ] **Step 4: Implement rule E5**

```python
# scripts/payload_guard/rules/e5.py
"""Rule E5 (#486): the binding wrappers may not author error strings.

Rule E3 gates GATED-FIELD INITIALIZERS. The binding wrappers' platform sink
is not one:

    FfiVaultError::NotAuthor { expected_fingerprint_hex, got_fingerprint_hex }
        => VaultNotAuthor::new_err(format!("expected={expected_fingerprint_hex}, ...")),

That is a function ARGUMENT. No extension of E3's initializer model reaches
it, and modelling "which function arguments become platform errors" is the
dataflow problem #488 was reframed to avoid.

So gate the SOURCE instead of the sink: `format!` — the only construct in
these crates that COMPOSES a new string from runtime parts — is confined to
each crate's sanctioned `detail.rs`. Same move `SecretaryLog` makes for
logcat (#472), `diagnosticDetail` for `privacy: .public` (#467) and
`error/detail.rs` for the bridge (#480): do not police call sites, make the
unsafe call unrepresentable and review the one file that defines what safe
means.

WHY THE BRIDGE IS EXCLUDED. The asymmetry is empirical. In the wrapper
crates 100% of production `format!` is error-bound, so confinement costs
nothing. In the bridge it is not: the majority of its 24 sites build
FILENAMES — `format!("{}.cbor.enc", ...)`, `format!("{}.card", ...)` in
`record/`, `contacts/` (x5), `trash/`, `share/`, `sync/` — a legitimate,
non-error use. Confining `format!` there would buy one rule at the price of
~9 allowlist entries for path building, diluting exactly the signal the
allowlist's highest-weight sections exist to carry. The bridge's error
strings are already gated at their initializers by E3.

SCOPE: `format!`, not `.to_string()`. `format!` COMPOSES a new string from
runtime parts; `.to_string()` RENDERS one value's `Display`, and every
current receiver in the error-mapping path is a bridge error type this guard
already scans (censused in this rule's own commit). If that census ever
stops holding, this rule widens.

DETECTION runs on the DISCOVERY view (comments and string CONTENTS blanked),
so a `format!` written inside a string literal or a comment is not a site.
Like every rule here it reads TEXT: a `format!` produced by another macro is
invisible.
"""
from __future__ import annotations

import re

from ..discovery import _inside, discovery_cfg_test_spans
from ..lexer import discovery_view, strip_comments
from ..types import Finding

FORMAT_MACRO_RE = re.compile(r"\bformat\s*!\s*[\(\[\{]")


def scan_wrapper_format_confinement(
    path_label: str, raw: str, detail_module_rel: str | None
) -> list[Finding]:
    """Every `format!` outside this root's sanctioned detail module."""
    if detail_module_rel and path_label.replace("\\", "/") == detail_module_rel:
        return []
    depth_view = discovery_view(raw)
    src = strip_comments(raw)
    excluded = discovery_cfg_test_spans(raw)
    findings: list[Finding] = []
    for m in FORMAT_MACRO_RE.finditer(depth_view):
        if _inside(m.start(), excluded):
            continue
        line_start = src.rfind("\n", 0, m.start()) + 1
        line_end = src.find("\n", m.start())
        line_end = len(src) if line_end == -1 else line_end
        findings.append(
            Finding(
                path=path_label,
                line=src.count("\n", 0, m.start()) + 1,
                source_line=" ".join(src[line_start:line_end].split()),
                variant="<format! outside detail.rs>",
                field="format!",
                field_type=f"must be built in {detail_module_rel}",
                rule="E5",
            )
        )
    return findings
```

Wire it into `scan.py` under `if root.format_confinement:` and add an `E5` arm to the reporting block's `elif` chain:

```python
            elif v.rule == "E5":
                detail = (
                    f"`format!` outside the sanctioned detail module — "
                    f"{v.field_type}"
                )
```

- [ ] **Step 5: Run the self-test, then the real scan**

Run: `uv run scripts/check-error-payload-hygiene.py --self-test`
Expected: OK.

Run: `uv run scripts/check-error-payload-hygiene.py`
Expected: **RED at 16 E5 findings** in `ffi/secretary-ffi-py/src/` (the uniffi ones were removed in Task 10). Reconcile against the spec's §1.3 census before continuing.

- [ ] **Step 6: Mutation-verify**

Remove the `if detail_module_rel and path_label... return []` early return; re-run. Expected: WN2 fires. Restore.
Remove the `_inside(m.start(), excluded)` skip; re-run. Expected: WN3 fires. Restore.

- [ ] **Step 7: Write ffi-py's detail module**

Create `ffi/secretary-ffi-py/src/detail.rs` with the same header rationale as the uniffi one, holding constructors for every ffi-py `format!` shape found in Step 5. At minimum:

```rust
/// `expected=<a>, got=<b>` — both arguments are already-gated bridge fields
/// (`FfiVaultError::NotAuthor`'s two fingerprint hexes, gated by rules
/// E2/E3 in the bridge). This crate composes them; it does not author them.
pub(crate) fn fingerprint_mismatch(expected_hex: &str, got_hex: &str) -> String {
    format!("expected={expected_hex}, got={got_hex}")
}

/// `<block_uuid_hex>: <detail>` — the collapsed RepairRejected message this
/// crate's `create_exception!` convention requires. Python callers split on
/// the first `": "`; `block_uuid_hex` is a hyphenated UUID with no embedded
/// `": "`, so that split is exact. Both inputs are already-gated bridge
/// fields.
pub(crate) fn uuid_prefixed(block_uuid_hex: &str, detail: &str) -> String {
    format!("{block_uuid_hex}: {detail}")
}

/// `<field> must be <expected> bytes, got <got>` — the ValueError shape.
pub(crate) fn arg_len(field: &'static str, expected: usize, got: usize) -> String {
    format!("{field} must be {expected} bytes, got {got}")
}
```

Add a `mod tests` asserting each constructor's rendered CONTENT, per #475's discipline.

Add `mod detail;` to `ffi/secretary-ffi-py/src/lib.rs`.

Note the `&str` parameters on the first two: unlike uniffi's `field`, these take *already-gated bridge values*, which cannot be `&'static str`. That is the shape #486 calls "combines only already-gated values", and the safety claim is that both call sites destructure a bridge error whose fields rules E2/E3 gate. State that in the doc comment at each call site.

- [ ] **Step 8: Rewrite ffi-py's 16 sites**

Route each `format!` through the new module. Sites: `errors.rs:144,202,210,224`, `repair_preview.rs:190,202`, `device.rs:230,237,287`, `repair.rs:96,173,236,301,313`, `settings.rs:94`, `record.rs:230`. Read each one first; several are `PyValueError::new_err(format!(...))` argument-validation shapes that map onto `arg_len`.

- [ ] **Step 9: Run the gates and commit**

Run:
```bash
uv run scripts/check-error-payload-hygiene.py --self-test && uv run scripts/check-error-payload-hygiene.py
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
```
Expected: self-test OK; real scan `OK` (16 → 0); tests and clippy green.

```bash
git add -A scripts/ ffi/
git commit -m "feat(guard): rule E5 — the binding wrappers may not author error strings (#486)

E3 gates gated-field INITIALIZERS. ffi-py's platform sink is not one:
VaultNotAuthor::new_err(format!(...)) is a function ARGUMENT, so no
extension of E3's initializer model reaches it, and modelling which
arguments become platform errors is the dataflow problem #488 was reframed
to avoid.

So gate the source instead of the sink: format! is confined to each wrapper
crate's sanctioned detail.rs. Same move SecretaryLog makes for logcat (#472)
and diagnosticDetail for privacy: .public (#467).

Viable because 30/30 production format! sites in these crates are
error-bound — zero legitimate-use allowlist entries. The bridge is
deliberately excluded: the majority of ITS format! sites build filenames,
where confinement would cost ~9 entries for path building.

Scope: format!, not .to_string(). Receiver census in this commit confirms
every .to_string() in an error-mapping path renders an already-gated bridge
error type.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 12: Documentation

**Files:**
- Modify: `CLAUDE.md`, `scripts/check-error-payload-hygiene.py` (docstring), `scripts/error-payload-hygiene-allowlist.txt` (preamble)
- Check: `README.md`, `ROADMAP.md`

- [ ] **Step 1: Rewrite CLAUDE.md's residuals paragraph**

The section "Rust error payloads: data-free by construction (#474)" currently states gated-field construction is CI-enforced "with three named residuals" (#487, #488, macro/trait-alias) plus the wrapper boundary (#486). Rewrite: #487 and #488 are CLOSED structurally (io payload position; `let`/assignment candidate forms), #486 is closed by the wrapper scan roots plus rule E5, and the ONLY remaining limit is macro-generated code and trait aliasing — inherent to a text-based guard.

Per the baton's standing warning, this prose is load-bearing: if a future change reopens any of these, re-point it; if a new residual class appears, ADD it.

Also update the Commands block: the guard now covers four scan roots and five rules.

- [ ] **Step 2: Update the guard's own module docstring**

The `LIMITS` section must state the four candidate positions, five rules, four roots, and shape 5's wrapper scoping. Remove the three-shapes enumeration Task 7 already replaced; confirm no stale "the three re-wrap sites in the tree today" sentence survives.

- [ ] **Step 3: Update the allowlist preamble**

It says "This guard has FOUR rules (#474 + #480)". Make it five, name E5, and name the four roots.

- [ ] **Step 4: Check README.md and ROADMAP.md**

Run:
```bash
grep -n 'error-payload\|error payload\|#474\|#480\|#486' README.md ROADMAP.md
```
Decide per hit whether this slice changes it. Precedent from #474/#480: both files were verified unchanged, with the grep recorded as evidence. Record the grep output in the commit message whichever way it goes.

- [ ] **Step 5: Commit**

```bash
git add -A CLAUDE.md README.md ROADMAP.md scripts/ docs/
git commit -m "docs: the guard's three named residuals are closed (#486, #487, #488)

CLAUDE.md's error-payload section promised gated-field construction was
CI-enforced with three named residuals plus a review-only wrapper boundary.
All four are now structural: the io::Error payload position (#487), the let
and assignment candidate forms (#488), and the wrapper crates as scan roots
plus rule E5 (#486).

What remains is macro-generated code and trait aliasing, which are inherent
to a guard that reads text rather than expanded macros, and are stated as
such rather than dropped.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 13: Full gates, baton, PR

- [ ] **Step 1: Run every gate**

```bash
cd /Users/hherb/src/secretary/.worktrees/486-guard-residual-closeout
pwd && git branch --show-current
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all --check
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
uv run scripts/check-error-payload-hygiene.py --self-test && uv run scripts/check-error-payload-hygiene.py
uv run core/tests/python/conformance.py
bash ios/scripts/check-public-log-hygiene.sh --self-test && bash ios/scripts/check-public-log-hygiene.sh
bash android/scripts/check-log-hygiene.sh --self-test && bash android/scripts/check-log-hygiene.sh
bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
(cd desktop && pnpm test && pnpm run svelte-check)
(cd android && ./gradlew :vault-access:test :kit:compileDebugKotlin)
git diff main... -- ffi/secretary-ffi-uniffi/src/secretary.udl
```
Expected: all green; the `.udl` diff EMPTY.

- [ ] **Step 2: Verify the allowlist budget**

Run: `git diff main... -- scripts/error-payload-hygiene-allowlist.txt | grep -c '^+[^+#]'`
Expected: **at most 2** new entries. More means a rule is mis-shaped — stop and escalate per the Global Constraints.

- [ ] **Step 3: Verify every commit carries the trailer**

Run: `git log main..HEAD --format='%H %s' | while read -r sha _; do git log -1 --format='%(trailers:key=Co-Authored-By)' "$sha" | grep -q . || echo "MISSING: $sha"; done`

Note: on git 2.54 a `--format='%(trailers:...)'` over a RANGE appends a blank line per commit, so an `awk 'NF<2'` audit never returns empty. Check per-commit, as above.

- [ ] **Step 4: Write the baton and retarget the symlink**

Author `docs/handoffs/2026-08-08-486-guard-residual-closeout-shipped.md` covering: what shipped with SHAs, what's next with acceptance criteria, open decisions/risks, and exact resume commands. Then:

```bash
ln -snf docs/handoffs/2026-08-08-486-guard-residual-closeout-shipped.md NEXT_SESSION.md
ls -la NEXT_SESSION.md && head -3 NEXT_SESSION.md
git add docs/handoffs/ NEXT_SESSION.md
git commit -m "docs: session baton — #486/#482/#487/#488 shipped

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 5: Push and open the PR**

```bash
git push -u origin feature/486-guard-residual-closeout
gh pr create --title "Guard residual closeout: wrapper crates, io::Error carrier, laundering shapes, P40 (#486, #487, #488, #482)" --body "..."
```

The PR body must state which issues close and note that the four issues' own acceptance criteria were re-derived by execution (#486's census was wrong in four ways).

---

## Self-Review

**Spec coverage.** §3 (split) → Tasks 1-5. §4.1 (#488) → Task 7. §4.2 (#487) → Task 8. §4.3 (#486) → Tasks 9-10. §4.4 (#482) → Task 6. §4.5 (E5) → Task 11. §5 (testing) → controls in every rule task, plus Task 13's gate list. §6 (risks) → Task 1's identity harness, Task 11 Step 1's `.to_string()` census, Task 13 Step 2's allowlist budget. §7 (done) → Task 13.

**Ordering note.** #482 (Task 6) runs before the E3 work because it touches `discovery.py` and `controls/core.py`, which the later tasks do not, keeping its two-sided mutation proof uncontaminated by rule changes.

**Type consistency.** `initializer_is_gated` gains `allow_field_access: bool` in Task 9 and is called with it from `scan_bridge_construction_sites` in the same task. `arg_len` has the same `(field, expected, got)` signature in both wrapper crates. `io_gated` is defined in Task 8 and used in Task 8 only. `ScanRoot`'s field names are used verbatim in `run_real_scan`.

**Known count drift.** Self-test counts quoted per task (`41 / 18 / 40 / 23`, etc.) assume no other control is added; if a task adds an extra control, the expected line shifts and the ACTUAL count should be recorded in that task's commit message rather than forcing the quoted number.
