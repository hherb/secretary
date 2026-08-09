# `Detail` Newtype Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every gated error-payload position in the FFI bridge a newtype the compiler enforces, so a runtime `String` cannot reach one regardless of which laundering shape a future author uses.

**Architecture:** A `pub struct Detail(String)` with a private inner field lives in `ffi/secretary-ffi-bridge/src/error/detail.rs` — the file that is already the reviewed allowlist of what may become a detail string. All 27 gated bridge fields are declared `Detail`; the ten sanctioned constructors return `Detail`. Downstream crates can name and read a `Detail` but cannot build one, so `detail: format!(…)` stops typechecking everywhere. The guard's rule E3 stops *being* the bridge's enforcement and becomes defence in depth.

**Tech Stack:** Rust 1.97.0 (pinned, `rust-toolchain.toml`), `thiserror`, Cargo resolver v2, Python 3 guard package under `scripts/payload_guard/`, `uv` for all Python.

**Spec:** [`docs/superpowers/specs/2026-08-09-500-detail-newtype-design.md`](../specs/2026-08-09-500-detail-newtype-design.md)

## Global Constraints

- **Worktree:** `/Users/hherb/src/secretary/.worktrees/500-detail-newtype`, branch `feature/500-detail-newtype`. Every command below runs from there. Verify with `pwd && git branch --show-current` before any `cargo` / `git` call — shell state does NOT persist between tool calls.
- **Never edit via a bare `secretary/` path.** The Edit tool targets the MAIN checkout unless the path is spelled `.worktrees/500-detail-newtype/…`.
- `#![forbid(unsafe_code)]` is a workspace lint. Do not introduce `unsafe`.
- Clippy must stay clean with `-D warnings`, **both** with and without `--tests`.
- Python is `uv` only — never `pip` / `pip3` / `python -m pip`.
- **No FFI surface change.** `git diff main... -- ffi/secretary-ffi-uniffi/src/secretary.udl` must be EMPTY at the end. No `FfiVaultError` variant added, removed, or renamed; no field added or removed. `Detail` never crosses the FFI.
- **No `core/` change, no on-disk format change, no KAT regeneration.**
- Every commit carries the trailer `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`.
- Reference issues as `(#500)`, never `Closes #500` — this repo's convention.
- **Every commit must leave the real guard scan GREEN.** Task order exists specifically to achieve this (Task 2 widens, Task 4 tightens); do not collapse those two.

---

### Task 1: `Detail` type, `test-support` feature, and the CI gate that makes it real

The type lands first with **no field using it yet**, so the feature-gate guarantee is proven on the real workspace before anything depends on it. Spec §10 lists "§5.1 was verified on a synthetic workspace, not this one" as an open risk; this task closes it.

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/error/detail.rs` (add the type at the top, after the `use` block at line 19)
- Modify: `ffi/secretary-ffi-bridge/src/lib.rs` (re-export, near line 147 `pub use error::{FfiUnlockError, FfiVaultError};`)
- Modify: `ffi/secretary-ffi-bridge/Cargo.toml` (add `[features]`)
- Create: `scripts/check-test-support-placement.sh`
- Modify: `.github/workflows/test.yml` (two additions — see Steps 8 and 10)

**Interfaces:**
- Produces: `secretary_ffi_bridge::Detail` — `pub struct Detail(String)`, private inner field. Methods `pub fn as_str(&self) -> &str`, `pub fn into_string(self) -> String`. Implements `Display` and derives `Debug`, `Clone`, `PartialEq`, `Eq`. Under `#[cfg(feature = "test-support")]` only: `pub fn for_test(s: &str) -> Detail`.
- Produces: Cargo feature `test-support` on `secretary-ffi-bridge`, default OFF.

- [ ] **Step 1: Write the failing test**

> **AMENDED before execution (pre-flight finding PF1).** An earlier version of
> this task also changed `detail::gated`'s return type to `Detail` and appended
> `.into_string()` at its call sites as temporary scaffolding, undone in Task 3.
> That REDS the real guard scan — rule E3 accepts a sanctioned-constructor call
> only when the call is the WHOLE initializer, so `detail::gated(e).into_string()`
> is denied (proven with `payload_guard.selftest.scan_bridge_control`). It would
> have violated this plan's own Global Constraint that every commit leaves the
> scan green. **Task 1 now changes NO constructor and NO field.** `Detail` lands
> standalone; all ten constructors move together in Task 3, in the same commit as
> the fields, so a sanctioned call is never momentarily wrapped.

Append to the `mod tests` block at the bottom of `ffi/secretary-ffi-bridge/src/error/detail.rs` (it starts at line 191, `#[cfg(test)] mod tests {`):

```rust
    // `Detail`'s own behaviour. Every constructor still returns `String` at
    // this point (Task 3 moves them), so `for_test` is the only way to build
    // one — which is exactly the property under test: the type has no public
    // construction path outside `detail.rs`.
    #[cfg(feature = "test-support")]
    #[test]
    fn detail_renders_borrows_and_unwraps() {
        let runtime = String::from("built at runtime");
        let d = Detail::for_test(&runtime);
        assert_eq!(d.as_str(), "built at runtime");
        assert_eq!(format!("{d}"), "built at runtime");
        assert_eq!(d.clone().into_string(), "built at runtime");
    }
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/hherb/src/secretary/.worktrees/500-detail-newtype
cargo test --release -p secretary-ffi-bridge --features test-support --lib detail 2>&1 | tail -20
```
Expected: FAIL to compile — `cannot find type Detail in this scope` (and `error: none of the package's features are named test-support`, until Step 5 adds it). Both are expected; Steps 3 and 5 resolve them.

- [ ] **Step 3: Add the type — and change no constructor**

In `ffi/secretary-ffi-bridge/src/error/detail.rs`, immediately after the `use std::path::Path;` line (line 19), insert:

```rust
/// A diagnostic string built by a sanctioned constructor in THIS module.
///
/// The inner field is private, so a `Detail` is constructible only from
/// inside `detail.rs`. Every gated payload position in the bridge is declared
/// `Detail`, which makes `detail: format!(…)` — and every other way of
/// producing a `String`, including the pattern-bind, build-then-mutate,
/// function-parameter and dotless-reassignment shapes rule E3 cannot see — a
/// TYPE ERROR at every call site in this crate and in every downstream crate.
///
/// # What this type does and does not claim
///
/// It claims exactly one thing: **this string came out of a reviewed
/// constructor below.** It does NOT claim that a struct holding one carries
/// no secrets. `FfiAddedRecipient` and `FfiWideningReport`
/// (`crate::repair::preview`) deliberately carry decrypted plaintext in
/// sibling fields — `display_name`, `block_name` — which stay `String` and
/// must. A `Detail` beside a plaintext `String` is correct, not an
/// inconsistency to "clean up".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detail(String);

impl Detail {
    /// Borrow the rendered text. The only read path a wrapper crate needs
    /// that does not consume the value.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume into the owned `String` the binding wrapper crates project
    /// across the FFI (uniffi's `VaultError` must carry a UDL `string`;
    /// PyO3 exceptions take a message). This is a PROJECTION, not a gate —
    /// see the spec's §4.
    pub fn into_string(self) -> String {
        self.0
    }

    /// Test-only escape hatch, absent from every non-test build.
    ///
    /// Wrapper-crate unit tests construct `FfiVaultError` values directly and
    /// cannot otherwise obtain a `Detail`. Gated behind a non-default Cargo
    /// feature that only `[dev-dependencies]` enables, so under resolver v2
    /// this function DOES NOT EXIST in `cargo build --release`. That is
    /// enforced by `cargo build --release --workspace` in CI — verified by
    /// execution that `cargo test`, `cargo clippy --tests` and the rustdoc
    /// gate all compile a production call to it CLEAN.
    #[cfg(feature = "test-support")]
    pub fn for_test(s: &str) -> Detail {
        Detail(s.to_string())
    }
}

impl std::fmt::Display for Detail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
```

**Change nothing else.** All eleven constructors keep their current signatures, all 27 field declarations stay `String`, and no call site is touched. Task 3 moves them together. Adding `Detail` alone cannot break a build or the guard scan — nothing references it yet except its own test.

- [ ] **Step 4: Run test to verify it passes**

```bash
cd /Users/hherb/src/secretary/.worktrees/500-detail-newtype
cargo test --release -p secretary-ffi-bridge --features test-support --lib detail 2>&1 | tail -15
cargo test --release -p secretary-ffi-bridge --lib detail 2>&1 | tail -15
```
Expected: the first PASSES and includes `detail_renders_borrows_and_unwraps`. The second also passes but SKIPS that test (the feature is off, so it is not compiled) — confirm by comparing the two test counts. Run Step 5 first if `--features test-support` errors with "none of the package's features are named test-support".

A `dead_code` warning on `as_str` / `into_string` is expected at this point — nothing calls them until Task 3. `-D warnings` would turn that into an error, so add `#[allow(dead_code)]`? **No** — do not silence it. `Detail` is `pub` and re-exported in Step 6, so it is part of the crate's public API and `dead_code` does not fire on public items. If a warning does appear, it means the re-export in Step 6 is missing or wrong; fix the export rather than the warning.

- [ ] **Step 5: Add the Cargo feature**

In `ffi/secretary-ffi-bridge/Cargo.toml`, add after the `[dependencies]` section:

```toml
[features]
# Test-only escape hatch for `Detail::for_test` (#500). NOT default, and
# enabled ONLY under a `[dev-dependencies]` line — see
# `scripts/check-test-support-placement.sh`, which fails CI if it ever
# appears on a normal dependency. Under resolver v2 a dev-dependency feature
# is not unified into a non-test build, so `cargo build --release` genuinely
# does not contain `for_test`.
test-support = []
```

- [ ] **Step 6: Re-export the type**

In `ffi/secretary-ffi-bridge/src/lib.rs`, change line 147 from:

```rust
pub use error::{FfiUnlockError, FfiVaultError};
```
to:
```rust
// `Detail` is re-exported out of the `pub(crate) mod detail` so downstream
// crates can NAME and READ one (`as_str` / `into_string` / `Display`) while
// remaining unable to CONSTRUCT one — the private inner field is the whole
// mechanism (#500).
pub use error::detail::Detail;
pub use error::{FfiUnlockError, FfiVaultError};
```

- [ ] **Step 7: Verify the feature-gate matrix on the REAL workspace**

This is the task's real deliverable. Plant a production call, run all five gates, record the results, then revert the plant.

**Never use `git checkout <file>` to remove the probe** — Steps 1-6 are still uncommitted, and `git checkout` would discard all of them. The probe is appended and removed by exact-text match instead.

```bash
cd /Users/hherb/src/secretary/.worktrees/500-detail-newtype

# Append the probe: a PRODUCTION fn (not #[cfg(test)]) reaching for the hatch.
cat >> ffi/secretary-ffi-bridge/src/error/detail.rs <<'EOF'
// ---- TEMPORARY PROBE (#500 Task 1 Step 7) ----
pub fn probe_launder(runtime: String) -> Detail {
    Detail::for_test(&runtime)
}
// ---- END TEMPORARY PROBE ----
EOF

echo "--- A) cargo build --release --workspace  (MUST FAIL) ---"
cargo build --release --workspace 2>&1 | grep -E "^error" | head -3
echo "--- B) cargo clippy --release --workspace, no --tests  (MUST FAIL) ---"
cargo clippy --release --workspace 2>&1 | grep -E "^error" | head -3
echo "--- C) cargo test --release --workspace  (expect 0) ---"
cargo test --release --workspace 2>&1 | grep -cE "^error"
echo "--- D) cargo clippy --release --workspace --tests  (expect 0) ---"
cargo clippy --release --workspace --tests 2>&1 | grep -cE "^error"
echo "--- E) rustdoc gate  (expect 0) ---"
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace 2>&1 | grep -cE "^error"
```

Remove the probe by exact-text match, then confirm it is gone:

```bash
cd /Users/hherb/src/secretary/.worktrees/500-detail-newtype
python3 - <<'PY'
import pathlib, sys
p = pathlib.Path("ffi/secretary-ffi-bridge/src/error/detail.rs")
s = p.read_text()
start = s.index("// ---- TEMPORARY PROBE (#500 Task 1 Step 7) ----")
end = s.index("// ---- END TEMPORARY PROBE ----") + len("// ---- END TEMPORARY PROBE ----\n")
p.write_text(s[:start] + s[end:])
print("probe removed")
PY
grep -c "probe_launder" ffi/secretary-ffi-bridge/src/error/detail.rs   # expect 0
cargo build --release --workspace 2>&1 | grep -cE "^error"             # expect 0
```

Expected: **A and B** each print an `error[E0599]` (or `error[E0433]`) line; **C, D and E** each print `0`. If A or B print nothing, **STOP** — the feature is not isolating, and the entire `test-support` design in the spec is invalid. Report that rather than working around it; it invalidates Task 1's premise and the spec needs revising before any later task runs.

Record the five observed outcomes in the Step 12 commit message.

- [ ] **Step 8: Add the CI build gate**

In `.github/workflows/test.yml`, in the `cargo test` job (job starts line 33), insert BEFORE the existing `cargo test --release --workspace` step at line 69:

```yaml
      # A NON-TEST build. Every other gate in this repo compiles the crate
      # WITH dev-dependency features unified, so a production call to the
      # `test-support`-gated `Detail::for_test` compiles clean through
      # `cargo test`, `cargo clippy --tests` AND the rustdoc gate (verified by
      # execution, #500). Only a non-test build catches it. Without this step
      # the feature gate is decorative.
      - name: cargo build --release --workspace
        run: cargo build --release --workspace
```

- [ ] **Step 9: Write the placement guard with its self-test**

Create `scripts/check-test-support-placement.sh`. The `test-support` feature is only isolating while it is enabled exclusively from `[dev-dependencies]`; one normal-dependency line silently defeats it. Follow the house pattern (`--self-test` proves the matcher fires on a known-positive control before the real scan is trusted):

```bash
#!/usr/bin/env bash
# Assert the bridge's `test-support` feature is enabled ONLY from a
# [dev-dependencies] section (#500).
#
# `Detail::for_test` can mint a `Detail` from a runtime String. It is absent
# from non-test builds ONLY because resolver v2 declines to unify a
# DEV-dependency's features into them. Enabling the feature on a NORMAL
# dependency line puts the hatch into the shipped artifact, and nothing else
# in CI would notice. That single line is what this guard denies.
set -euo pipefail

readonly FEATURE="test-support"
readonly DEV_SECTION="dev-dependencies"

# Print every manifest section that enables $FEATURE, as "<file>:<section>".
scan() {
    local root="$1"
    find "$root" -name Cargo.toml -not -path '*/target/*' -print0 |
    while IFS= read -r -d '' f; do
        awk -v feat="$FEATURE" -v file="$f" '
            /^\[/ { section = $0; gsub(/[][]/, "", section) }
            index($0, feat) && index($0, "features") { print file ":" section }
        ' "$f"
    done
}

fail=0
while IFS= read -r hit; do
    [ -z "$hit" ] && continue
    section="${hit##*:}"
    case "$section" in
        *"$DEV_SECTION"*) ;;
        *) echo "DENIED: $hit — '$FEATURE' may only be enabled from [$DEV_SECTION]"; fail=1 ;;
    esac
done < <(scan "${1:-.}")

if [ "${SELF_TEST:-0}" = "1" ]; then
    exit "$fail"
fi
[ "$fail" -eq 0 ] && echo "test-support placement: OK"
exit "$fail"
```

Add the self-test driver at the end of the file (before the final `exit`), replacing the `SELF_TEST` block above with a real control:

```bash
if [ "${1:-}" = "--self-test" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    mkdir -p "$tmp/good" "$tmp/bad"
    cat > "$tmp/good/Cargo.toml" <<'TOML'
[dev-dependencies]
secretary-ffi-bridge = { path = "..", features = ["test-support"] }
TOML
    cat > "$tmp/bad/Cargo.toml" <<'TOML'
[dependencies]
secretary-ffi-bridge = { path = "..", features = ["test-support"] }
TOML
    if "$0" "$tmp/good" >/dev/null 2>&1; then :; else
        echo "SELF-TEST FAIL: known-negative control was DENIED"; exit 1; fi
    if "$0" "$tmp/bad" >/dev/null 2>&1; then
        echo "SELF-TEST FAIL: known-positive control was NOT denied"; exit 1; fi
    echo "test-support placement self-test: OK (2/2 controls)"
    exit 0
fi
```

Place the `--self-test` block immediately after the `readonly` declarations so it runs before the real scan. Make it executable: `chmod +x scripts/check-test-support-placement.sh`.

- [ ] **Step 10: Run the guard both ways and wire it into CI**

```bash
cd /Users/hherb/src/secretary/.worktrees/500-detail-newtype
bash scripts/check-test-support-placement.sh --self-test
bash scripts/check-test-support-placement.sh
shellcheck scripts/check-test-support-placement.sh
```
Expected: self-test `OK (2/2 controls)`; real scan `OK` (no crate enables the feature yet — Task 3 adds uniffi's); shellcheck silent.

Then add to `.github/workflows/test.yml` in the `rust error payload hygiene` job (starts line 235), after the existing `check-error-payload-hygiene.py` step at line 268:

```yaml
      - name: 'check-test-support-placement.sh --self-test'
        run: bash scripts/check-test-support-placement.sh --self-test
      - name: 'check-test-support-placement.sh'
        run: bash scripts/check-test-support-placement.sh
```

Step names are QUOTED deliberately — an unquoted ` #` inside a YAML `name:` starts a comment and silently truncates it.

- [ ] **Step 11: Full gate sweep**

```bash
cd /Users/hherb/src/secretary/.worktrees/500-detail-newtype
cargo fmt --all
cargo test --release --workspace 2>&1 | tail -5
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -5
cargo clippy --release --workspace -- -D warnings 2>&1 | tail -5
cargo build --release --workspace 2>&1 | tail -3
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace 2>&1 | tail -3
uv run scripts/check-error-payload-hygiene.py --self-test | tail -3
uv run scripts/check-error-payload-hygiene.py | tail -3
actionlint .github/workflows/test.yml
```
Expected: all green. The payload guard is untouched so far, so its self-test counts are unchanged.

- [ ] **Step 12: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/500-detail-newtype
git add ffi/secretary-ffi-bridge/src/error/detail.rs ffi/secretary-ffi-bridge/src/lib.rs \
        ffi/secretary-ffi-bridge/Cargo.toml scripts/check-test-support-placement.sh \
        .github/workflows/test.yml
git add -u
git commit -m "$(cat <<'EOF'
feat(bridge): `Detail` newtype + `test-support` hatch + the CI gate it needs (#500)

The type, its feature-gated test hatch, and the non-test build that makes the
gate real. No gated field uses `Detail` yet — that is Task 3.

Verified by execution on this workspace, not reasoned about: a production
`Detail::for_test(runtime_string)` compiles CLEAN through `cargo test
--release --workspace`, `cargo clippy --release --workspace --tests`, and
`RUSTDOCFLAGS=-D warnings cargo doc` (rustdoc does not type-check fn bodies).
Only `cargo build --release --workspace` and clippy WITHOUT `--tests` catch
it. Every gate this repo ran before this commit would have missed it, so the
build step is not belt-and-braces — without it the feature is decorative.

`check-test-support-placement.sh` denies the one line that defeats the
isolation: enabling the feature from a normal dependency instead of
[dev-dependencies]. Self-tested against both a known-positive and a
known-negative control.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Guard learns `Detail` — widening only, real scan stays green

The guard must accept `Detail` under a gated bridge field **before** Task 3 declares any field that way, or Task 3's commit would red the real scan. This task widens (`String` OR `Detail`); Task 4 tightens to `Detail` only. Two commits, neither red — that is why they are separate.

**Files:**
- Modify: `scripts/payload_guard/roots.py` (add a field to `ScanRoot`; set it on all four roots)
- Modify: `scripts/payload_guard/types.py:226-251` (`is_bridge_field_safe`)
- Modify: `scripts/payload_guard/rules/e1.py`, `rules/e2.py` (thread the new argument)
- Modify: `scripts/payload_guard/selftest.py` (`_EXPECTED_ROOT_FLAGS` + a new control)

**Interfaces:**
- Consumes: nothing from Task 1 (guard-side only).
- Produces: `ScanRoot.gated_field_types: frozenset[str]` — the set of type spellings permitted under a `GATED_FIELD_NAMES` name on that root. `is_bridge_field_safe(name, ty, local_error_enums, aliases, foreign_names, gated_field_types)` — new **required** final parameter, no default (a default is how a new caller silently gets the permissive behaviour).

- [ ] **Step 1: Write the failing control**

In `scripts/payload_guard/selftest.py`, find the bridge control list consumed by `run_self_test` (around line 608, the `bridge_expect` loop). Add two controls to it, following the existing entry shape — a `(label, source, expectation)` tuple:

```python
    (
        "BP45",
        # A gated field declared `Detail` must be ACCEPTED on the bridge
        # (#500). Before the newtype the only accepted spelling was `String`.
        'pub enum FooError {\n'
        '    #[error("boom: {detail}")]\n'
        '    Boom { detail: Detail },\n'
        '}\n',
        None,  # expect NO finding
    ),
    (
        "BP46",
        # A gated field declared with a NEAR-MISS spelling still denies —
        # the carve-out is for the literal named types, not "close enough".
        'pub enum FooError {\n'
        '    #[error("boom: {detail}")]\n'
        '    Boom { detail: Option<Detail> },\n'
        '}\n',
        {"rule": "E2", "field": "detail"},
    ),
```

Match the exact tuple arity and expectation-dict key names the neighbouring entries use — read three existing entries first. `_check_expectation_keys()` (line 64) rejects a key `_finding_matches` does not read, so a typo fails the self-test loudly rather than degrading the control (a #496 fix).

- [ ] **Step 2: Run the self-test to verify BP45 fails**

```bash
cd /Users/hherb/src/secretary/.worktrees/500-detail-newtype
uv run scripts/check-error-payload-hygiene.py --self-test 2>&1 | tail -20
```
Expected: FAIL. BP45 reports an unexpected E2 finding — `Detail` is neither data-free nor `String`, so `is_bridge_field_safe` denies it. BP46 already passes (it denies for the right reason). If BP45 *passes*, stop: something already accepts `Detail` and the premise is wrong.

- [ ] **Step 3: Add the per-root gated type set**

In `scripts/payload_guard/roots.py`, add a field to the `ScanRoot` dataclass after `bridge_mode` (line 36):

```python
    gated_field_types: frozenset[str]
    """Type spellings accepted under a `GATED_FIELD_NAMES` field name on this
    root (#500). The BRIDGE moved its gated fields to the `Detail` newtype,
    whose private inner field makes a runtime `String` unrepresentable in the
    position; the two WRAPPER crates keep `String` because uniffi's UDL must
    project a `string` and PyO3 exceptions take a message, so their posture is
    unchanged and rules E2/E3/E5 remain their only enforcement.

    Empty for `core`, which has no gated-name carve-out at all — every field
    there must clear `is_data_free` on its own."""
```

Set it on each of the four roots in `SCAN_ROOTS`:

```python
    # core
    gated_field_types=frozenset(),
    # bridge — DURING THE #500 MIGRATION this accepts both; Task 4 narrows it
    # to `Detail` alone once every declaration has moved.
    gated_field_types=frozenset({"String", "Detail"}),
    # ffi-py
    gated_field_types=frozenset({"String"}),
    # ffi-uniffi
    gated_field_types=frozenset({"String"}),
```

- [ ] **Step 4: Make `is_bridge_field_safe` consult it**

In `scripts/payload_guard/types.py`, replace lines 226-251 with:

```python
def is_bridge_field_safe(
    name: str,
    ty: str,
    local_error_enums: frozenset[str],
    aliases: dict[str, str] | None,
    foreign_names: frozenset[str],
    gated_field_types: frozenset[str],
) -> bool:
    """True when a BRIDGE- or WRAPPER-root field is safe under rule E2's
    carve-out (#480, per-root types #500).

    Either it independently clears `is_data_free` — the ordinary tiers,
    data-free by TYPE, exactly as core requires — or its declared type is
    EXACTLY one of `gated_field_types` under a name in `GATED_FIELD_NAMES`:
    data-free by CONSTRUCTION SITE instead.

    `gated_field_types` is per-root (`ScanRoot.gated_field_types`) and has NO
    DEFAULT on purpose. It used to be the hardcoded literal `"String"`, and a
    default here would let a future caller inherit whichever spelling happened
    to be listed first — the permissive outcome — without naming it. Callers
    state which root they are scanning.

    `normalize_type` is applied for the comparison so a field-level `#[from]`
    or visibility prefix does not defeat the match; `Option<Detail>`, `&str`,
    or any other near-miss spelling still denies — the carve-out is for the
    literal named types, not "close enough."
    """
    if is_data_free(ty, local_error_enums, aliases, foreign_names):
        return True
    return normalize_type(ty) in gated_field_types and name in GATED_FIELD_NAMES
```

- [ ] **Step 5: Thread the argument through both callers**

`is_bridge_field_safe` has two call sites. Find them:

```bash
cd /Users/hherb/src/secretary/.worktrees/500-detail-newtype
grep -rn "is_bridge_field_safe" scripts/payload_guard/
```

Both `rules/e2.py::bridge_declaration_findings` (line 59) and the `bridge_mode` branch in `rules/e1.py` need a `gated_field_types` parameter added to their own signatures and passed down. Thread it from `scan.py`'s `run_real_scan`, which already has the `ScanRoot` in hand, and from `selftest.py`'s `scan_bridge_control` / `scan_wrapper_control`. Every intermediate signature gains the parameter as a **required** argument — do not add defaults anywhere along the chain, for the reason in the docstring above.

- [ ] **Step 6: Update the root-flag tripwire**

In `scripts/payload_guard/selftest.py`, `_EXPECTED_ROOT_FLAGS` (line 245) pins each root's rule flags so a flag cannot be switched off tree-wide with a green self-test (#496). It currently holds `bool` values; `gated_field_types` is a set, so add it in the shape `_check_root_rule_flags` (line 269) can compare. Extend the expected dict per root:

```python
    "core":       {..., "gated_field_types": frozenset()},
    "bridge":     {..., "gated_field_types": frozenset({"String", "Detail"})},
    "ffi-py":     {..., "gated_field_types": frozenset({"String"})},
    "ffi-uniffi": {..., "gated_field_types": frozenset({"String"})},
```

`_check_root_rule_flags` compares with `!=`, which works for both `bool` and `frozenset` — verify by reading it before assuming. If it type-asserts `bool`, widen the annotation to `dict[str, object]`.

- [ ] **Step 7: Run the self-test and the real scan**

```bash
cd /Users/hherb/src/secretary/.worktrees/500-detail-newtype
uv run scripts/check-error-payload-hygiene.py --self-test 2>&1 | tail -10
uv run scripts/check-error-payload-hygiene.py 2>&1 | tail -10
```
Expected: self-test PASSES with counts up by 2 (BP45, BP46). Real scan **OK across four roots** — the bridge still declares `String`, which is still accepted.

- [ ] **Step 8: Confirm the parity test still passes**

The allowlist file format is shared with the two shell guards; `core/tests/error_payload_hygiene_parity.rs` pins that claim.

```bash
cargo test --release --workspace --test error_payload_hygiene_parity 2>&1 | tail -5
```
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/500-detail-newtype
git add scripts/payload_guard/
git commit -m "$(cat <<'EOF'
guard: accept `Detail` under a gated bridge field (widening only) (#500)

Rule E2's carve-out was the hardcoded spelling `String`. It is now
`ScanRoot.gated_field_types`, a per-root set: the bridge accepts BOTH
`String` and `Detail` for the duration of the migration, the two wrapper
roots keep `String` alone.

Widening deliberately lands before the Rust move so that no commit on this
branch reds the real scan. The bridge set narrows to `Detail` alone in the
follow-up commit, once every declaration has moved — that narrowing is the
security-relevant half and is reviewable on its own.

`is_bridge_field_safe`'s new parameter is REQUIRED, with no default anywhere
along the call chain. A default would hand a future caller the permissive
spelling without them naming it, which is the shape of the fail-open wiring
bugs #496 spent its final review finding.

Controls BP45 (a `Detail` gated field is accepted) and BP46 (`Option<Detail>`
still denies — the carve-out is the literal type, not "close enough").

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: The Rust move — 27 declarations, 10 constructors, both wrapper crates

The big mechanical task. The compiler enumerates the work: every missed site is a type error, which is the entire point of the change.

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/error/detail.rs` (nine more constructor return types; `io_gated_with_path_and_advice`'s internal unwrap)
- Modify: `ffi/secretary-ffi-bridge/src/error/vault/mod.rs` (21 declarations, listed below)
- Modify: `ffi/secretary-ffi-bridge/src/error/unlock.rs` (lines 37, 60)
- Modify: `ffi/secretary-ffi-bridge/src/settings/parse.rs` (lines 27, 42)
- Modify: `ffi/secretary-ffi-bridge/src/repair/preview.rs` (lines 35, 53)
- Modify: `ffi/secretary-ffi-bridge/src/error/vault/tests.rs` (29 in-crate test constructions)
- Modify: `ffi/secretary-ffi-uniffi/src/errors/vault.rs`, `errors/unlock.rs` (projection arms + 12 test constructions)
- Modify: `ffi/secretary-ffi-py/src/errors.rs` (projection arms)
- Modify: `ffi/secretary-ffi-uniffi/Cargo.toml` (dev-dependency feature)
- Modify: wrapper `namespace/` files projecting the two preview DTOs

**Interfaces:**
- Consumes: `secretary_ffi_bridge::Detail` (Task 1), `Detail::for_test` under `test-support`.
- Produces: all 27 gated bridge fields typed `Detail`; ten `detail::*` constructors returning `Detail`.

The exact 27 declarations (`<file> <line> <field>`), captured at `3775ef5`:

```
settings/parse.rs   27  detail          error/vault/mod.rs  240  uuid_hex
settings/parse.rs   42  detail          error/vault/mod.rs  249  uuid_hex
error/unlock.rs     37  detail          error/vault/mod.rs  260  detail
error/unlock.rs     60  detail          error/vault/mod.rs  270  detail
error/vault/mod.rs  62  detail          error/vault/mod.rs  284  detail
error/vault/mod.rs  83  detail          error/vault/mod.rs  305  detail
error/vault/mod.rs  97  detail          error/vault/mod.rs  323  detail
error/vault/mod.rs  127 uuid_hex        error/vault/mod.rs  348  detail
error/vault/mod.rs  143 uuid_hex        error/vault/mod.rs  371  block_uuid_hex
error/vault/mod.rs  169 detail          error/vault/mod.rs  379  block_uuid_hex
error/vault/mod.rs  187 expected_fingerprint_hex   error/vault/mod.rs 383 detail
error/vault/mod.rs  189 got_fingerprint_hex        repair/preview.rs  35  pub uuid_hex
error/vault/mod.rs  219 recipient_fingerprint_hex  repair/preview.rs  53  pub block_uuid_hex
error/vault/mod.rs  231 detail
```

- [ ] **Step 1: Change all ten constructor return types**

Task 1 deliberately changed none of them (pre-flight finding PF1 — a half-moved constructor reds the guard scan, because rule E3 accepts a sanctioned call only as the WHOLE initializer and the interim `.into_string()` wrapper is not that shape). They all move here, in the same commit as the fields.

In `ffi/secretary-ffi-bridge/src/error/detail.rs`, change `-> String` to `-> Detail` and wrap each body's final expression in `Detail(...)`, for: `gated` (63), `gated_with_context` (67), `uuid_hex` (71), `uuid_hyphenated` (75), `fingerprint_hex` (79), `gated_for_uuid` (83), `literal_for_uuid` (91), `counted` (95), `gated_with_path` (107), `gated_with_path_and_advice` (123). Examples:

```rust
pub(crate) fn gated(e: &impl GatedDetail) -> Detail {
    Detail(e.to_string())
}

pub(crate) fn gated_with_context(context: &'static str, e: &impl GatedDetail) -> Detail {
    Detail(format!("{context}: {e}"))
}
```

The existing `detail.rs` unit tests assert on `String` return values (e.g. `assert_eq!(gated(&e), "gone")` at line 198). Each needs `.as_str()` inserted: `assert_eq!(gated(&e).as_str(), "gone")`. Work through all of them — `gated_renders_display`, `gated_with_context_prefixes`, `gated_with_path_appends_disclosed_path`, `gated_with_path_and_advice_puts_the_advice_last`, `uuid_renderers`, `uuid_composites`, `counted_renders_index`. `io_gated_with_path_and_advice_renders_display_path_then_advice` asserts on an `io::Error` and needs no change.

`gated_with_path_and_advice` composes another constructor, so unwrap the inner value:

```rust
pub(crate) fn gated_with_path_and_advice(
    e: &impl GatedDetail,
    path: &Path,
    advice: &'static str,
) -> Detail {
    Detail(format!(
        "{}; {advice}",
        crate::error::detail::gated_with_path(e, path).as_str()
    ))
}
```

`io_gated_with_path_and_advice` (160) keeps returning `std::io::Error`; unwrap at the boundary:

```rust
    std::io::Error::new(
        kind,
        crate::error::detail::gated_with_path_and_advice(e, path, advice).into_string(),
    )
```

Leave the `detail.rs` doc comment on `io_gated_with_path_and_advice` intact — its explanation of why the call is self-qualified (guard rule E3 needs the literal `detail::` text) still applies.

- [ ] **Step 2: Run the build to enumerate every affected site**

```bash
cd /Users/hherb/src/secretary/.worktrees/500-detail-newtype
cargo build --release --workspace 2>&1 | grep -E "^(error|  -->)" | head -80
```
Expected: a long list of `expected `String`, found `Detail`` errors. This IS the work list. Capture it: `cargo build --release --workspace 2>&1 | grep -E "^  -->" | sort -u > /tmp/sites.txt`.

- [ ] **Step 3: Change the 27 declarations**

Change each `detail: String,` to `detail: Detail,` (likewise `uuid_hex`, `block_uuid_hex`, `recipient_fingerprint_hex`, `expected_fingerprint_hex`, `got_fingerprint_hex`) at the 27 sites listed above. Add `use crate::error::detail::Detail;` to each of the five files that needs it.

Update the doc comments that assert the field's type — several say "Stored as a `String`". For example `error/vault/mod.rs:112-113` reads:

```
/// `"112233445566778899aabbccddeeff00"`. Stored as a `String` for
/// consistency with other variants' `detail: String` payloads; the
```
Change to:
```
/// `"112233445566778899aabbccddeeff00"`. Stored as a [`Detail`] for
/// consistency with other variants' gated payloads; the
```
Find them all: `grep -n 'detail: String\|as a `String`' ffi/secretary-ffi-bridge/src/error/vault/mod.rs`.

- [ ] **Step 4: Get the bridge compiling on its own**

```bash
cd /Users/hherb/src/secretary/.worktrees/500-detail-newtype
cargo build --release -p secretary-ffi-bridge 2>&1 | grep -E "^(error|  -->)" | head -40
```
Iterate until this reports zero errors before touching the wrapper crates — a bridge that compiles alone makes the remaining errors unambiguously wrapper-side.

**A sanctioned call must remain the WHOLE initializer.** If a site tempts you into `detail::gated(&e).into_string()` or any other trailing transform, that is the PF1 shape and rule E3 denies it (verified: `accepted | detail::gated(e)` vs `DENIED | detail::gated(e).into_string()`). The field is a `Detail` now, so the bare call is both correct and the only accepted shape. Check as you go:
```bash
grep -rnE "detail::[a-z_]+\([^)]*\)\s*\." --include='*.rs' ffi/secretary-ffi-bridge/src/   # expect no hits
```

- [ ] **Step 5: Fix the wrapper projection arms**

```bash
cargo build --release --workspace 2>&1 | grep -E "^  -->" | sort -u
```
Every remaining error is a wrapper arm moving a bridge `Detail` into a wrapper `String` field. Append `.into_string()` at each. The shorthand arms must be expanded — `VaultError::CorruptVault { detail }` becomes `VaultError::CorruptVault { detail: detail.into_string() }`.

For the two preview DTOs, the wrapper projects `uuid_hex` / `block_uuid_hex` into uniffi records; same `.into_string()` treatment.

Rebuild until `cargo build --release --workspace` reports zero errors.

- [ ] **Step 6: Add uniffi's dev-dependency and fix its 12 test constructions**

In `ffi/secretary-ffi-uniffi/Cargo.toml`:

```toml
[dev-dependencies]
# `test-support` gives these tests `Detail::for_test`, the only way to build a
# `Detail` outside the bridge's own `detail.rs` (#500). DEV-ONLY — under
# resolver v2 that keeps the hatch out of every non-test build, which
# `scripts/check-test-support-placement.sh` enforces.
secretary-ffi-bridge = { path = "../secretary-ffi-bridge", features = ["test-support"] }
```

If a `secretary-ffi-bridge` dev-dependency line already exists, add the `features` key to it rather than duplicating the entry.

Then in `ffi/secretary-ffi-uniffi/src/errors/vault.rs`, the 12 constructions inside `#[cfg(test)] mod tests` (starts line 223; constructions at 333, 367, 417, 446, 477, 489, 501, 544, 556, 609, 654, 666) change from a string literal to `Detail::for_test(...)`:

```rust
        let bridge_err = FfiVaultError::SaveCryptoFailure {
            detail: Detail::for_test("aead failure"),
        };
```
Add `use secretary_ffi_bridge::Detail;` to the test module.

- [ ] **Step 7: Fix the bridge's own 29 test constructions**

`ffi/secretary-ffi-bridge/src/error/vault/tests.rs` builds the 29 gated fields with `.to_string()`. Change each to `Detail::for_test(...)`.

A crate cannot depend on itself, so the bridge's own tests cannot reach `for_test` through the `test-support` dev-dependency the way uniffi does. Within the crate, though, `--cfg test` DOES apply — so add a second, `cfg(test)`-gated definition alongside the feature-gated one in `error/detail.rs`:

```rust
    /// In-crate counterpart to the `test-support` hatch above.
    ///
    /// A crate cannot list itself as a dev-dependency, so the bridge's own
    /// tests cannot reach the feature-gated `for_test`. `--cfg test` does
    /// apply within the crate, which covers them. The `not(feature = ...)`
    /// guard prevents a duplicate definition when a downstream crate's
    /// dev-dependency turns the feature on during a workspace `cargo test`.
    ///
    /// This does NOT widen the hatch: `cfg(test)` is never active in a
    /// `cargo build`, so neither definition exists in a shipped artifact.
    #[cfg(all(test, not(feature = "test-support")))]
    pub(crate) fn for_test(s: &str) -> Detail {
        Detail(s.to_string())
    }
```

Place it inside the existing `impl Detail` block, directly after the feature-gated `for_test`. Note the visibility difference — `pub(crate)` here, `pub` on the feature-gated one — which is deliberate: the in-crate definition never needs to escape the crate.

Verify BOTH configurations compile, since the `not(feature)` guard means each is exercised by a different invocation:
```bash
cargo test --release -p secretary-ffi-bridge 2>&1 | tail -3
cargo test --release -p secretary-ffi-bridge --features test-support 2>&1 | tail -3
```

- [ ] **Step 8: Full workspace test**

```bash
cd /Users/hherb/src/secretary/.worktrees/500-detail-newtype
cargo fmt --all
cargo build --release --workspace 2>&1 | tail -3
cargo test --release --workspace 2>&1 | tail -8
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -5
cargo clippy --release --workspace -- -D warnings 2>&1 | tail -5
```
Expected: all green.

- [ ] **Step 9: Verify no FFI surface change**

```bash
git diff main... -- ffi/secretary-ffi-uniffi/src/secretary.udl
```
Expected: **EMPTY output.** If not, a variant or field changed shape — that is out of scope and must be reverted.

- [ ] **Step 10: Guard + placement check still green**

```bash
uv run scripts/check-error-payload-hygiene.py --self-test | tail -3
uv run scripts/check-error-payload-hygiene.py | tail -3
bash scripts/check-test-support-placement.sh --self-test
bash scripts/check-test-support-placement.sh
```
Expected: guard OK (Task 2's widening covers `Detail`); placement now reports OK with uniffi's dev-dependency present.

- [ ] **Step 11: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
refactor(bridge): all 27 gated payload fields become `Detail` (#500)

Ten sanctioned constructors return `Detail`; the eleventh
(`io_gated_with_path_and_advice`) still returns `std::io::Error` and unwraps
at that boundary, which is why rule E3 keeps its io-payload position.

The wrapper crates keep `String` in their OWN error types — uniffi's UDL must
project a `string`, PyO3 exceptions take a message — so each projection arm
gains one `.into_string()`. That unwrap sits one line from the wrapper's own
construction site and confers no protection on it: the wrappers stay
text-guarded by E2/E3/E5, unchanged. The compiler guarantee is the bridge's
109 construction sites and nothing wider.

The bridge's own tests use a `#[cfg(all(test, not(feature = "test-support")))]`
constructor rather than a self-dependency; uniffi's 12 take the feature via
[dev-dependencies].

`secretary.udl` diffs empty. No variant, field, or Display string changed.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: Guard tightens — `String` under a gated bridge field now DENIES

The security-relevant half of the guard change, reviewable on its own now that the tree has moved.

**Files:**
- Modify: `scripts/payload_guard/roots.py` (bridge `gated_field_types` → `{"Detail"}`)
- Modify: `scripts/payload_guard/selftest.py` (`_EXPECTED_ROOT_FLAGS`; new control)

- [ ] **Step 1: Write the failing control**

Add to the bridge control list in `selftest.py`, same shape as BP45/BP46:

```python
    (
        "BP47",
        # After #500 a gated bridge field declared `String` DENIES. The
        # carve-out that accepted it existed only while the tree still used
        # it; leaving it accepted would mean a new error type could opt out
        # of the newtype by declaring the old spelling.
        'pub enum FooError {\n'
        '    #[error("boom: {detail}")]\n'
        '    Boom { detail: String },\n'
        '}\n',
        {"rule": "E2", "field": "detail"},
    ),
```

- [ ] **Step 2: Run to verify it fails**

```bash
uv run scripts/check-error-payload-hygiene.py --self-test 2>&1 | tail -12
```
Expected: FAIL — BP47 expects an E2 finding, but the bridge set still accepts `String`.

- [ ] **Step 3: Narrow the bridge's accepted set**

In `scripts/payload_guard/roots.py`, change the bridge root:

```python
        # #500: the bridge's gated fields are the `Detail` newtype, whose
        # private inner field makes a runtime `String` UNREPRESENTABLE in the
        # position. `String` is no longer accepted here — a new bridge error
        # type cannot opt out of the newtype by declaring the old spelling.
        # The wrapper roots still take `String`; see the spec's §4 for why
        # that boundary is real and not an oversight.
        gated_field_types=frozenset({"Detail"}),
```

Update `_EXPECTED_ROOT_FLAGS`'s `"bridge"` entry to `frozenset({"Detail"})` in the same commit — that tripwire exists precisely to make this a two-place edit.

- [ ] **Step 4: Run to verify it passes**

```bash
uv run scripts/check-error-payload-hygiene.py --self-test 2>&1 | tail -8
uv run scripts/check-error-payload-hygiene.py 2>&1 | tail -8
```
Expected: self-test PASSES (BP47 now fires as expected, BP45 still accepted); real scan **OK across four roots**.

- [ ] **Step 5: Demonstrate the compile error — do not merely assert it**

Spec §11 requires this to be shown. Plant, observe, revert:

```bash
cd /Users/hherb/src/secretary/.worktrees/500-detail-newtype
python3 - <<'PY'
import pathlib
p = pathlib.Path("ffi/secretary-ffi-bridge/src/error/vault/mod.rs")
s = p.read_text()
s = s.replace(
    'detail: detail::gated(&e)',
    'detail: format!("{e}")',
    1,
)
p.write_text(s)
PY
cargo build --release -p secretary-ffi-bridge 2>&1 | grep -E "^error" | head -3
git checkout ffi/secretary-ffi-bridge/src/error/vault/mod.rs
cargo build --release -p secretary-ffi-bridge 2>&1 | grep -cE "^error"
```
Expected: the planted build prints `error[E0308]: mismatched types … expected `Detail`, found `String``; after revert, `0`. If the replace finds no match, pick any live gated-field construction site from `grep -n 'detail: detail::' ffi/secretary-ffi-bridge/src/error/vault/mod.rs` and plant there instead.

Record the observed error text in the commit message — that is the demonstration.

- [ ] **Step 6: Commit**

```bash
git add scripts/payload_guard/
git commit -m "$(cat <<'EOF'
guard: a `String` gated field now DENIES on the bridge root (#500)

Narrows `ScanRoot.gated_field_types` for the bridge from {String, Detail} to
{Detail}, now that every declaration has moved. Without this a new bridge
error type could opt out of the newtype by declaring the old spelling and the
guard would wave it through.

Demonstrated rather than asserted — planting `detail: format!("{e}")` at a
live construction site gives:

    error[E0308]: mismatched types
       expected `Detail`, found `String`

That is the whole point of #500: the four E3 laundering shapes documented as
needing dataflow analysis (pattern binds, build-then-mutate, fn parameter,
dotless reassignment) all now fail to typecheck in the bridge, along with
every shape nobody has thought of. E3 keeps running there as defence in depth
and remains the ONLY enforcement on the two wrapper roots.

Control BP47.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: #498 — hint-position arguments must be string literals

**Files:**
- Modify: `scripts/payload_guard/rules/e3.py`
- Modify: `scripts/payload_guard/selftest.py` (control)
- Modify: `scripts/error-payload-hygiene-allowlist.txt` (only if the census turns up a live non-literal)

- [ ] **Step 1: Re-run #498's census before trusting it**

The spec (§6.1) requires this — the census is #498's, taken at `3775ef5`, and the rule is zero-false-positive only if it still holds.

```bash
cd /Users/hherb/src/secretary/.worktrees/500-detail-newtype
grep -rnoE 'detail::[a-z_]+\(\s*[^),]+' --include='*.rs' \
  ffi/secretary-ffi-bridge/src ffi/secretary-ffi-py/src ffi/secretary-ffi-uniffi/src \
  | grep -vE 'detail::[a-z_]+\(\s*"' \
  | grep -vE 'detail::[a-z_]+\(\s*&' \
  | sort -u
```
Any line printed is a call whose FIRST argument is neither a string literal nor a reference. Read each. If the only hits are `detail.rs`'s own internal re-forwards, the census holds. **If a live non-literal producer exists, stop and report it** — it is a finding in its own right, not something to allowlist past.

- [ ] **Step 2: Write the failing control**

Add to the bridge control list in `selftest.py`:

```python
    (
        "BP48",
        # #498: a `&'static str` hint is NOT leak-proof — safe stable Rust
        # mints one from runtime data via `Box::leak`. The hint position must
        # be a string LITERAL, not merely a `&'static str`-typed expression.
        'fn f(e: &E) -> X {\n'
        '    let leaked: &\'static str = Box::leak(format!("{e}").into_boxed_str());\n'
        '    X::V { detail: detail::gated_with_context(leaked, e) }\n'
        '}\n',
        {"rule": "E3", "field": "detail"},
    ),
```

- [ ] **Step 3: Run to verify it fails**

```bash
uv run scripts/check-error-payload-hygiene.py --self-test 2>&1 | tail -12
```
Expected: FAIL — E3 currently accepts any `detail::` call without inspecting arguments, so BP48 reports no finding where one is expected.

- [ ] **Step 4: Implement the literal check**

In `scripts/payload_guard/rules/e3.py`, extend the sanctioned-call acceptance (`DETAIL_CALL_RE`, line 209, and the acceptance arm in `initializer_is_gated`, line 356) so that when a call is matched, its HINT-POSITION arguments are additionally required to be string literals.

The hint positions are the parameters typed `&'static str` in the constructor's signature. `sanctioned_constructor_names` (line 102) already parses signatures for `_ctor_params_are_safe`; extend it to return, per constructor, the INDEXES of its `&'static str` parameters, and check those argument positions at each call site.

A string literal for this purpose is a token matching `^r?#*"` after whitespace stripping — a plain `"…"` or a raw `r"…"` / `r#"…"#`. Anything else denies.

Add a docstring stating the honest limit verbatim from spec §6.1: this watches the door, it does not remove it; only #498's closed-`enum Context` option would make a leaked `&'static str` unrepresentable, and #498 stays open recording that.

- [ ] **Step 5: Run to verify it passes**

```bash
uv run scripts/check-error-payload-hygiene.py --self-test 2>&1 | tail -8
uv run scripts/check-error-payload-hygiene.py 2>&1 | tail -8
```
Expected: self-test PASSES; real scan **OK across four roots**. If the real scan now reports findings, they are the census's false negatives from Step 1 — go back and read them rather than allowlisting.

- [ ] **Step 6: Commit**

```bash
git add scripts/payload_guard/ scripts/error-payload-hygiene-allowlist.txt
git commit -m "$(cat <<'EOF'
guard: hint-position arguments must be string literals (#498, partial)

`&'static str` is not leak-proof: `Box::leak(format!(..).into_boxed_str())`
mints one from runtime data in safe stable Rust, `#![forbid(unsafe_code)]`
does not stop it, and #498 demonstrated the resulting call scans CLEAN. Every
sanctioned constructor takes its hint that way.

Rule E3 now requires those argument positions to be string LITERALS. The
positions are derived from each constructor's own signature (the parameters
typed `&'static str`), not from a hand-maintained list.

Census re-run at HEAD before landing, per the spec: the domain is still
entirely literal, so this is zero-false-positive.

HONEST LIMIT, recorded in the rule's docstring: this watches the door, it
does not remove it. A text rule cannot make a leaked `&'static str`
unrepresentable the way the `Detail` newtype does for the payload itself.
Only #498's closed-`enum Context` option would, and #498 stays OPEN for it.

Control BP48.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: #504 — ffi-py's two `&str` constructors take `&Detail`

**Files:**
- Modify: `ffi/secretary-ffi-py/src/detail.rs:78`, `:117` (signatures + the PROVENANCE comment)
- Modify: `ffi/secretary-ffi-py/src/errors.rs:141-147`, `:200-206` (call sites)
- Modify: `scripts/payload_guard/rules/e3.py` (`SAFE_PARAM_TYPES`, `STR_PARAM_CTOR_EXCEPTIONS`)

- [ ] **Step 1: Write the failing tests**

In `ffi/secretary-ffi-py/src/detail.rs`'s `#[cfg(test)] mod tests`, add content-and-order assertions. #504 flags that both functions take two same-typed arguments that are silently swappable and are currently tested only for exception class:

```rust
    #[test]
    fn fingerprint_mismatch_puts_expected_before_got() {
        let expected = Detail::for_test("aaaa");
        let got = Detail::for_test("bbbb");
        let msg = fingerprint_mismatch(&expected, &got);
        assert_eq!(msg, "expected=aaaa, got=bbbb");
        assert!(msg.find("aaaa").unwrap() < msg.find("bbbb").unwrap());
    }

    #[test]
    fn uuid_prefixed_puts_the_uuid_first() {
        let uuid = Detail::for_test("11223344-5566-7788-99aa-bbccddeeff00");
        let detail = Detail::for_test("residue rejected");
        let msg = uuid_prefixed(&uuid, &detail);
        assert_eq!(msg, "11223344-5566-7788-99aa-bbccddeeff00: residue rejected");
    }
```

These need `Detail::for_test`, so add the dev-dependency feature to `ffi/secretary-ffi-py/Cargo.toml`:

```toml
[dev-dependencies]
# `Detail::for_test` for the detail.rs message-content tests (#504). DEV-ONLY.
secretary-ffi-bridge = { path = "../secretary-ffi-bridge", features = ["test-support"] }
```

- [ ] **Step 2: Run to verify they fail**

```bash
cargo test --release -p secretary-ffi-py --lib detail 2>&1 | tail -15
```
Expected: FAIL to compile — `fingerprint_mismatch` takes `&str`, not `&Detail`.

- [ ] **Step 3: Change the signatures**

```rust
pub(crate) fn fingerprint_mismatch(expected: &Detail, got: &Detail) -> String {
    format!("expected={}, got={}", expected.as_str(), got.as_str())
}

pub(crate) fn uuid_prefixed(uuid_part: &Detail, detail_part: &Detail) -> String {
    format!("{}: {}", uuid_part.as_str(), detail_part.as_str())
}
```

Add `use secretary_ffi_bridge::Detail;` to the file.

Rewrite the PROVENANCE doc comment on `uuid_prefixed` (currently lines 82-116). Most of it exists to trace by hand why each argument is trustworthy, including the admission that `detail_part` is backed by E2 + core E1 rather than re-verified by E3. That hand-tracing is now a compile-time fact — a `&Detail` can only have come from a bridge sanctioned constructor. Replace with a short statement of that, and delete the per-parameter provenance walk. Keep the note about Python callers splitting on the first `": "` — that is still a live API contract.

- [ ] **Step 4: Update the two call sites**

`ffi/secretary-ffi-py/src/errors.rs:141-147` and `:200-206` destructure the bridge error and pass the fields. They now pass `&Detail` values directly — drop any `&` -to-`&str` coercion. Rebuild:

```bash
cargo build --release -p secretary-ffi-py 2>&1 | grep -E "^error" | head -5
```

- [ ] **Step 5: Empty the exception set**

In `scripts/payload_guard/rules/e3.py`:

```python
# #504: EMPTY. Both entries (`fingerprint_mismatch`, `uuid_prefixed`) took
# `&str` and were pinned here as a point-in-time review claim the guard could
# not verify. They now take `&Detail`, so their inputs are gated by TYPE — a
# `Detail` is constructible only inside the bridge's own `detail.rs`. Any
# `&str`-taking constructor added to a `detail.rs` from here on fails the
# guard until someone deliberately re-populates this set, which is the review
# checkpoint the bare-name registry never had.
STR_PARAM_CTOR_EXCEPTIONS: frozenset[str] = frozenset()
```

And add `&Detail` to `SAFE_PARAM_TYPES` (line 52):

```python
        "&Detail",
```

- [ ] **Step 6: Run tests and the guard**

```bash
cargo test --release -p secretary-ffi-py --lib detail 2>&1 | tail -8
cargo test --release --workspace 2>&1 | tail -5
uv run scripts/check-error-payload-hygiene.py --self-test | tail -3
uv run scripts/check-error-payload-hygiene.py | tail -3
bash scripts/check-test-support-placement.sh
```
Expected: all PASS/OK.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
refactor(ffi-py): the two `&str` detail constructors take `&Detail` (#504)

`fingerprint_mismatch` and `uuid_prefixed` were the only sanctioned
constructors in the tree taking a bare `&str`, permitted by the pinned
`STR_PARAM_CTOR_EXCEPTIONS` set. Nothing verified what they were passed.

Taking `&Detail` makes the inputs gated by TYPE — a `Detail` is constructible
only inside the bridge's `detail.rs` — so the exception set is now EMPTY and
a future `&str` constructor fails the guard until someone deliberately
re-populates it.

`uuid_prefixed`'s PROVENANCE comment shrinks accordingly: it existed to trace
by hand why each argument was trustworthy, including the admission that
`detail_part` was backed by E2 + core E1 and NOT re-verified by E3. That is
now a compile-time fact.

Taking `&Detail` does NOT fix the swappability #504 also flags — both
parameters are still the same type — so both functions gain message-CONTENT
and ARGUMENT-ORDER assertions. These run under `cargo test`, unlike the
pytest suite (#501, still open).

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: #503 — the second `[u8; 32]` stack frame

**Files:**
- Modify: `ffi/secretary-ffi-uniffi/src/namespace/mod.rs` (add the sibling near `array32_from_vec` at line 664; fix the doc comment at 580-581; call site at 598)
- Modify: `ffi/secretary-ffi-uniffi/src/namespace/repair.rs:228`, `:356`

- [ ] **Step 1: Write the failing test**

In `ffi/secretary-ffi-uniffi/src/namespace/mod.rs`'s test module:

```rust
    #[test]
    fn array32_from_vec_into_writes_through_and_rejects_wrong_length() {
        let mut out = [0u8; 32];
        let src: Vec<u8> = (0u8..32).collect();
        array32_from_vec_into(&src, &mut out, "device_secret").expect("32 bytes is valid");
        assert_eq!(out.to_vec(), src);

        let mut out2 = [0u8; 32];
        let err = array32_from_vec_into(&[1u8, 2, 3], &mut out2, "device_secret")
            .expect_err("3 bytes must be rejected");
        match err {
            VaultError::InvalidArgument { detail } => {
                assert_eq!(detail, "device_secret must be 32 bytes, got 3");
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
        assert_eq!(out2, [0u8; 32], "the out slot must be untouched on error");
    }
```

The length assertion in the message is the #503-adjacent regression this pins: the sibling must read `bytes.len()` BEFORE any wipe, exactly as the by-value helper does.

- [ ] **Step 2: Run to verify it fails**

```bash
cargo test --release -p secretary-ffi-uniffi --lib array32_from_vec_into 2>&1 | tail -10
```
Expected: FAIL — `cannot find function array32_from_vec_into`.

- [ ] **Step 3: Add the sibling**

In `ffi/secretary-ffi-uniffi/src/namespace/mod.rs`, immediately after `array32_from_vec` (line 664-668):

```rust
/// [`array32_from_vec`] for a SECRET 32-byte input, writing through the
/// caller's slot instead of returning by value (#503).
///
/// `array32_from_vec` materializes its `[u8; 32]` in its OWN frame and
/// returns it; the caller zeroizes only the copy it received. Release-mode
/// inlining will usually collapse the two frames, but the helper is not
/// `#[inline]` and CLAUDE.md's zeroize discipline is explicit about not
/// resting on codegen. Writing through `out` means the array exists in
/// exactly one place as a SOURCE-LEVEL fact.
///
/// Use this for a device secret. The by-value [`array32_from_vec`] stays for
/// non-secret 32-byte inputs (an `ApprovedWidening.file_fingerprint`), where
/// there is nothing to protect and an out-parameter reads worse.
///
/// `out` is left UNTOUCHED when `bytes` is the wrong length.
pub(crate) fn array32_from_vec_into(
    bytes: &[u8],
    out: &mut [u8; 32],
    field: &'static str,
) -> Result<(), VaultError> {
    if bytes.len() != 32 {
        return Err(VaultError::InvalidArgument {
            detail: crate::detail::arg_len(field, 32, bytes.len()),
        });
    }
    out.copy_from_slice(bytes);
    Ok(())
}
```

- [ ] **Step 4: Run to verify it passes**

```bash
cargo test --release -p secretary-ffi-uniffi --lib array32_from_vec_into 2>&1 | tail -8
```
Expected: PASS.

- [ ] **Step 5: Move the three `device_secret` call sites**

`namespace/mod.rs:598`:
```rust
    // `mut` so the [u8; 32] stack copy is zeroized IN PLACE below — a
    // re-binding `let mut` would copy the array and wipe only the copy.
    // Written through by `array32_from_vec_into` rather than returned by
    // value, so this slot is the ONLY [u8; 32] in play (#503).
    let mut secret_arr = [0u8; 32];
    array32_from_vec_into(device_secret, &mut secret_arr, "device_secret")?;
```
Apply the same shape at `namespace/repair.rs:228` and `:356`. Read each site first — the surrounding zeroize placement differs and must be preserved.

- [ ] **Step 6: Fix the stale doc comment**

`namespace/mod.rs:580-581` currently reads "the transient `[u8; 32]` stack copy made here is zeroized on all paths" — singular, and describing the shape that is now gone. Replace:

```rust
/// `device_secret` is a zero-copy borrow of the foreign buffer
/// (`[ByRef] bytes`, #307) — the foreign adapter owns it and its scrub. The
/// single transient `[u8; 32]` stack copy made here is written through by
/// [`array32_from_vec_into`] (so no second copy exists in a callee frame,
/// #503) and is zeroized on all paths.
```

- [ ] **Step 7: Verify no by-value helper remains on a secret path**

```bash
cd /Users/hherb/src/secretary/.worktrees/500-detail-newtype
grep -rn "array32_from_vec(" --include='*.rs' ffi/secretary-ffi-uniffi/src/
```
Expected: only non-secret callers (fingerprint / `ApprovedWidening`) remain. Any `device_secret` hit is a missed site.

- [ ] **Step 8: Full sweep and commit**

```bash
cargo fmt --all
cargo test --release --workspace 2>&1 | tail -5
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo clippy --release --workspace -- -D warnings 2>&1 | tail -3
git add -A
git commit -m "$(cat <<'EOF'
fix(ffi-uniffi): no second un-zeroized [u8; 32] frame for a device secret (#503)

`array32_from_vec` materializes its `[u8; 32]` inside its own frame and
returns it by value; only the caller's copy was zeroized, and the helper is
not `#[inline]`. Release-mode inlining will usually collapse the frames — but
this repo's zeroize discipline is explicit about not resting on codegen.

Adds `array32_from_vec_into`, which writes through the caller's slot, and
moves the three `device_secret` sites to it. The array now exists in exactly
one place as a source-level fact. The by-value helper stays for the
non-secret 32-byte fingerprint callers, where an out-parameter buys nothing
and reads worse.

Also fixes the doc comment at namespace/mod.rs:580, which said "the transient
stack copy" — singular — while there were two.

The new helper reads `bytes.len()` BEFORE touching anything, and the test
asserts the exact message; the bug #496 fixed in this same area was a length
read AFTER a `zeroize()` that reported "got 0" every time.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: Documentation, identity-harness baseline, and the honest limits list

**Files:**
- Modify: `CLAUDE.md` (the "Rust error payloads: data-free by construction" section)
- Modify: `scripts/check-error-payload-hygiene.py` (module docstring LIMITS)
- Modify: `scripts/error-payload-hygiene-allowlist.txt` (preamble)
- Modify: `scripts/payload_guard/rules/e3.py` (docstring — what it now does and does not guarantee)
- Re-take: `scripts/dev/payload_guard_identity.sh` baseline

- [ ] **Step 1: Re-take the identity-harness baseline and review the diff**

Spec §9.1: this slice legitimately changes guard behaviour, so the harness will NOT diff empty. Every changed line must be attributable to a specific rule change.

```bash
cd /Users/hherb/src/secretary/.worktrees/500-detail-newtype
git stash list  # confirm clean
bash scripts/dev/payload_guard_identity.sh /tmp/after-500.txt
git show main:scripts/dev/payload_guard_identity.sh > /tmp/harness-main.sh 2>/dev/null || true
git stash push -u -m "500-doc-wip" 2>/dev/null || true
git checkout main -- . 2>/dev/null && bash scripts/dev/payload_guard_identity.sh /tmp/before-500.txt
git checkout feature/500-detail-newtype -- . && git stash pop 2>/dev/null || true
diff -u /tmp/before-500.txt /tmp/after-500.txt | head -60
```

**Do not run the `git checkout main -- .` dance if any parallel session shares this worktree** — per this repo's history a stash/checkout cycle on a shared worktree applies the wrong session's stash. Safer alternative: generate the "before" transcript from a throwaway clone at `main`:

```bash
git worktree add /tmp/wt-500-before main
(cd /tmp/wt-500-before && bash scripts/dev/payload_guard_identity.sh /tmp/before-500.txt)
diff -u /tmp/before-500.txt /tmp/after-500.txt
git worktree remove /tmp/wt-500-before
```

For each differing line, write one sentence naming the rule change that predicts it (Task 2's widening, Task 4's narrowing, Task 5's literal check, Task 6's empty exception set, the new control labels). **A line no change predicts is a defect — investigate before proceeding.** Paste the attributed diff into the commit message.

- [ ] **Step 2: Update CLAUDE.md**

In the "Rust error payloads: data-free by construction (#474)" section:

- State that the bridge's gated fields are the `Detail` newtype and what that closes: the four E3 laundering shapes previously listed as "needing dataflow analysis" are closed **for the bridge** — pattern binds, build-then-mutate, fn parameter, dotless reassignment — along with shapes not yet enumerated.
- State just as plainly that they remain **open for the two wrapper roots**, whose error types keep `String` because uniffi's UDL must project one. Do NOT flatten this into "laundering is fixed". Spec §4 exists for this sentence.
- Record the `test-support` feature, why it is dev-dependency-only, and that `cargo build --release --workspace` in CI is what makes it real — including that `cargo test`, `cargo clippy --tests` and the rustdoc gate all miss a production call to the hatch.
- Update the rule summary: E2 is now per-root (`ScanRoot.gated_field_types`), bridge `{Detail}` / wrappers `{String}`; E3 gained the string-literal hint check; `STR_PARAM_CTOR_EXCEPTIONS` is empty.
- Remove `#504` and `#503` from the open list; keep `#497`, `#499`, `#501`, `#502`, `#494`, `#495` and #498's structural half.
- Note the `FfiAddedRecipient` / `FfiWideningReport` subtlety: E2 does not sweep them (they are not `*Error`/`*Warning`), so for those two fields the newtype is the ONLY declaration-level enforcement — and their sibling `display_name` / `block_name` fields deliberately carry plaintext and stay `String`.

- [ ] **Step 3: Update the guard's LIMITS docstring**

`scripts/check-error-payload-hygiene.py`'s module docstring is the authoritative limits list. Make the same bridge/wrapper distinction, add #498's remaining half, and add one NEW limit this work introduces:

> **The `test-support` feature is a build-configuration guarantee, not a language one.** `Detail::for_test` can mint a `Detail` from a runtime `String`; it is absent from shipped artifacts only because resolver v2 declines to unify a dev-dependency's features into a non-test build. Enabling the feature on a normal dependency line puts it back. `scripts/check-test-support-placement.sh` denies that line, and `cargo build --release --workspace` in CI catches a call to a hatch that should not exist — but neither is the compiler refusing to express the thing.

- [ ] **Step 4: Update the allowlist preamble and e3.py's docstring**

The allowlist preamble describes what each section means. `STR_PARAM_CTOR_EXCEPTIONS` is empty now; say so and say what re-populating it would mean. In `rules/e3.py`, state that on the bridge root E3 is defence in depth rather than the enforcement, and that on the two wrapper roots it remains the only enforcement.

- [ ] **Step 5: Full final gate sweep**

```bash
cd /Users/hherb/src/secretary/.worktrees/500-detail-newtype
pwd && git branch --show-current
cargo fmt --all --check
cargo build --release --workspace 2>&1 | tail -3
cargo test --release --workspace 2>&1 | tail -5
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo clippy --release --workspace -- -D warnings 2>&1 | tail -3
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace 2>&1 | tail -3
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run scripts/check-error-payload-hygiene.py --self-test | tail -3
uv run scripts/check-error-payload-hygiene.py | tail -3
bash scripts/check-test-support-placement.sh --self-test
bash scripts/check-test-support-placement.sh
bash ios/scripts/check-public-log-hygiene.sh --self-test && bash ios/scripts/check-public-log-hygiene.sh
bash android/scripts/check-log-hygiene.sh --self-test && bash android/scripts/check-log-hygiene.sh
bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh
actionlint .github/workflows/test.yml
(cd desktop && pnpm test && pnpm run svelte-check)
(cd android && ./gradlew :vault-access:test :kit:compileDebugKotlin)

# Spec §11: ZERO gated names still declared `String` anywhere in the bridge.
grep -rnE '^\s*(pub )?(detail|uuid_hex|block_uuid_hex|recipient_fingerprint_hex|expected_fingerprint_hex|got_fingerprint_hex): String,?\s*$' \
  --include='*.rs' ffi/secretary-ffi-bridge/src/ | wc -l   # expect 0

# Spec §11: no FFI surface change.
git diff main... -- ffi/secretary-ffi-uniffi/src/secretary.udl

# Spec §10: no commit on the branch reds the real scan.
git rebase --exec 'uv run scripts/check-error-payload-hygiene.py' main
```
Expected: all green; the gated-`String` grep prints `0`; the `git diff` is **EMPTY**; the `git rebase --exec` completes without stopping. (If the rebase stops, the commit it stopped on reds the scan — that is a Task-2/Task-4 ordering defect, not something to force past. `git rebase --abort` and fix the ordering.)

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
docs: #500 closes the E3 laundering shapes FOR THE BRIDGE, not tree-wide (#500)

CLAUDE.md, the guard's LIMITS docstring, the allowlist preamble and e3.py's
own docstring all now say the same two things: the four laundering shapes
CLAUDE.md listed as needing dataflow analysis are closed by the compiler on
the bridge, and they remain OPEN on the two wrapper roots, whose error types
keep `String` because uniffi's UDL must project one.

Keeping that distinction sharp is the point. "Documentation claiming more
coverage than the code delivers" was the single most repeated review finding
of the #496 branch, and "laundering is fixed" is exactly the sentence this
change invites someone to write.

One NEW limit recorded rather than glossed: the `test-support` gate is a
BUILD-CONFIGURATION guarantee, not a language one. `Detail::for_test` can
mint a `Detail` from a runtime String and is absent from shipped artifacts
only because resolver v2 declines to unify a dev-dependency's features into a
non-test build.

Also notes that E2 does not sweep `FfiAddedRecipient` / `FfiWideningReport`
(not `*Error`/`*Warning`), so for those two fields the newtype is the only
declaration-level enforcement — and that their sibling `display_name` /
`block_name` fields deliberately carry plaintext and stay `String`.

Identity-harness baseline re-taken; every differing line attributed to a
named rule change.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## After the last task

Spec §10 requires a **whole-branch review on the most capable model** — #496's real regression was invisible to every per-task review and surfaced only in an old-vs-new differential. Ask specifically for:

1. An **old-vs-new guard differential**: load the guard from `3775ef5` and from HEAD in one process, push fixtures through both, and diff the findings. Per-task review cannot see cross-task interactions.
2. Verification that **no commit on the branch reds the real scan** (`git rebase --exec 'uv run scripts/check-error-payload-hygiene.py'`).
3. A check that every claim in CLAUDE.md and the LIMITS docstring is one the code delivers.

Then: push, open the PR, and write the handoff at `docs/handoffs/2026-08-09-500-detail-newtype-shipped.md` with the symlink retargeted in the same commit.
