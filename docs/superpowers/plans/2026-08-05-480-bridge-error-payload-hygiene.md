# Bridge Error-Payload Hygiene (#480 + #481 + #478) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every platform-visible detail string built in `ffi/secretary-ffi-bridge` constructible only through typed, secret-free constructors, and extend `scripts/check-error-payload-hygiene.py` to enforce that structurally (rules E2/E3/E4), closing #480, #481, and #478.

**Architecture:** A new `ffi/secretary-ffi-bridge/src/error/detail.rs` module is the only place a detail `String` may be built — constructors take `&'static str`, integers, `[u8; 16]`, or `&impl GatedDetail` (a marker trait implemented in that one file for types whose `Display` is already owned). The Python guard gains three lexically-tractable rules: E2 (bridge declaration sweep), E3 (gated-field initializer gate), E4 (`GatedDetail` impl cross-check against the guard's own registry).

**Tech Stack:** Rust (stable, workspace `cargo test --release`), Python 3.11 stdlib-only guard script run via `uv`, existing TAB-separated allowlist format shared with `scripts/lib/hygiene-allowlist.sh`.

**Spec:** `docs/superpowers/specs/2026-08-05-480-bridge-error-payload-hygiene-design.md` (committed `443f247`).

## Global Constraints

- Branch `feature/480-bridge-error-payload-hygiene`, worktree `/Users/hherb/src/secretary/.worktrees/480-bridge-error-payload-hygiene`. ALL commands below run from that worktree root unless stated. The Edit/Write tools MUST use full `.worktrees/480-bridge-error-payload-hygiene/...` paths — bare `secretary/` paths hit the main checkout.
- No `.udl` change, no `FfiVaultError`/`FfiUnlockError` variant or field-name change, no conformance-KAT regeneration. `git diff main... -- ffi/secretary-ffi-uniffi/src/secretary.udl` must stay EMPTY.
- The pinned gated-field-name set (spec §3.2): `detail`, `uuid_hex`, `block_uuid_hex`, `recipient_fingerprint_hex`, `expected_fingerprint_hex`, `got_fingerprint_hex`. DTO-only names `record_uuid_hex` / `device_uuid_hex` are deliberately NOT in the set (data-carrying DTO fields, not diagnostics).
- Guard changes follow the #474 review discipline: every new self-test control must be mutation-verified (break the guard, watch the control fail) before its commit.
- `#![forbid(unsafe_code)]`; clippy `-D warnings` clean; rustdoc `-D warnings` clean; files kept under ~500 lines where reasonable.
- Commit messages end with: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.
- Python runs via `uv` exclusively (never pip). Guard invocations: `uv run scripts/check-error-payload-hygiene.py --self-test` then `uv run scripts/check-error-payload-hygiene.py`.
- Between Task 3 and Task 8 the real scan is EXPECTED RED — the finding count is the progress meter. Do not "fix" this by allowlisting; each rewrite task states its expected count change.

---

### Task 1: `error/detail.rs` — GatedDetail trait, constructors, impls

**Files:**
- Create: `ffi/secretary-ffi-bridge/src/error/detail.rs`
- Modify: `ffi/secretary-ffi-bridge/src/error/mod.rs` (add `pub(crate) mod detail;`)
- Modify: `ffi/secretary-ffi-bridge/src/vault/manifest.rs:464` region (convert `ReplaceManifestError` to thiserror)
- Test: unit tests inside `detail.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**
- Produces (later tasks call these EXACTLY as spelled, module-qualified `detail::<fn>` — the guard's E3 recognizes only that call shape):
  - `pub(crate) trait GatedDetail: std::fmt::Display {}`
  - `pub(crate) fn gated(e: &impl GatedDetail) -> String` — renders `{e}`
  - `pub(crate) fn gated_with_context(context: &'static str, e: &impl GatedDetail) -> String` — `"{context}: {e}"`
  - `pub(crate) fn uuid_hex(uuid: &[u8; 16]) -> String` — `hex::encode`
  - `pub(crate) fn uuid_hyphenated(uuid: &[u8; 16]) -> String` — `format_uuid_hyphenated`
  - `pub(crate) fn fingerprint_hex(fingerprint: &[u8; 16]) -> String` — `hex::encode`
  - `pub(crate) fn gated_for_uuid(context: &'static str, uuid: &[u8; 16], e: &impl GatedDetail) -> String` — `"{context} {hex}: {e}"`
  - `pub(crate) fn literal_for_uuid(context: &'static str, uuid: &[u8; 16]) -> String` — `"{context} {hex}"`
  - `pub(crate) fn counted(context: &'static str, n: usize) -> String` — `"{context}: {n}"`

- [ ] **Step 1: Write the failing tests** (in the new file's `tests` mod; they fail to compile until the module exists — that IS the red step for a new module)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gated_renders_display() {
        let e = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        assert_eq!(gated(&e), "gone");
    }

    #[test]
    fn gated_with_context_prefixes() {
        let e = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        assert_eq!(gated_with_context("read foo", &e), "read foo: gone");
    }

    #[test]
    fn uuid_renderers() {
        let uuid = [0xABu8; 16];
        assert_eq!(uuid_hex(&uuid), "ab".repeat(16));
        assert_eq!(fingerprint_hex(&uuid), "ab".repeat(16));
        assert_eq!(
            uuid_hyphenated(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                              0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00]),
            "11223344-5566-7788-99aa-bbccddeeff00"
        );
    }

    #[test]
    fn uuid_composites() {
        let e = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let uuid = [0x01u8; 16];
        assert_eq!(
            gated_for_uuid("block file missing for", &uuid, &e),
            format!("block file missing for {}: gone", "01".repeat(16))
        );
        assert_eq!(
            literal_for_uuid("trash entry has no matching file for", &uuid),
            format!("trash entry has no matching file for {}", "01".repeat(16))
        );
    }

    #[test]
    fn counted_renders_index() {
        assert_eq!(counted("unknown settings field ignored; field index", 3),
                   "unknown settings field ignored; field index: 3");
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --release -p secretary-ffi-bridge detail 2>&1 | tail -5`
Expected: compile error — module `detail` does not exist.

- [ ] **Step 3: Write the module**

Module doc comment must state (in your own words, matching the spec): this file is the ONLY place in the bridge permitted to build a detail string; `impl GatedDetail for X` is a security decision; every impl outside this file fails CI (guard rule E4). Body:

```rust
pub(crate) trait GatedDetail: std::fmt::Display {}

// Core error enums: safe by recursion — scripts/check-error-payload-hygiene.py
// gates each one's payloads at its own definition (rule E1).
impl GatedDetail for secretary_core::vault::VaultError {}
impl GatedDetail for secretary_core::vault::block::BlockError {}
impl GatedDetail for secretary_core::unlock::UnlockError {}
impl GatedDetail for secretary_core::unlock::mnemonic::MnemonicError {}
impl GatedDetail for secretary_core::unlock::vault_toml::VaultTomlError {}
impl GatedDetail for secretary_core::identity::card::CardError {}
impl GatedDetail for secretary_core::crypto::sig::SigError {}
impl GatedDetail for secretary_core::sync::SyncError {}

// Bridge-local, guard-scanned (rule E2 covers their declarations).
// NOTE: SettingsParseError's impl is added in Task 7, when that type gains
// Display (thiserror conversion) — adding it here would not compile.
impl GatedDetail for crate::vault::manifest::ReplaceManifestError {}

// Reviewed claims OUTSIDE the guard's registries — each is an E4 allowlist
// entry (Task 8) and the claim lives in the allowlist reason column:
impl GatedDetail for std::io::Error {}              // path + errno: already disclosed
impl GatedDetail for std::num::ParseIntError {}     // fixed std phrases, no input echo
impl GatedDetail for std::str::ParseBoolError {}    // fixed std phrase, no input echo
impl GatedDetail for secretary_cli::state::StateError {} // folds io::Error / core-gated SyncError

pub(crate) fn gated(e: &impl GatedDetail) -> String {
    e.to_string()
}

pub(crate) fn gated_with_context(context: &'static str, e: &impl GatedDetail) -> String {
    format!("{context}: {e}")
}

pub(crate) fn uuid_hex(uuid: &[u8; 16]) -> String {
    hex::encode(uuid)
}

pub(crate) fn uuid_hyphenated(uuid: &[u8; 16]) -> String {
    secretary_core::vault::format_uuid_hyphenated(uuid)
}

pub(crate) fn fingerprint_hex(fingerprint: &[u8; 16]) -> String {
    hex::encode(fingerprint)
}

pub(crate) fn gated_for_uuid(context: &'static str, uuid: &[u8; 16], e: &impl GatedDetail) -> String {
    format!("{context} {}: {e}", hex::encode(uuid))
}

pub(crate) fn literal_for_uuid(context: &'static str, uuid: &[u8; 16]) -> String {
    format!("{context} {}", hex::encode(uuid))
}

pub(crate) fn counted(context: &'static str, n: usize) -> String {
    format!("{context}: {n}")
}
```

Adjust import paths to whatever the crate actually re-exports (e.g. `format_uuid_hyphenated`'s real path — check `ffi/secretary-ffi-bridge/src/error/vault/mod.rs`'s existing import of it; if it is not `pub` from core, replicate the existing bridge import). If an impl target's path differs (e.g. `BlockError` re-exported at `secretary_core::vault::BlockError`), use the path that compiles — but keep ALL impls in this file.

- [ ] **Step 4: Convert `ReplaceManifestError` to thiserror** (in `ffi/secretary-ffi-bridge/src/vault/manifest.rs` around line 464): replace the hand-written `Display` impl with `#[derive(Debug, thiserror::Error)]` + `#[error("vault manifest handle has been closed during save")]` on the type, preserving the exact message string (the bridge tests assert on it). Delete the manual `impl Display`.

- [ ] **Step 5: Run tests + clippy**

Run: `cargo test --release -p secretary-ffi-bridge 2>&1 | tail -5 && cargo clippy --release -p secretary-ffi-bridge --tests -- -D warnings 2>&1 | tail -3`
Expected: all tests pass (the new constructors are not yet called from production code — clippy may flag dead_code on constructors; if so add `#[allow(dead_code)]` on the module with a `// removed in Task 4-7 when call sites land` comment, and REMOVE it in Task 7's final step).

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat(bridge): detail.rs — GatedDetail trait + sanctioned detail constructors (#480)"
```

---

### Task 2: Guard rule E2 — bridge declaration sweep (+ E1 carve-out)

**Files:**
- Modify: `scripts/check-error-payload-hygiene.py`
- Reference: existing structures — `SCAN_ROOT` (line ~216), `run_real_scan` (~1748), `scan_source` (~1450), `POSITIVE_CONTROLS` (~1854), `NEGATIVE_CONTROLS` (~2519), `run_self_test` (~2926), `scan_control` (~2910)

**Interfaces:**
- Produces (consumed by Tasks 3/8):
  - `BRIDGE_SCAN_ROOT = REPO_ROOT / "ffi" / "secretary-ffi-bridge" / "src"`
  - `GATED_FIELD_NAMES = frozenset({"detail", "uuid_hex", "block_uuid_hex", "recipient_fingerprint_hex", "expected_fingerprint_hex", "got_fingerprint_hex"})`
  - `scan_source(...)` gains keyword arg `bridge_mode: bool = False`
  - New rule id string `"E2"`; findings keyed `path\tE2\t<collapsed declaration text>`
  - `run_real_scan` iterates BOTH roots; core files scan exactly as today (byte-identical findings), bridge files scan with `bridge_mode=True`
  - New self-test lists `BRIDGE_POSITIVE_CONTROLS` / `BRIDGE_NEGATIVE_CONTROLS` and helper `scan_bridge_control(src)` (mirrors `scan_control` with `bridge_mode=True`)

**Rule E2 semantics (implement exactly):**
1. In `bridge_mode`, the existing E1 attribute scan gets ONE carve-out: an interpolated field whose declared type is exactly `String` AND whose name is in `GATED_FIELD_NAMES` is not a finding (its construction is gated by E3). Everything else — `String` under any other name, `Vec<u8>`, unrecognized types, UNPARSED structures — denies exactly as E1 does today.
2. Additionally, for every `#[error]`-bearing enum variant or struct in a bridge file, every PARSED FIELD (interpolated or not — uniffi projects fields regardless of Display) whose type is not data-free (per the existing `is_data_free` tiers) must have its name in `GATED_FIELD_NAMES` and type exactly `String`; otherwise emit an E2 finding with the collapsed variant/struct declaration text as key. (This is what catches a platform-projected `String` that the Display never mentions.)
3. Also sweep bridge `pub enum` declarations whose NAME ends `Error` or `Warning` but carry NO `#[error]` attribute (plain derives — `SettingsWarning`, today's `SettingsParseError`): parse their fields with the existing `parse_fields`; apply check 2. Discovery: regex `\benum\s+([A-Za-z_][A-Za-z0-9_]*(?:Error|Warning))\b` over the comments-blanked view, then `balanced_slice` the body, skipping bodies inside `cfg_test_spans`.

**Expected real-scan result after this task:** exactly ONE E2 finding — `SettingsParseError::UnknownVersion { version: String }` (`ffi/secretary-ffi-bridge/src/settings/parse.rs`) — fixed in Task 7. Record the RED baseline in the commit message.

- [ ] **Step 1: Add failing self-test controls first.** Append to the new `BRIDGE_POSITIVE_CONTROLS`:

```python
(
    "BP1 String field under an unsanctioned name in a thiserror enum",
    '''
    #[derive(thiserror::Error, Debug)]
    pub enum E {
        #[error("bad version")]
        UnknownVersion { version: String },
    }
    ''',
),
(
    "BP2 String field under an unsanctioned name, interpolated (E1 path still denies in bridge_mode)",
    '''
    #[derive(thiserror::Error, Debug)]
    pub enum E {
        #[error("bad: {version}")]
        UnknownVersion { version: String },
    }
    ''',
),
(
    "BP3 non-thiserror *Error enum with a stray String field",
    '''
    pub enum SettingsParseError {
        UnknownVersion { version: String },
    }
    ''',
),
(
    "BP4 Vec<u8> under a gated name still denies (type must be exactly String)",
    '''
    #[derive(thiserror::Error, Debug)]
    pub enum E {
        #[error("x")]
        V { detail: Vec<u8> },
    }
    ''',
),
```

And to `BRIDGE_NEGATIVE_CONTROLS`:

```python
(
    "BN1 detail: String under a gated name passes the declaration scan",
    '''
    #[derive(thiserror::Error, Debug)]
    pub enum E {
        #[error("sync failed: {detail}")]
        SyncFailed { detail: String },
    }
    ''',
),
(
    "BN2 data-free payloads pass untouched",
    '''
    #[derive(thiserror::Error, Debug)]
    pub enum E {
        #[error("at #{index}")]
        V { index: usize },
    }
    ''',
),
(
    "BN3 *Error enum inside cfg(test) is not swept",
    '''
    #[cfg(test)]
    mod tests {
        pub enum FakeError {
            V { leak: String },
        }
    }
    ''',
),
```

Wire `scan_bridge_control` + the two new lists into `run_self_test` (same loop pattern as the existing lists; label prefix keeps output readable). Update the final OK line to print all four counts.

- [ ] **Step 2: Run self-test to verify the new controls FAIL** (rules not implemented yet)

Run: `uv run scripts/check-error-payload-hygiene.py --self-test; echo "exit=$?"`
Expected: FAIL listing BP1–BP4 ("POSITIVE control did not fire") — proves the controls are not vacuous before the rule exists.

- [ ] **Step 3: Implement E2 + bridge_mode carve-out + two-root `run_real_scan`.** Keep core behavior byte-identical: discovery registries for E1 tiers stay computed from core sources only; compute a SEPARATE bridge discovery pass (bridge enums/aliases/consts) for the bridge files' tier inputs, and record `scanned_error_type_names` (every `#[error]`-bearing enum AND struct name seen under either root) for Task 3's E4.

- [ ] **Step 4: Self-test green + mutation-verify.** Run the self-test (all controls pass). Then mutate: comment out the E2 name-set check, run self-test, confirm BP1/BP3 fail; restore. Comment out the `cfg_test_spans` skip, confirm BN3 fails; restore.

- [ ] **Step 5: Run the real scan, record the RED baseline**

Run: `uv run scripts/check-error-payload-hygiene.py; echo "exit=$?"`
Expected: exit 1, exactly 1 finding (`settings/parse.rs` UnknownVersion). If MORE appear, STOP and reconcile against the census in this plan's appendix before proceeding — an unexpected finding is either a census gap (fine, note it) or a rule bug.

- [ ] **Step 6: Commit** (message records the baseline: "real scan: 1 expected E2 finding (UnknownVersion), fixed in Task 7")

---

### Task 3: Guard rules E3 (construction gate) + E4 (impl cross-check)

**Files:**
- Modify: `scripts/check-error-payload-hygiene.py`

**Interfaces:**
- Consumes: Task 2's `BRIDGE_SCAN_ROOT`, `GATED_FIELD_NAMES`, `scanned_error_type_names`, bridge control lists.
- Produces: rule ids `"E3"` / `"E4"`; `DETAIL_MODULE_REL = "ffi/secretary-ffi-bridge/src/error/detail.rs"`; `sanctioned_constructor_names(detail_src) -> frozenset[str]` (regex `pub\(crate\)\s+fn\s+([a-z_][a-z0-9_]*)` over the comments-blanked view of detail.rs; missing file → empty set, which denies every constructor call: fail-closed).

**Rule E3 semantics (implement exactly):** on each bridge file's comments-blanked view, skipping `cfg_test_spans`:
1. Candidates: every occurrence of `<name>\s*:` where `<name>` ∈ `GATED_FIELD_NAMES`, NOT immediately followed by another `:` (excludes `detail::gated(...)` paths), and not preceded by an identifier char (excludes `record_uuid_hex:` matching on `uuid_hex`).
2. Read the initializer expression: the text from after the `:` to the first `,` or `}` at top-level nesting (track `(){}[]` depth; the lexer views already blanked strings/comments so literal commas can't split).
3. ACCEPT if the expression (whitespace-trimmed, then with the lexer's literal spans consulted on the RAW text) is:
   - a single string literal, optionally followed by exactly `.into()` or `.to_string()`;
   - a call whose path ends `detail::<name>(` with `<name>` ∈ sanctioned constructor names;
   - the exact token `String` (a struct/enum/fn DECLARATION's type position, not a value — a self-test control pins that `String::new()` still denies);
   - the exact same identifier as the field name (`detail: detail` re-wrap; shorthand `{ detail }` never matches step 1 at all).
4. Otherwise emit an E3 finding, key = `path\tE3\t<collapsed "name: expression"> text`.

**Rule E4 semantics (implement exactly):**
1. Find every `impl\s+GatedDetail\s+for\s+([A-Za-z0-9_:<>]+)` on the comments-blanked view of every bridge file.
2. Any match in a file other than `DETAIL_MODULE_REL` → E4 finding (key = collapsed impl line).
3. For matches in detail.rs: the target's LAST path segment must be in `scanned_error_type_names` (either root); otherwise E4 finding — allowlistable (`std::io::Error` etc., Task 8).

- [ ] **Step 1: Add failing controls.** `BRIDGE_POSITIVE_CONTROLS` additions (E3/E4 need path awareness — give `scan_bridge_control` an optional `path_label` and `detail_src` argument; default `path_label="<self-test-bridge>"` which is NOT the detail module, and `detail_src` a fixture declaring `pub(crate) fn gated(` + `pub(crate) fn uuid_hex(`):

```python
(
    "BP5 format! initializer on a gated field",
    ''' fn f() -> E { E::V { detail: format!("x: {}", leak()) } } ''',
),
(
    "BP6 method-call initializer (e.to_string()) denies",
    ''' fn f(e: X) -> E { E::V { detail: e.to_string() } } ''',
),
(
    "BP7 hex::encode initializer denies (only detail::uuid_hex is sanctioned)",
    ''' fn f(u: [u8; 16]) -> E { E::V { uuid_hex: hex::encode(u) } } ''',
),
(
    "BP8 unqualified constructor call denies (must be detail::-qualified)",
    ''' fn f(e: X) -> E { E::V { detail: gated(&e) } } ''',
),
(
    "BP9 String::new() denies (only the bare declaration token String passes)",
    ''' fn f() -> E { E::V { detail: String::new() } } ''',
),
(
    "BP10 impl GatedDetail outside detail.rs",
    ''' impl GatedDetail for SomeType {} ''',
),
(
    "BP11 impl GatedDetail in detail.rs for an unregistered type",
    # run with path_label = the detail module path
    ''' impl GatedDetail for totally::ForeignType {} ''',
),
(
    "BP12 identifier passthrough under a DIFFERENT name denies",
    ''' fn f(s: String) -> E { E::V { detail: s } } ''',
),
```

`BRIDGE_NEGATIVE_CONTROLS` additions:

```python
("BN4 literal", ''' fn f() -> E { E::V { detail: "fixed" } } '''),
("BN5 literal .into()", ''' fn f() -> E { E::V { detail: "fixed".into() } } '''),
("BN6 literal .to_string()", ''' fn f() -> E { E::V { detail: "fixed".to_string() } } '''),
("BN7 sanctioned qualified call", ''' fn f(e: X) -> E { E::V { detail: detail::gated(&e) } } '''),
("BN8 declaration shape detail: String not a finding",
 ''' pub enum E { #[error("x: {detail}")] V { detail: String } } ''' ),
("BN9 detail: detail passthrough", ''' fn f(detail: String) -> E { E::V { detail: detail } } '''),
("BN10 module path detail::x( is not an initializer",
 ''' fn f() -> String { detail::uuid_hex(&[0u8; 16]) } '''),
("BN11 record_uuid_hex is NOT a gated name",
 ''' fn f(u: [u8; 16]) -> D { D { record_uuid_hex: hex::encode(u) } } '''),
("BN12 cfg(test) construction is skipped",
 ''' #[cfg(test)] mod tests { fn f() -> E { E::V { detail: format!("{}", x()) } } } '''),
("BN13 fully-qualified crate::error::detail::gated( passes",
 ''' fn f(e: X) -> E { E::V { detail: crate::error::detail::gated(&e) } } '''),
```

Note BN8: in bridge_mode the enum declaration's `detail: String` must produce NO E3 finding (E2 handles declarations); the exact-token-`String` acceptance is what this pins.

- [ ] **Step 2: Run self-test — verify BP5–BP12 fail** (not yet implemented). `uv run scripts/check-error-payload-hygiene.py --self-test`

- [ ] **Step 3: Implement E3 + E4** per the semantics above. Wire into `run_real_scan`'s bridge loop; findings filter through the allowlist exactly like E1 (`f"{f.path}\t{rule}\t{f.source_line}"`).

- [ ] **Step 4: Self-test green + mutation-verify.** Run the self-test (all controls green), then apply each mutation below, confirm the NAMED control fails, and restore before the next: (a) drop the `::`-lookahead exclusion → BN10 fires spuriously; (b) accept `.to_string()` on ANY receiver, not just literals → BP6 reports "did not fire"; (c) make `sanctioned_constructor_names` return the empty set → BN7 fires spuriously; (d) accept unqualified constructor names (drop the `detail::` path requirement) → BP8 reports "did not fire"; (e) drop rule E4's outside-detail.rs file check → BP10 reports "did not fire"; (f) drop E4's registry check → BP11 reports "did not fire".

- [ ] **Step 5: Run real scan; record the RED inventory.** Expected magnitude per the census appendix: ~86 E3 findings on `detail:` sites + 24 on hex-field sites + 4 E4 findings (`std::io::Error`, `ParseIntError`, `ParseBoolError`, `StateError`) + 1 E2 (UnknownVersion). Reconcile the ACTUAL list against the appendix; investigate any site in one and not the other before committing.

- [ ] **Step 6: Update the guard's module docstring** — WHY/RULE/LIMITS sections gain the E2/E3/E4 story: the sink-pinning argument, the pinned field-name set, the `String`-token acceptance, the post-construction-assignment (`x.detail = ...`) blind spot, the naming-convention discovery heuristic, and DELETE the now-false LIMITS paragraph "It covers `core/src/**` only... Do not read '#478' as 'this gap is owned.'" (replaced by the new coverage statement; the four external citation sites are Task 9).

- [ ] **Step 7: Commit** (message records the full RED count as the burn-down baseline)

---

### Task 4: Rewrite sites — `error/`, `create.rs`, `unlock.rs`, `vault/`

**Files:** Modify: `ffi/secretary-ffi-bridge/src/error/unlock.rs`, `error/vault/mod.rs`, `create.rs`, `unlock.rs`, `vault/orchestration.rs`, `vault/manifest.rs`. Tests live beside them and in `error/vault/tests.rs`.

**Interfaces:** Consumes Task 1's constructors (always `use crate::error::detail;` + `detail::<fn>(...)` call shape).

Every site below, exact target expressions (add `use crate::error::detail;` to each touched file):

| Site | Current | Target |
|---|---|---|
| `error/unlock.rs:76` | `detail: inner.to_string()` | `detail: detail::gated(inner)` (binding is a reference; adjust `&`/deref to compile) |
| `error/unlock.rs:85` | `detail: e.to_string()` | `detail: detail::gated(&e)` |
| `error/unlock.rs:103` | `detail: e.to_string()` | `detail: detail::gated(&e)` |
| `error/unlock.rs:118` | `detail: e.to_string()` | `detail: detail::gated(&e)` |
| `error/vault/mod.rs:424` | `detail: format!("{context}: {source}")` | rebind arm to `e @ VE::Io { .. }` → `detail: detail::gated(&e)` (core Display: `vault I/O error ({context}): {source}`) |
| `error/vault/mod.rs:452` | `uuid_hex: hex::encode(block_uuid)` | `uuid_hex: detail::uuid_hex(&block_uuid)` (match binding is by-value `[u8;16]` here — adjust `&` as needed) |
| `error/vault/mod.rs:460-461` | `expected_fingerprint_hex: hex::encode(expected)` etc. | `detail::fingerprint_hex(&expected)` / `detail::fingerprint_hex(&got)` |
| `error/vault/mod.rs:485` | `recipient_fingerprint_hex: hex::encode(fingerprint)` | `detail::fingerprint_hex(&fingerprint)` |
| `error/vault/mod.rs:493,501,541` | `detail: hex::encode(block_uuid)` | `detail: detail::uuid_hex(&block_uuid)` |
| `error/vault/mod.rs:509` | multi-line `format!("trashed block {} failed verification: {detail}", hex::encode(block_uuid))` | rebind arm `e @ VE::RestoreVerificationFailed { .. }` → `detail: detail::gated(&e)` — content becomes core's own Display (`trashed block [7, 7, …] failed verification: …`; the UUID rendering changes from hex to Debug-array — update any test asserting the old shape DELIBERATELY, keeping a content assertion on the inner detail text) |
| `error/vault/mod.rs:524` | multi-line RestoreTargetMissing format | rebind `e @ VE::RestoreTargetMissing { .. }` → `detail: detail::gated(&e)` |
| `error/vault/mod.rs:556,565` | `block_uuid_hex: format_uuid_hyphenated(&block_uuid)` | `block_uuid_hex: detail::uuid_hyphenated(&block_uuid)` |
| `error/vault/mod.rs:604` | `detail: format!("{e}")` | `detail: detail::gated(e)` (the `e @ (...)` binding already exists) |
| `create.rs:347` | `format!("vault.toml unreadable post-create: {e}")` | `detail::gated_with_context("vault.toml unreadable post-create", &e)` |
| `create.rs:352` | `format!("vault.toml undecodable post-create: {e}")` | `detail::gated_with_context("vault.toml undecodable post-create", &e)` |
| `vault/manifest.rs:351` | `format!("owner card re-encode failed: {e}")` | `detail::gated_with_context("owner card re-encode failed", &e)` |
| `unlock.rs:81`, `vault/orchestration.rs:78` | literals | UNCHANGED (E3-clean already) |

Also `error/conversions.rs:25,27` shorthands: UNCHANGED (E3 rule 3).

- [ ] **Step 1: Rewrite the table above.**
- [ ] **Step 2: Run bridge tests; update detail-shape assertions deliberately** (census lists the test destructuring sites; only RestoreVerificationFailed/RestoreTargetMissing content changes shape). `cargo test --release -p secretary-ffi-bridge 2>&1 | tail -5`
- [ ] **Step 3: Guard burn-down check.** `uv run scripts/check-error-payload-hygiene.py 2>&1 | grep -c 'E3'` — expected: count dropped by exactly the number of sites rewritten in this task (compute from the table; record actual in the commit message).
- [ ] **Step 4: Commit.**

---

### Task 5: Rewrite sites — `record/`, `contacts/`, `trash/`, `edit/`

**Files:** Modify: `record/orchestration.rs`, `contacts/{mod,export,import,enumerate,delete,share,recipients,revoke}.rs`, `trash/{list,orchestration}.rs`, `edit/{mod,move_record,tombstone}.rs`.

Exact targets (same import convention):

| Site | Target |
|---|---|
| `record/orchestration.rs:156` | `uuid_hex: detail::uuid_hex(block_uuid)` (adjust `&`) |
| `record/orchestration.rs:170` | `detail: detail::gated_for_uuid("block file missing for", block_uuid, &e)` |
| `record/orchestration.rs:175` | `detail: detail::gated_with_context("failed to read block file", &e)` |
| `record/orchestration.rs:211` | `detail: detail::gated_with_context("malformed block file", &e)` |
| `record/orchestration.rs:220` | `detail: detail::gated_with_context("failed to canonicalize owner card", &e)` |
| `record/orchestration.rs:227` | `detail: detail::gated_with_context("failed to extract owner pk bundle", &e)` |
| `record/orchestration.rs:231` | `detail: detail::gated_with_context("failed to parse owner ML-DSA-65 public key", &e)` |
| `record/orchestration.rs:264` | `detail: detail::gated_with_context("block decryption failed", &e)` |
| `record/orchestration.rs:242,245,283` | literals — UNCHANGED |
| `contacts/mod.rs:60` | `detail: detail::gated(&e)` |
| `contacts/mod.rs:64` | `detail: detail::gated_with_context("contact card self-signature verification failed", &e)` — `{e:?}`→Display; CardError is core-gated |
| `contacts/export.rs:31` | `detail: detail::gated_with_context("owner card re-encode failed", &e)` |
| `contacts/import.rs:31,55` | `detail::gated_with_context("ensure contacts/", &e)` / `("write contact card", &e)` |
| `contacts/import.rs:45,51` | `uuid_hex: detail::uuid_hex(&card.contact_uuid)` |
| `contacts/enumerate.rs:34,41` | `detail::gated_with_context("read_dir contacts/", &e)` / `("iterate contacts/", &e)` |
| `contacts/delete.rs:42` | `uuid_hex: detail::uuid_hex(&contact_uuid)` |
| `contacts/delete.rs:45` | `detail: detail::gated_with_context("remove contact card", &e)` |
| `contacts/share.rs:55,98` | `uuid_hex: detail::uuid_hex(...)` |
| `contacts/share.rs:103` | `detail: detail::gated_for_uuid("read contact card", uuid, &e)` |
| `contacts/recipients.rs:64`, `contacts/revoke.rs:56` | `uuid_hex: detail::uuid_hex(block_uuid)` (adjust `&`) |
| `trash/list.rs:108` | `detail: detail::literal_for_uuid("trash entry has no matching file for", &entry.block_uuid)` |
| `trash/list.rs:120,167,175` | `detail::gated_with_context("failed to read trash file"/"failed to read trash directory"/"failed to read trash directory entry", &e)` |
| `trash/orchestration.rs:89` | `detail: detail::gated(&e)` |
| `trash/orchestration.rs:103` | rebind `e @ VaultError::Io { .. }` → `detail::gated(&e)` |
| `trash/orchestration.rs:106` | `uuid_hex: detail::uuid_hex(block_uuid)` |
| `trash/orchestration.rs:156` | `detail: detail::gated(&e)` |
| `edit/mod.rs:141` | `uuid_hex: detail::uuid_hex(&record_uuid)` |
| `edit/mod.rs:282` | `detail: detail::gated(&e)` |
| `edit/move_record.rs:128`, `edit/tombstone.rs:50,91` | `uuid_hex: detail::uuid_hex(...)` |
| all `"...".into()` literal sites in these files | UNCHANGED |

- [ ] **Step 1: Rewrite.** Note the `{context}: {source}` arms rebind to whole-error `gated(&e)` — the rendered text gains core's `vault I/O error (...)` framing; existing tests asserting `"ensure contacts/"`-style substrings still match (substring is preserved inside the new text) — verify, don't assume.
- [ ] **Step 2: Bridge tests.** `cargo test --release -p secretary-ffi-bridge 2>&1 | tail -5`
- [ ] **Step 3: Burn-down check** (expected drop = table row count; record actual).
- [ ] **Step 4: Commit.**

---

### Task 6: Rewrite sites — `revoke/`, `purge/`, `save/`, `restore/`, `retention/`, `share/`, `repair/`, `sync/`

**Files:** Modify: `revoke/orchestration.rs`, `purge/orchestration.rs`, `save/orchestration.rs`, `restore/orchestration.rs`, `retention/orchestration.rs`, `share/orchestration.rs`, `repair/preview.rs`, `sync/{status,orchestration}.rs`.

| Site | Target |
|---|---|
| `revoke/orchestration.rs:89,162` | `detail: detail::gated(&e)` |
| `revoke/orchestration.rs:120` | `detail: detail::gated_with_context("identity ML-DSA-65 secret parse failed", &e)` — `{e:?}`→Display (`invalid key length`) |
| `revoke/orchestration.rs:184` | rebind `e @ VaultError::Io { .. }` → `detail::gated(&e)` (drop the `{context}: {source}` destructure) |
| `revoke/orchestration.rs:187,238` | `detail: detail::gated(&e)` |
| `purge/orchestration.rs:136,317` | `detail: detail::gated(&e)` |
| `purge/orchestration.rs:150,331` | rebind Io arm → `detail::gated(&e)` |
| `purge/orchestration.rs:153` | `detail: detail::uuid_hex(block_uuid)` |
| `purge/orchestration.rs:205,377` | `detail: detail::gated(&e)` |
| `save/orchestration.rs:135` | `detail: detail::gated(&e)` |
| `save/orchestration.rs:166` | rebind Io arm → `detail::gated(&e)` |
| `save/orchestration.rs:210` | `detail: detail::gated(&e)` |
| `restore/orchestration.rs:86` | `detail: detail::gated(&e)` |
| `restore/orchestration.rs:102` | rebind Io arm → `detail::gated(&e)` |
| `restore/orchestration.rs:105,108,140` | `detail: detail::uuid_hex(block_uuid)` |
| `restore/orchestration.rs:114,128` | rebind `e @ VaultError::RestoreVerificationFailed { .. }` / `RestoreTargetMissing { .. }` → `detail: detail::gated(&e)` (same content note as Task 4's :509/:524 — update shape-asserting tests at `restore/orchestration.rs:200-237` deliberately) |
| `restore/orchestration.rs:145` | `recipient_fingerprint_hex: detail::fingerprint_hex(&fingerprint)` |
| `restore/orchestration.rs:185` | `detail: detail::gated(&e)` |
| `retention/orchestration.rs:160` | `detail: detail::gated(&e)` |
| `retention/orchestration.rs:175` | rebind Io arm → `detail::gated(&e)` |
| `retention/orchestration.rs:206` | `detail: detail::gated(&e)` |
| `share/orchestration.rs:135` | `detail::gated_with_context("identity ML-DSA-65 secret parse failed", &e)` |
| `share/orchestration.rs:175` | `detail: detail::gated(&e)` |
| `share/orchestration.rs:203` | `uuid_hex: detail::uuid_hex(&card_uuid)` |
| `share/orchestration.rs:208` | `detail::gated_with_context("read existing contact card for overwrite check", &e)` |
| `share/orchestration.rs:233` | rebind Io arm → `detail::gated(&e)` |
| `share/orchestration.rs:236,286` | `detail: detail::gated(&e)` |
| `repair/preview.rs:91,99` | `block_uuid_hex: detail::uuid_hyphenated(&w.block_uuid)` / `uuid_hex: detail::uuid_hyphenated(&a.uuid)` |
| `sync/status.rs:86,90` | `detail: detail::gated(&e)` (StateError impl from Task 1; E4 allowlist in Task 8) |
| `sync/orchestration.rs:254,277` | `detail: detail::gated(&e)` |
| all literal `.into()` sites in these files | UNCHANGED |

- [ ] **Step 1: Rewrite.**
- [ ] **Step 2: Bridge tests** (update the restore shape assertions listed above; keep content assertions on inner text).
- [ ] **Step 3: Burn-down check** — after this task the ONLY remaining E3 findings must be the settings sites (Task 7); the only E2 finding UnknownVersion; E4 exactly the four std/cli impls. Print and verify the exact residual list.
- [ ] **Step 4: Commit.**

---

### Task 7: Settings — #481 fixes, `UnknownVersion` restructure, `SettingsParseError` → thiserror, desktop knock-on

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/settings/parse.rs`, `settings/orchestration.rs`
- Modify: `desktop/src-tauri/src/settings/parse.rs`, `desktop/src-tauri/src/errors/types.rs`, `desktop/src-tauri/src/errors/tests.rs`, `desktop/src/lib/errors.ts`
- Tests: bridge settings test mods (`settings/parse.rs` tests @201, orchestration tests if any), desktop `settings/parse.rs:248-251`, desktop `pnpm test`

**Interfaces:** Consumes `detail::counted`, `detail::gated_with_context`, `detail::gated`. Produces: `SettingsParseError` as a thiserror enum with `UnknownVersion` (no payload) + `Corrupt { detail: String }`; desktop `AppError::SettingsUnknownVersion` and `AppWarning::SettingsUnknownVersion` lose their `version` field; TS union member `{ code: 'settings_unknown_version' }` loses `version`.

- [ ] **Step 1: Write the failing mutation-proof tests FIRST** (bridge `settings/parse.rs` tests mod):

```rust
#[test]
fn unknown_field_warning_never_echoes_the_field_name() {
    let fields = vec![("secret_field_name_xyz".to_string(), "v".to_string())];
    let (_, warnings) = parse_settings_fields(SETTINGS_RECORD_TYPE, &fields).expect("lenient");
    let SettingsWarning::Corrupt { detail } = &warnings[0] else {
        panic!("expected Corrupt, got {warnings:?}");
    };
    assert!(
        !detail.contains("secret_field_name_xyz"),
        "decrypted field name leaked into warning detail: {detail}"
    );
    assert!(detail.contains("field index"), "ordinal hint missing: {detail}");
}

#[test]
fn unknown_version_error_never_echoes_the_record_type() {
    let err = parse_settings_fields("secret.record.type.v9", &[]).unwrap_err();
    let rendered = err.to_string();
    assert!(
        !rendered.contains("secret.record.type.v9"),
        "decrypted record_type leaked: {rendered}"
    );
}
```

And in `settings/orchestration.rs` (or its test location — if it has no test mod, add `#[cfg(test)] mod tests` with what is testable without a vault; if `read_settings` needs a full vault, put the not-text-typed assertion in the existing integration-test home for settings — find it with `grep -rn "is not text-typed" ffi/ core/ desktop/` and follow suit; if only the desktop asserts it, the bridge-level parse tests above are the mutation-proof anchor and the orchestration site is pinned by the guard alone — state which in the commit message).

- [ ] **Step 2: Run to verify the new tests FAIL** (name still echoed): `cargo test --release -p secretary-ffi-bridge settings 2>&1 | tail -8`

- [ ] **Step 3: Implement the bridge side.**
  - `SettingsParseError` becomes:
    ```rust
    #[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
    pub enum SettingsParseError {
        /// `record_type` is not `secretary.settings.v1`. Carries NO payload:
        /// the offending value is decrypted record content (#481/#480).
        #[error("settings record_type is not secretary.settings.v1")]
        UnknownVersion,
        /// A known field failed to parse (integer or boolean).
        #[error("settings field parse failure: {detail}")]
        Corrupt { detail: String },
    }
    ```
  - `parse_settings_fields`: `UnknownVersion { version: record_type.to_string() }` → `UnknownVersion`; the field loop becomes `for (i, (name, value)) in fields.iter().enumerate()`; the four numeric/bool arms become `detail: detail::gated_with_context("auto_lock_timeout_ms parse failure", &e)` (etc. — keep each field's literal context string exactly as today, minus the `: {e}` which the constructor adds); the `other` arm becomes `detail: detail::counted("unknown settings field ignored; field index", i)` and stops binding `other` by name (bind `_` to avoid unused warnings).
  - `settings/orchestration.rs:53` → `detail: detail::counted("settings block record count (expected 1)", block.record_count())`.
  - `settings/orchestration.rs:70` → the loop already has `i`: `detail: detail::counted("settings field is not text-typed; field index", i)`.
  - Add to `ffi/secretary-ffi-bridge/src/error/detail.rs`, beside the `ReplaceManifestError` impl (deferred from Task 1 because the type had no `Display` until now): `impl GatedDetail for crate::settings::parse::SettingsParseError {}`.
  - `settings/orchestration.rs:103` → `detail: detail::gated_with_context("settings record unparseable", &e)` (Display now, via the thiserror conversion above).

- [ ] **Step 4: Desktop knock-on.**
  - `desktop/src-tauri/src/settings/parse.rs:66-69`: arm becomes `Err(SettingsParseError::UnknownVersion) => Err(AppError::SettingsUnknownVersion)`.
  - `desktop/src-tauri/src/errors/types.rs:145`: `SettingsUnknownVersion { version: String }` → fieldless `SettingsUnknownVersion` (keep the `#[error]` message); same for `AppWarning::SettingsUnknownVersion` (~:236-238).
  - `desktop/src/lib/errors.ts`: `grep -n "settings_unknown_version\|version" desktop/src/lib/errors.ts` and update every union member / formatter that read `version` (census: lines ~24, 61, 76, 111, 173, 343). The user-facing copy keeps its fixed sentence.
  - Update desktop tests `desktop/src-tauri/src/settings/parse.rs:248-251` and `errors/tests.rs:70`.

- [ ] **Step 5: Verify.**

```bash
cargo test --release -p secretary-ffi-bridge 2>&1 | tail -5
cargo test --release --workspace 2>&1 | tail -5      # desktop src-tauri is in the workspace
(cd desktop && pnpm test 2>&1 | tail -5 && pnpm run check 2>&1 | tail -5)
uv run scripts/check-error-payload-hygiene.py; echo "exit=$?"
```

Expected: all Rust + JS tests pass; svelte-check clean; guard now reports ZERO E2/E3 findings and exactly the 4 E4 impl findings.

- [ ] **Step 6: Mutation-prove the new tests** — reintroduce `{other}` at the unknown-field site, watch the Step-1 test fail, revert; same for `version` echo.
- [ ] **Step 7: Remove any Task-1 `#[allow(dead_code)]` scaffold; clippy clean.**
- [ ] **Step 8: Commit.**

---

### Task 8: Allowlist entries → guard GREEN; parity probe; CI check

**Files:**
- Modify: `scripts/error-payload-hygiene-allowlist.txt`
- Modify: `core/tests/error_payload_hygiene_parity.rs`
- Verify (no expected change): `.github/workflows/test.yml` hygiene job

- [ ] **Step 1: Add the E4 section.** Update the header comment (it currently claims "exactly ONE rule, `E1`") to name E1/E2/E3/E4 and their meanings, then append a new section (weight: between Sections 2 and 3 — these are impl-soundness claims, reviewed once, stable):

```text
# =============================================================================
# SECTION 2b — GatedDetail IMPLS FOR TYPES OUTSIDE THE GUARD'S REGISTRIES (#480)
#
# Rule E4 verifies that every `impl GatedDetail for X` in the bridge's
# error/detail.rs names a type this guard itself scans. These four types are
# NOT scanned, so each impl is a reviewed claim about what the type's Display
# renders. Re-review on any dependency bump that touches them.
# =============================================================================

ffi/secretary-ffi-bridge/src/error/detail.rs	E4	impl GatedDetail for std::io::Error {}	path + errno — already disclosed per the threat model (same verdict as core Section 2)
ffi/secretary-ffi-bridge/src/error/detail.rs	E4	impl GatedDetail for std::num::ParseIntError {}	std renders fixed phrases ("invalid digit found in string"); the parsed input is never echoed
ffi/secretary-ffi-bridge/src/error/detail.rs	E4	impl GatedDetail for std::str::ParseBoolError {}	std renders a fixed phrase ("provided string was not `true` or `false`"); input never echoed
ffi/secretary-ffi-bridge/src/error/detail.rs	E4	impl GatedDetail for secretary_cli::state::StateError {}	Display folds a fixed prefix over io::Error (disclosed) or core-gated SyncError (cli/src/state.rs:51-62); re-verify if cli adds variants
```

The KEY column must match the guard's collapsed-impl-line key EXACTLY — after writing the entries, run the guard and paste the emitted key text verbatim if it differs.

- [ ] **Step 2: Guard GREEN.**

```bash
uv run scripts/check-error-payload-hygiene.py --self-test && uv run scripts/check-error-payload-hygiene.py; echo "exit=$?"
```

Expected: self-test OK (with the new control counts), real scan exit 0, zero findings.

- [ ] **Step 3: Vacuity check on the allowlist** — delete ONE E4 entry, re-run, confirm exactly that impl is reported; restore.

- [ ] **Step 4: Parity probe.** In `core/tests/error_payload_hygiene_parity.rs`, extend `FIXTURE` with an E4-rule line and add probes proving the rule column is honored by BOTH parsers:

```rust
// appended to FIXTURE:
"ffi/x/detail.rs\tE4\timpl GatedDetail for std::io::Error {}\treason three\n",
```

```rust
// appended to probes — NOTE probe_python/probe_bash currently hardcode "E1";
// parameterize both helpers with a `rule: &str` argument in this step.
("ffi/x/detail.rs", "E4", "impl GatedDetail for std::io::Error {}", true),
("ffi/x/detail.rs", "E1", "impl GatedDetail for std::io::Error {}", false), // wrong rule must not match
```

- [ ] **Step 5:** `cargo test --release --workspace --test error_payload_hygiene_parity 2>&1 | tail -3` — PASS.
- [ ] **Step 6:** Confirm `.github/workflows/test.yml`'s hygiene job invokes the script with no path arguments (it does — the new roots ride along; only update the job's display name if it says "core"). `grep -n -A5 'error payload hygiene' .github/workflows/test.yml`
- [ ] **Step 7: Commit.**

---

### Task 9: Docs, citation re-pointing, #478 Kotlin updates, follow-up issue

**Files:**
- Modify: `CLAUDE.md` (§"Rust error payloads" + the Commands block guard description)
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseError.kt:53-61`
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/SecretFreeError.swift:112-121`
- Modify: `android/vault-access/src/main/kotlin/org/secretary/sync/VaultSyncError.kt:25-52`
- Modify: `android/kit/src/test/kotlin/org/secretary/sync/VaultSyncErrorMappingTest.kt:19-31`
- Verify unchanged: `README.md`, `ROADMAP.md`

- [ ] **Step 1: CLAUDE.md.** Replace the quoted `:311-321` paragraph ("The guard scans everything under `core/src/` only … whole gap were tracked.") with a statement matching the new reality: the guard scans `core/src/**` AND `ffi/secretary-ffi-bridge/src/**`; bridge detail strings are constructible only via `error/detail.rs` (rules E2/E3/E4, sink-pinning like `SecretaryLog`/`diagnosticDetail`); the binding wrapper crates (`ffi/secretary-ffi-py`, `ffi/secretary-ffi-uniffi`) remain unscanned — their non-`InvalidArgument` sites are fixed literals / verbatim pass-throughs of bridge-gated strings, censused 2026-08-05 and tracked by the NEW follow-up issue (Step 5). Update the Commands-block comment above the guard invocations to name both roots. KOTLIN NOTE from the #474 baton: when editing the Kotlin KDocs below, never write `core/src/**`-style glob text inside a KDoc — Kotlin block comments NEST and `/**` inside them swallows the file; write "everything under `core/src/`".
- [ ] **Step 2: VaultBrowseError.kt + SecretFreeError.swift.** Replace each quoted "#478 covers only…/gated by review alone" passage with: the bridge halves of `CorruptVault` / `SaveCryptoFailure` details are now guard-owned (#480: `error/detail.rs` constructors + rules E2/E3/E4, CI-enforced), so both halves of the string are structurally gated; keep the pointer to `scripts/check-error-payload-hygiene.py`.
- [ ] **Step 3: VaultSyncError.kt KDoc.** Replace the traced-sites paragraph (`:25-52`) with a STRUCTURAL claim: every `FfiVaultError::SyncFailed` producer constructs its `detail` through `ffi/secretary-ffi-bridge/src/error/detail.rs` (fixed literals or `GatedDetail` folds), enforced by the hygiene guard's construction gate in CI (#480, closing #478) — a new ungated producer fails the Rust author's own PR. Delete the per-line site list (the drifted line numbers die with it). Keep the `[StateCorrupt]` paragraph but swap its content-trace for the same structural sentence.
- [ ] **Step 4: VaultSyncErrorMappingTest.kt:19-31.** Rewrite the pointer comment: the pass-through is still deliberate, its safety is now structural (#480 gate), citing #478 as closed by it; remove "(tracked as the #475 follow-up)".
- [ ] **Step 5: File the follow-up issue** (standing authorization):

```bash
gh issue create --title "binding wrappers (ffi-py / ffi-uniffi) build detail strings outside the #480 construction gate" --body "<body>"
```

Body: rules E2/E3/E4 stop at `ffi/secretary-ffi-bridge/src/**`; the 2026-08-05 census found `ffi/secretary-ffi-py` constructs ZERO details, and `ffi/secretary-ffi-uniffi` has 16 fixed-literal `FolderInvalid` sites + 16 verbatim pass-through re-wraps (list the file:line inventory from this plan's census appendix) + the deliberately-unscanned `InvalidArgument` class (platform-authored, redacted on platforms, #473/#476). Acceptance: extend E3's roots to the uniffi crate with pass-throughs accepted, or record the decision not to. Cite #480's PR.
- [ ] **Step 6: README/ROADMAP.** `grep -n "467\|472\|474\|payload" README.md ROADMAP.md` — precedent says guards appear in neither; verify and leave unchanged (state the verification in the commit message).
- [ ] **Step 7: Android compile guard for the Kotlin edits** (KDoc-only, but the nesting trap is real): `(cd android && ./gradlew :vault-access:compileKotlin :kit:compileDebugKotlin -q)` — both succeed. (`:vault-access` uses `kotlin("jvm")` — there is NO `:vault-access:compileDebugKotlin`.)
- [ ] **Step 8: Commit.**

---

### Task 10: Full gates, wrap-up

- [ ] **Step 1: The full gate list, from the worktree:**

```bash
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py
uv run scripts/check-error-payload-hygiene.py --self-test && uv run scripts/check-error-payload-hygiene.py
bash ios/scripts/check-public-log-hygiene.sh --self-test && bash ios/scripts/check-public-log-hygiene.sh
bash android/scripts/check-log-hygiene.sh --self-test && bash android/scripts/check-log-hygiene.sh
bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
(cd desktop && pnpm test && pnpm run svelte-check)
(cd android && ./gradlew :vault-access:test :kit:compileDebugKotlin)
git diff main... -- ffi/secretary-ffi-uniffi/src/secretary.udl   # MUST be empty
```

Run the two uniffi conformance scripts even though the `.udl` is unchanged (per the conformance-scripts-don't-compile-:kit lesson, plus detail-content assertions may exist in the Swift/Kotlin harnesses — if one asserts old detail text, update THAT assertion deliberately and note it). Long builds run FOREGROUND with a generous `timeout` parameter (600000) — do not background them (four agents stalled that way last session).
- [ ] **Step 2:** `bash android/scripts/check-log-hygiene.sh` unchanged-pass confirms no Kotlin edit touched a gated line; if the KDoc edits tripped a rule, fix per its allowlist discipline (they should not — comments are exempt).
- [ ] **Step 3: Verify every commit carries the trailer:** `git log main.. --format='%h %(trailers:key=Co-Authored-By,valueonly)' | awk 'NF<2'` → empty.
- [ ] **Step 4: Commit any residue; do NOT push yet** — session-end flow (baton + PR) is the controller's job, not this task's.

---

## Census appendix (authoritative inventory, gathered 2026-08-05)

Non-test `detail:` initializer sites: **121** (per-file counts: create 2 · unlock 1 · settings/parse 5 · settings/orchestration 4 · record/orchestration 10 · revoke 8 · contacts/mod 3 · contacts/export 1 · contacts/import 2 · contacts/enumerate 2 · contacts/delete 1 · contacts/share 1 · trash/list 4 · trash/orchestration 5 · purge 11 · edit/mod 3 · sync/dto 2 · sync/status 3 · sync/orchestration 6 · restore 10 · retention 5 · save 5 · share 8 · repair/preview 1 · repair/orchestration 1 · vault/orchestration 1 · vault/manifest 1 · error/conversions 2 (shorthand) · error/unlock 4 · error/vault/mod 9). Of these, the literal/shorthand sites (~35) pass E3 unchanged; the rest are rewritten in Tasks 4–7.

Non-test gated hex-field initializer sites: **24** — `hex::encode`: record/orchestration:156, contacts/recipients:64, contacts/import:45,51, edit/move_record:128, contacts/share:55,98, trash/orchestration:106, contacts/delete:42, edit/tombstone:50,91, contacts/revoke:56, edit/mod:141, restore/orchestration:145, error/vault/mod:452,460,461,485, share/orchestration:203; `format_uuid_hyphenated`: error/vault/mod:556,565, repair/preview:91,99. DTO-only names NOT gated: `record_uuid_hex` (sync/dto:107,134), `device_uuid_hex` (sync/status:70).

Type resolutions: `StateError` = `secretary_cli::state::StateError` (cli/src/state.rs:51; Decode/Encode wrap core `SyncError`, Io wraps `std::io::Error`). `MlDsa65Secret::from_bytes` → `SigError` (core/src/crypto/sig.rs:139; only `InvalidKeyLength`). `ContactCard::{from_canonical_cbor, verify_self}` → `CardError` (core/src/identity/card.rs:318/:482; all payloads data-free). `VaultError::Io` Display `vault I/O error ({context}): {source}` (E1-allowlisted); `RestoreVerificationFailed` Display `trashed block {block_uuid:?} failed verification: {detail}` (E1-allowlisted, detail: String produced only in core/src/vault/orchestrators.rs).

uniffi wrapper census (for the Task 9 issue): `FolderInvalid` fixed-literal sites — namespace/mod.rs:171,208,244,569,631,665; namespace/repair.rs:123,174,257,303,334,400. Pass-through re-wraps — errors/unlock.rs:55,57; errors/vault.rs:164,166,167,170,186,187-188,190,191,198,201,205-206,214,217. `InvalidArgument` sites (out of scope, #473/#476): namespace/mod.rs:283,603,608,674,684,820; namespace/repair.rs:221,226,367,372; namespace/block_crud.rs:135. pyo3: zero construction sites.

Desktop `UnknownVersion` consumers: desktop/src-tauri/src/settings/parse.rs:63-71 (match arm), errors/types.rs:145 (`SettingsUnknownVersion { version }`, serialized — crosses IPC) + :236-238 (AppWarning twin, test-only producer at errors/tests.rs:70), desktop/src/lib/errors.ts:24,61,76,111,173,343, desktop test parse.rs:248-251.
