# Design: bridge error-payload hygiene — extend the #474 guard to `secretary-ffi-bridge` (#480, absorbing #481 and #478)

**Status:** DRAFT — under review, not yet approved.
**Date:** 2026-08-05.
**Issues:** closes #480 (bridge scan gap), #481 (settings field-name leak), #478 (`SyncFailed` gating — via its "extend the guard broadly" acceptance alternative).

## 1. Problem

`scripts/check-error-payload-hygiene.py` (#474) proves every `core` error payload is
data-free by construction — and stops exactly there. The FFI bridge
(`ffi/secretary-ffi-bridge/`) builds the strings the platforms actually see:
16 `detail: String` fields across `FfiUnlockError` (2), `FfiVaultError` (12),
`SettingsWarning` and `SettingsParseError` (1 each) — plus 9 further `String`
fields carrying hex renderings of UUIDs and public-key fingerprints under the
names `uuid_hex` / `block_uuid_hex` / `recipient_fingerprint_hex` /
`expected_fingerprint_hex` / `got_fingerprint_hex` — filled at ~60 construction sites
(`detail: format!(...)` / `e.to_string()` folds) across ~25 files. Those sites are
gated by review alone. #474 removed both platforms' wholesale redactions on the
strength of the `core` guarantee; the bridge is where that guarantee currently ends.

Two live leaks prove the gap (both #481):

- `settings/orchestration.rs:70` — `format!("settings field '{}' is not text-typed", field.name())`,
  a **decrypted settings field name**.
- `settings/parse.rs:115` — `format!("unknown settings field ignored: {other}")`,
  an **arbitrary decrypted field name** (the forward-compat bucket, unconstrained).

The census for this design found a third, one hop away:

- `SettingsParseError::UnknownVersion { version: String }` carries the raw
  `record_type` read from the **decrypted settings record**, and
  `settings/orchestration.rs:103` renders it into a detail via `{e:?}` (Debug).

## 2. Approach decision

**Chosen: sanctioned detail constructors + sink-pinning ("Approach B").** The same
move this repo has made three times: Android pins every logcat sink to
`SecretaryLog`, whose signatures make the unsafe 3-arg call unrepresentable; iOS
funnels every rendering through `diagnosticDetail`; `core` discards the `ciborium`
message inside the one module that ever sees it (`core/src/cbor.rs`). Construction
of a detail string becomes possible only through typed constructors whose
signatures cannot express the leak, and the Python guard's job shrinks to lexical
checks it can perform soundly.

**Rejected — "scan + allowlist":** add the bridge to `SCAN_ROOT` and allowlist all
16 `detail: String` variants with construction-site claims. Small diff, but it
makes Section-3-style entries (point-in-time human claims the guard structurally
cannot verify) the *rule* precisely where the platform surface is, and every
future producer edit silently invalidates one. #480's acceptance leans against it
("extend the recursion tier rather than allowlisting ~20 folds one by one").

**Rejected — "expression classifier":** teach the Python guard to classify
arbitrary `format!` argument expressions (which binding, from which match arm, of
what type). That is type inference by regex — the exact hazard the #474 guard's
LIMITS block documents as needing a real resolver, and the #474 reviews took five
adversarial fix rounds on a strictly simpler problem. Fail-open risk, rejected.

## 3. Architecture

### 3.1 Rust: `error/detail.rs` — the only place a detail string is built

New module `ffi/secretary-ffi-bridge/src/error/detail.rs`:

- **`pub(crate) trait GatedDetail: std::fmt::Display {}`** — a marker whose
  meaning is: *this type's `Display` output is already owned* — by the hygiene
  guard at the type's own definition (core error enums: safe by recursion), or by
  an explicit reviewed claim (`std::io::Error`: path + errno, already-disclosed
  per the threat model). Implementing it is a **security decision**, exactly as
  conforming `SecretFreeError` / `SecretFreeThrowable` is on the platforms.
- **Every `impl GatedDetail for X` lives in this one file.** The Python guard
  cross-checks the list (rule G3 below), so an unsound impl fails CI.
- **Constructors** covering the shapes the call-site census found — none accepts a
  runtime `String` or `&str`; every textual parameter is `&'static str`
  (compile-time enforced, the `set_once` mechanism from #474):

  | Constructor (names indicative) | Shape it replaces |
  |---|---|
  | `gated(e: &impl GatedDetail) -> String` | `format!("{e}")`, `e.to_string()` |
  | `gated_with_context(context: &'static str, e: &impl GatedDetail)` | `format!("read contact card: {e}")` |
  | `uuid_hex(uuid: &[u8; 16])` | `hex::encode(block_uuid)` |
  | `gated_for_uuid(context: &'static str, uuid: &[u8; 16], e: &impl GatedDetail)` | `format!("block file missing for {}: {}", hex::encode(u), e)` |
  | `literal_for_uuid(context: &'static str, uuid: &[u8; 16])` | `format!("trash entry has no matching file for {}", hex::encode(u))` |
  | `counted(context: &'static str, n: u64)` | `format!("settings block has {} records (expected 1)", n)`; #481's static-hint-plus-ordinal shape |

  The exact constructor set is finalized during implementation from the full
  census; the **constraint** is fixed: parameters are `&'static str`, data-free
  scalars (integers), 16-byte UUIDs (already-disclosed — they are block file
  names on disk), or `&impl GatedDetail`. Constructors render `Display` only,
  never `Debug`.

- **All ~60 construction sites rewritten** to string literals or constructor
  calls. Multi-line folds that interpolate a core error's *fields*
  (`RestoreVerificationFailed { block_uuid, detail }` →
  `format!("trashed block {} failed verification: {detail}", …)`) collapse to
  `gated(&e)` over the whole core error where core's own `Display` renders the
  same content; where it does not, a combination constructor is used. `{e:?}`
  Debug folds become `Display` folds (§4.3).

### 3.2 Python: three new lexically-tractable rules

The guard keeps its single-lexer architecture (`lex_spans` + blanked views) and
gains a bridge rule family. Scan roots become `core/src` (existing rules,
unchanged) plus `ffi/secretary-ffi-bridge/src` (existing declaration rule +
G1–G3). Default-deny throughout; every new denial is allowlistable only by exact
normalized text; `--self-test`-first discipline with mutation-verified controls.

- **G1 — declaration rule.** Bridge `#[error]` enums are scanned with the
  existing core rule. A `String`-typed payload field in a bridge error/warning
  enum is *not* an automatic denial (the construction gate is what makes it
  safe), **provided its name is in the pinned gated-field set** — `detail`,
  `uuid_hex`, `block_uuid_hex`, `recipient_fingerprint_hex`,
  `expected_fingerprint_hex`, `got_fingerprint_hex` (the existing FFI
  surface's `String` fields; renaming them would change the platform-visible
  field names, which §3.3 forbids). A `String` field under any other name
  denies at the declaration. This is what turns
  `UnknownVersion { version: String }` into a build-time finding rather than a
  code-review hope. Enums without `#[error]` (e.g. `SettingsWarning`,
  `SettingsParseError` — plain derives) are covered by the same declaration
  sweep over `pub enum` items whose name ends in `Error` or `Warning`
  (a stated-limit heuristic; see §6).
- **G2 — construction gate.** Every field initializer for a gated-field name
  (`detail:`, `uuid_hex:`, `block_uuid_hex:`, `recipient_fingerprint_hex:`,
  `expected_fingerprint_hex:`, `got_fingerprint_hex:`) in bridge non-test code
  (test spans skipped via the existing `cfg_test_spans` machinery) must be one
  of:
  1. a string literal, optionally followed by `.into()` / `.to_string()`;
  2. a call to a sanctioned constructor (path ending in one of the
     `detail.rs` function names, which the guard reads from `detail.rs`
     itself rather than hardcoding);
  3. the exact passthrough of an already-gated value: field shorthand
     (`{ detail }`) or `detail: detail`.
  Anything else — any `format!`, any other method call, any other identifier —
  denies. The allowlist is the only escape, and entries there are Section-3
  weight (construction-site claims).
- **G3 — trait-impl cross-check.** Every `impl GatedDetail for X` is extracted
  from `detail.rs` (and denied if found anywhere else in the bridge). `X` must
  resolve to an error enum the guard itself scans (under either root) or to an
  explicit allowlist entry (`std::io::Error`; any third-party type a fold
  genuinely needs, each with file:line reasoning). This is #480's "extend the
  recursion tier": the impl list is the extension point, machine-checked
  against the guard's own registry.

### 3.3 What does NOT change

- `FfiUnlockError` / `FfiVaultError` **variant sets, field names, and `.udl` are
  unchanged** — `detail: String` stays `detail: String` on the FFI surface, so
  no uniffi/pyo3 regeneration, no Kotlin/Swift type changes, no conformance-KAT
  regeneration. Only the *content* of the strings is now gated. (One possible
  exception: `SettingsParseError::UnknownVersion`, §4.2.)
- The CI job from #474 already runs the script; extending the script extends the
  job. No workflow change expected beyond possibly renaming a comment.

## 4. Findings the scan will flag, and their fixes

### 4.1 The #481 sites (fix in this branch)

- `settings/orchestration.rs:70` → `counted("settings field is not text-typed; field index", i)`
  (static hint + ordinal, #474's established shape; strictly loses only the
  decrypted name, keeps which field position raised it).
- `settings/parse.rs:115` → the forward-compat purpose ("a field this build
  doesn't understand was ignored") conveyed with the ordinal, not the name:
  `counted("unknown settings field ignored; field index", i)`. The parse loop
  gains the index it already iterates with.
- A test asserts the rendered warning does **not** contain the field name,
  mutation-proven by reintroducing the interpolation (#481 acceptance).

### 4.2 `SettingsParseError::UnknownVersion { version: String }` (new finding)

The `version` payload is the raw `record_type` from the decrypted record. Fix at
the declaration per G1: replace with a data-free shape (e.g. `{ length: usize }`
or no payload — the diagnostic point is "not `secretary.settings.v1`", which the
variant name already states). `settings/orchestration.rs:103`'s `{e:?}` fold then
routes through `gated`/`gated_with_context` once `SettingsParseError` implements
`GatedDetail` (it becomes a scanned, data-free bridge enum → G3-clean).
Implementation checks whether the desktop client (`desktop/src-tauri/src/settings/parse.rs`)
projects `version` and adjusts that projection; this is the one place a
platform-visible shape may change, and it is desktop-only.

### 4.3 `{e:?}` Debug folds (3 sites)

Constructors render `Display` only. Each site either switches to a `GatedDetail`
`Display` fold (where the type is a core enum — e.g. `contacts/mod.rs:64`'s
`verify_self` error) or, where the type is third-party (e.g.
`revoke/orchestration.rs:120`'s ML-DSA secret-parse error), the implementation
reviews what its `Display` renders and records the `GatedDetail` impl as an
allowlist entry — or restructures to a literal if the review cannot bound it.

### 4.4 `cli::state::StateError` folds (`sync/status.rs`)

If `StateError` lives outside the two scan roots, its two `e.to_string()` folds
need a reviewed `GatedDetail` impl + allowlist entry (G3), with the review
recorded at the entry. If it is core-owned, it is already scanned and the impl
is registry-clean. Resolved during implementation; both outcomes are sound.

### 4.5 Everything else

The remaining ~50 sites are literal prefixes over core folds, `io::Error` folds,
and UUID renderings — mechanical rewrites to the constructor set with no content
change worth noting. The implementation keeps a per-site census table in the plan
so the reviewer can spot-check content equivalence.

## 5. Boundaries and non-goals

- **The binding wrapper crates (`ffi/secretary-ffi-py`, `ffi/secretary-ffi-uniffi`)
  stay unscanned.** Their error construction is dominated by `InvalidArgument`,
  whose payload is deliberately platform/binding-authored and **stays redacted on
  both platforms** (CLAUDE.md: do not sweep it into "align the platforms"; #473 /
  #476 track its rendering). If the implementation census finds a wrapper-crate
  site constructing a *non*-`InvalidArgument` detail, it is fixed or filed — not
  silently absorbed.
- **`desktop/src-tauri` stays unscanned** — it is a consumer. #481's desktop
  projection is adjusted only as far as §4.2 requires.
- **No redaction changes on any platform.** This branch changes what the strings
  can contain, not who displays them. `VaultSyncError.Failed` keeps its detail
  (#478 acceptance: redacting it is an explicit non-goal).
- **No `.udl` change, no conformance-KAT regeneration** (§3.3), unless §4.2's
  desktop-only shape change requires a bridge-internal type adjustment — which
  does not touch the mobile FFI surface either way.

## 6. Limits (stated, not hidden)

Inherited from the #474 guard: no macro expansion, pattern-not-parser, name-based
resolution with the documented shadow hazards. New, bridge-specific:

- **G1's error-enum discovery outside `#[error]` derives is a naming-convention
  heuristic** (`*Error` / `*Warning`). An error-like enum named outside the
  convention, carrying a `String` field not named `detail`, initialized without a
  `detail:` key, is invisible to all three rules. Review owns naming; the limit
  is stated in the guard's docstring.
- **G2 gates the pinned field-name set, not the type `String`.** A bridge
  author who adds a `String` payload under a name outside the set is caught by
  G1 at the declaration — but only inside G1's discovery set (above).
- **G3 verifies the impl list, not the impl's soundness.** `std::io::Error`'s
  entry is a reviewed claim exactly like core's Section-3 entries; the honest
  statement for a `GatedDetail` type is "fails or is allowlisted at its own
  definition."
- **Passthrough form (G2.3) trusts the value was gated at its original
  construction site** — sound because every construction site in the crate is
  gated by the same rule, but a `detail` field *assigned* later
  (`x.detail = leak`) is a shape G2 does not see. The census found zero such
  sites; a self-test control pins the `detail: detail` form, and post-construction
  assignment is called out as a review item in the guard docstring.

## 7. Testing

- **Guard self-test:** new positive controls (a `format!` initializer fires; a
  `String` field named other than `detail` fires; an `impl GatedDetail` outside
  `detail.rs` fires; an impl for an unregistered type fires) and negative
  controls (literal, literal`.into()`, each constructor form, shorthand
  passthrough, test-span `format!` does not fire). Every control added is
  **mutation-verified** — deliberately break the guard and watch the control
  fail — per the #474 review discipline that caught five vacuous controls.
- **Rust tests:** the #481 mutation-proven content test (§4.1); existing bridge
  tests keep passing with content-equivalent details (sites asserting on detail
  substrings are updated deliberately, not loosened).
- **Parity test** (`core/tests/error_payload_hygiene_parity.rs`): extended if the
  allowlist grammar gains section headers, otherwise unchanged.
- **Full gate list** from the #474 baton (workspace tests, clippy `-D warnings`,
  rustdoc, conformance.py, both platform log-hygiene guards, lean-binding guard,
  both uniffi conformance runners) — the bridge is FFI-adjacent, so both
  conformance scripts run even though no signature changes (per the
  conformance-scripts-don't-compile-:kit lesson, `:kit` + `:app` compile too).

## 8. Documentation and citation re-pointing

- **The four #480-named citation sites** — CLAUDE.md (#474 section), the guard's
  LIMITS docstring, `VaultBrowseError.kt`, `SecretFreeError.swift` — currently
  say the bridge gap is unowned / #478 covers only a slice. All four are
  re-pointed to state the gap is closed and how.
- **#478's two Kotlin sites:** `VaultSyncError`'s KDoc content-traced paragraph
  (`VaultSyncError.kt:46-51`) becomes a structural claim ("gated at construction
  in the bridge, CI-enforced"), and the stale pointer comment in
  `VaultSyncErrorMappingTest.kt:24-25` cites #478's closure.
- **CLAUDE.md** command block: the guard's description updated to name both scan
  roots. README/ROADMAP: expected unchanged by precedent (#189/#467/#472/#474
  guards appear in neither); verified at the end, not assumed.

## 9. Acceptance mapping

| Issue acceptance item | Where satisfied |
|---|---|
| #480: scan root covers `ffi/secretary-ffi-bridge/src/**`, default-deny, `--self-test`-first | §3.2 |
| #480: every violation fixed or reviewed-allowlisted, sectioned by weight | §4, §3.2 |
| #480: `format!("{e}")` folds handled by recursion-tier extension, not ~20 entries | §3.1 trait + §3.2 G3 |
| #480: four citation sites re-pointed | §8 |
| #481: neither site interpolates a runtime field name; #474 shapes used | §4.1 |
| #481: forward-compat purpose preserved via ordinal | §4.1 |
| #481: mutation-proven absence test | §4.1, §7 |
| #481: sites caught by the extended scan rather than fixed-and-forgotten | §3.2 G2 |
| #478: every `SyncFailed` producer gated at construction OR guard extended to the bridge | §3.2 (the broad alternative) |
| #478: KDoc structural claim + test pointer comment updated | §8 |
| #478: `VaultSyncError.Failed` keeps its detail | §5 |
