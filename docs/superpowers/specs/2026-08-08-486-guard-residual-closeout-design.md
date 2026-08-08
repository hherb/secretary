# Design: closing the four residuals of the error-payload hygiene guard

**Issues:** #486 (wrapper crates unscanned) · #482 (unpinned fail-open half) ·
#487 (io::Error carrier) · #488 (E3 laundering shapes)
**Date:** 2026-08-08 · **Base:** `main` @ `7fa210c`
**Predecessors:** #474 (PR #479, `core` payloads data-free) → #480/#481/#478
(PR #489, bridge detail strings gated at construction)

---

## 1. Why this exists

`scripts/check-error-payload-hygiene.py` proves that no error payload crossing
the FFI carries a runtime `String` nobody vouched for. #474 established that
for `core/src/**`; #480 extended it to `ffi/secretary-ffi-bridge/src/**` by
pinning detail-string construction to one reviewed file.

The guard shipped with four named residuals, recorded honestly in its own
docstring and in CLAUDE.md rather than hidden. This design closes all four.
They are treated as one slice because they are one mechanism: three of the four
are the same question — *which expressions may produce a gated string, and at
which syntactic positions does the guard look for them* — and the fourth
(#482) is a missing control on the pass that decides whether a bare type name
is trusted at all.

The end state is that CLAUDE.md's "three named residuals" paragraph goes to
zero and the wrapper-crate trust boundary becomes CI-enforced rather than
review-only.

### 1.1 What the census actually says (corrected by execution)

#486's acceptance criteria rest on a census that is wrong in both directions.
It was mis-filed once, corrected once on re-review, and is still wrong. This
design re-derives it by running the live guard against the wrapper crates
(probe: import the guard by path, call `scan_bridge_construction_sites` /
`scan_source` / `scan_bridge_plain_declarations` on every wrapper source).

| #486 predicts | Measured |
|---|---|
| `uuid_hex: a.uuid_hex` "fits E3's field's-own-name shape unchanged" | **Denies.** E3 arm 4 compares the initializer to the field name exactly; `a.uuid_hex` ≠ `uuid_hex`. 4 sites. |
| ~15 uniffi "verbatim pass-through re-wraps" need classifying | **Invisible.** They are field *shorthand* (`VaultError::CorruptVault { detail }`) — no `detail:` token, so `GATED_INIT_RE` never matches and E3 never sees them. |
| `InvalidArgument` sites "deliberately out of scope, tracked by #473/#476" | **E3 fires on all 10.** The rule has no notion of that scoping; the field is named `detail`, so it is a candidate. |
| ffi-py `format!` combinations are "shape (b), fits none of E3's three shapes" | **Also invisible.** They are `new_err(format!(…))` — a function *argument*, not a gated-field initializer. Not denied; unmodelled. |

Measured totals for extending the existing rules to both wrapper crates:

- **0** rule-E1 and rule-E2 findings. The wrapper crates' own error
  declarations are already clean, so extending the declaration rules to them
  is free.
- **14** rule-E3 findings: 4 DTO field-access pass-throughs, 10
  `InvalidArgument` construction sites.

### 1.2 The finding underneath the bookkeeping

```rust
// ffi/secretary-ffi-uniffi/src/namespace/mod.rs:672
pub(crate) fn uuid_from_vec(bytes: &[u8], field: &str) -> Result<[u8; 16], VaultError> {
    bytes.try_into().map_err(|_| VaultError::InvalidArgument {
        detail: format!("{field} must be 16 bytes, got {}", bytes.len()),
    })
}
```

`field: &str`, not `&'static str`. Two producers already pass a runtime
`format!` (`namespace/repair.rs:52`, `:65`). Both interpolate only an integer
index today, so nothing leaks — but the *signature* admits any runtime string,
and 45 call sites feed it.

This is structurally the same defect class as #481 (which interpolated
decrypted settings field names), sitting one layer out from where #480 closed
it. It is the substantive reason to do #486 structurally rather than by
allowlist.

### 1.3 The `format!` census that decides rule E5

Every `format!` occurrence in both wrapper crates, classified:

| Crate | Production `format!` | Error-bound | Non-error |
|---|---|---|---|
| `secretary-ffi-py` | 16 | 16 | 0 |
| `secretary-ffi-uniffi` | 14 | 14 | 0 |

The 10 remaining occurrences (`let rendered = format!("{err}");` in
`errors/unlock.rs`, `errors/vault.rs`) are all inside `#[cfg(test)]` modules
and are excluded by the guard's existing `discovery_cfg_test_spans` pass.

**100% of production `format!` in the wrapper crates is error-bound.** That is
what makes a blanket confinement rule (§4.5) clean rather than noisy: it needs
no allowlist entries for legitimate non-error string building, because there is
none.

---

## 2. Non-goals

- **No change to the on-disk vault format, the FFI surface, or `secretary.udl`.**
  `git diff main... -- ffi/secretary-ffi-uniffi/src/secretary.udl` must be empty.
- **No new `FfiVaultError` variant or field.** (Per
  `project_secretary_ffivaulterror_workspace_match`, a variant change would
  impose a workspace-wide exhaustive-match obligation plus two conformance
  harnesses cargo cannot see. Out of scope here.)
- **No KAT regeneration.**
- **Not closing macro-generated code or trait aliasing.** Like rules E1–E4,
  every rule here reads TEXT, not expanded macros. A `macro_rules!`-generated
  declaration or construction site is invisible, and
  `use detail::GatedDetail as GD;` spells the trait under an alias. These stay
  documented residuals; closing them needs a real parser and is out of scope.
- **Not addressing #473 / #476** (carried diagnostics rendered as on-screen
  copy). Those are a rendering question on the platforms, not a construction
  question in Rust. `InvalidArgument`'s *platform-authored* payload stays
  redacted on both platforms and is untouched by this work.

---

## 3. Phase 1 — split the guard into a package

The guard is 5035 lines (~3.3k logic, ~1.4k self-test control corpus). This
slice adds three candidate forms, one rule, two scan roots and a batch of
controls — call it ~6k. The repo's standing convention is to split proactively
at 500 lines and to design new code as directory modules.

### 3.1 Layout

The entry point keeps its path, its PEP 723 header, and its two documented
invocations. Everything else moves:

```
scripts/check-error-payload-hygiene.py   entry point: PEP 723 header + dispatch
scripts/payload_guard/
    __init__.py
    config.py        REPO_ROOT, scan roots, DATA_FREE_TYPES, GATED_FIELD_NAMES,
                     DETAIL_MODULE_REL, ALLOWLIST_PATH
    lexer.py         lex_spans, render_view, strip_comments, discovery_view,
                     balanced_slice, balanced_braces, string_literal_token_ends
    types.py         Finding, strip_visibility, normalize_type, strip_field_attrs,
                     is_data_free, is_bridge_field_safe, alias_shadowed_names
    discovery.py     span passes, find_type_aliases/consts/shadows,
                     foreign_use_names, top_level_mod_names,
                     discover_declarations, _discover_tier_inputs
    allowlist.py     load_allowlist
    rules/
        e1.py        scan_source + attribute/placeholder parsing
        e2.py        bridge declaration sweeps
        e3.py        construction sites (all four candidate forms)
        e4.py        impl GatedDetail allowlist
        e5.py        wrapper-crate format! confinement (NEW, §4.5)
    scan.py          run_real_scan
    controls/
        core.py      POSITIVE_CONTROLS / NEGATIVE_CONTROLS
        bridge.py    BRIDGE_POSITIVE_CONTROLS / BRIDGE_NEGATIVE_CONTROLS
        wrapper.py   WRAPPER_* controls (NEW, §5)
    selftest.py      run_self_test, control matching, view invariants
```

The 310-line module docstring distributes to the module each part describes.
The entry point retains the WHY-THIS-EXISTS narrative and a LIMITS summary that
points at the modules holding the detail, so a reader landing on the documented
path still meets the argument first.

### 3.2 Verified constraint: `uv run` and sibling imports

Confirmed by execution before adopting this layout: a PEP 723 script with
`dependencies = []` imports a sibling package under `uv run`, from any working
directory, invoked by absolute or relative path. Python places the script's
directory on `sys.path[0]`.

### 3.3 The caller that breaks

`core/tests/error_payload_hygiene_parity.rs:102-118` loads the guard with:

```python
spec = u.spec_from_file_location("guard", sys.argv[1])
mod  = u.module_from_spec(spec); sys.modules["guard"] = mod
spec.loader.exec_module(mod)
entries = mod.load_allowlist(pathlib.Path(sys.argv[2]))
```

`spec_from_file_location` does **not** add the script's directory to
`sys.path`, so the entry point's `from payload_guard.allowlist import …` would
raise `ModuleNotFoundError`. The probe must `sys.path.insert(0, …)` the
script's parent before `exec_module`. This is the only non-doc caller that
changes.

Other callers, all unchanged: `.github/workflows/test.yml:265-268`, CLAUDE.md's
Commands block, and CLAUDE.md's prose link.

### 3.4 Acceptance: behavioural identity, not merely green

Code motion is only safe if it is provably inert. "Self-test passes" is too
weak — it would pass if a whole rule silently stopped running.

1. Self-test reports exactly `40 positive / 18 negative / 35 bridge positive /
   18 bridge negative`, and the count line is byte-identical to baseline.
2. Real scan on the clean tree: `OK`, exit 0.
3. **Planted-violation diff.** With a fixed set of planted violations (one per
   rule E1–E4) applied to a scratch copy of the tree, the guard's full stderr
   output before and after the split diffs to empty. This exercises the finding
   formatter, line numbers, allowlist keys and rule routing — not just the
   exit code.
4. `cargo test --release --workspace --test error_payload_hygiene_parity`
   green with the updated probe.

Phase 1 lands as its own commits, before any rule change, so the rule diff is
reviewable in isolation.

---

## 4. Phase 2 — the four closures

Rule E3 generalizes from *one candidate form in one root* to *four candidate
forms in three roots*. Rule E5 covers the sink class E3 structurally cannot
model.

### 4.1 #488 — laundering shapes, without dataflow

The issue states its three shapes "need dataflow, which is a different kind of
tool." They do not. The reframing: **a `let` binding to a gated name is itself
a construction of a gated value**, so gate its initializer with the same test.

| #488 shape | Closes by |
|---|---|
| 1. `e.detail = format!("{x}");` | New candidate form: `<expr>.<gated_name> =` (assignment), gated by the same shapes. |
| 2. `let detail = format!("{x}"); E::V { detail }` | New candidate form: `let [mut] <gated_name> =`. The launder *is* the candidate; the shorthand needs no coverage. |
| 3. `let detail = format!("{x}"); E::V { detail: detail }` | Same as 2 — caught at the `let`, before arm 4 ever sees it. |

Legitimate pattern bindings (`FfiVaultError::CorruptVault { detail } => …`,
function parameters) produce no `let` and no assignment, so they stay
unaffected — which is why arm 4 can remain as-is.

Measured cost tree-wide: **one** `let <gated> =` site
(`ffi/secretary-ffi-bridge/src/repair/tests/mod.rs:205`, whose RHS is
`format_uuid_hyphenated(&block_uuid)` — data-free), and **zero** assignment
sites. That file is a test module gated in its parent, which the guard's
documented per-file `#[cfg(test)]` LIMIT cannot see from inside, so it takes
one allowlist entry naming the parent's gate — the remedy that LIMIT already
prescribes.

Arm 4 (`detail: detail`) keeps its stated gap for the *parameter* case, which
no `let` covers. That residual shrinks from "any local binding" to "a function
parameter named exactly like the field", and the docstring says so.

### 4.2 #487 — the io::Error carrier

`std::io::Error` is E4-allowlisted as a **carrier**: its `Display` renders
whatever it was constructed with. A bridge site can mint one from a `format!`
and hand it to `core`'s `VaultError::Io { source }`, which reaches a gated
field via that impl — and E3 gates the bridge's own initializer expression, not
what feeds `core`'s.

**Closure:** the payload argument of `io::Error::new(…, <expr>)` and
`io::Error::other(<expr>)` becomes an E3 candidate, gated by the same shapes.

Measured cost: the four production sites in `retention/`, `purge/` (×2) and
`trash/` pass a string literal and are accepted free. One site needs rewriting
— `ffi/secretary-ffi-bridge/src/repair/orchestration.rs:137-147`, the exact
site #487 names — through a new sanctioned constructor. Test-module sites are
excluded or allowlisted as above.

`cli/src/daemon.rs:424` is the same *shape* outside every scan root and
unreachable from any gated fold (the bridge imports only
`secretary_cli::{state, pipeline}`). It stays out of scope, and the allowlist's
`impl GatedDetail for std::io::Error` reason column is updated to say the
in-root half is now CI-enforced.

### 4.3 #486 — the wrapper crates

**Scan roots** extend to `ffi/secretary-ffi-py/src/**` and
`ffi/secretary-ffi-uniffi/src/**`. Per the existing discipline, each root gets
its **own** discovery pass — a wrapper-local alias/const/enum must not vouch
for a bridge or core field, or vice versa.

**New accepted E3 shape 5 — field access ending in the gated name.**
`uuid_hex: a.uuid_hex` is accepted when the final path segment equals the field
name. This is arm 4's name-trust one level deeper, and it is labelled as such:
it trusts that a field named `uuid_hex` on some other type was gated where
*that* type declared it — which, for the four DTO sites, rules E2/E3 in the
bridge do in fact establish. The docstring states the trust relation rather
than claiming provenance.

**Shape 5 is scoped to the two wrapper roots**, not granted tree-wide. It is a
new *acceptance*, so widening it to the bridge would open a laundering door
there (`detail: some_local.detail`) in exchange for nothing — the bridge has
no DTO pass-through sites, which §1.1's measurement confirms: all four live in
the wrapper crates. A rule that accepts more is only safe where something needs
it. The self-test pins both halves: a wrapper-root control where shape 5
accepts, and a bridge-root control where the identical expression still denies.

**Sanctioned constructors per wrapper crate.** Each gets an `error/detail.rs`
holding the only functions permitted to build its error strings. They do not
need the `GatedDetail` trait — their inputs are `&'static str`, integers, and
already-gated bridge values — so **rule E4 stays bridge-scoped**. That is not
merely a scoping choice: `GatedDetail` is declared `pub(crate)` in the bridge,
so no wrapper crate can implement it even if a future author tried. E4's
premise ("the set of types a detail string can be built from is exactly the set
of impls in one reviewed file") is therefore unaffected by the new roots.
Shapes needed:

- uniffi: `arg_len(field: &'static str, expected: usize, got: usize)`,
  `range(context: &'static str, min: …, max: …)`.
- ffi-py: the two `format!` combinations of already-gated fields
  (`NotAuthor`'s two fingerprint hexes; `RepairRejected`'s `block_uuid_hex` +
  `detail`).

**Signature tightening.** `uuid_from_vec` / `array32_from_vec` take
`field: &'static str`. The two producers passing `&format!("approvals[{idx}]…")`
are rewritten — the index they carry is a caller-side loop counter, and the
natural fix is a constructor arm taking `(&'static str, usize)` rather than a
formatted label.

### 4.4 #482 — the unpinned fail-open half

`foreign_use_names` is a **withdrawal** pass: hiding a `use` from it RESTORES
a bare-name credit. Its polarity is inverted relative to the three
credit-granting registries, which is why it reads a union of the raw source and
the comments-blanked view.

Verified by mutation before designing:

| Mutation | Self-test | Meaning |
|---|---|---|
| baseline | `OK 40/18/35/18` | — |
| raw read only (drop blanked half) | **`OK`, exit 0** | **unpinned** — #482 confirmed |
| blanked read only (drop raw half) | P38 + P39 fail | pinned |

And the shape the issue names genuinely discriminates:
`use std::/*why*/io::Error;` → raw read yields `[]`, blanked read yields
`['Error']`.

**Closure:** control **P40**, modelled on P38 — a local `pub enum Error` giving
the bare spelling a tree-global credit, a variant carrying `#[from] Error`, and
`use std::/*why*/io::Error;` to withdraw it. Fires at baseline; goes silent
under the raw-only mutation. Mutation-proven both ways: raw-only breaks exactly
P40, blanked-only breaks exactly P38/P39, and neither leaves the self-test
green.

Plus the two companions the issue folds in:

1. `LIMIT 4`'s enumeration is wrong. It says rustc catches "only the
   `type usize = String;` costume"; `type bool = String;` also warns
   (`non_camel_case_types`). Only CamelCase shadows (`type CborFault = String;`)
   are lint-invisible. The substantive point stands; the enumeration is
   corrected.
2. `docs/superpowers/plans/2026-08-05-474-error-payload-hygiene.md` (`:1222`,
   `:2438`, `:2531`) still says #478 owns the whole bridge-unscanned gap. PR
   #479 corrected every live site; the plan is a historical execution artifact
   that now trails the code and gets a dated correction note.

The `foreign_use_names` docstring's fail-closed reasoning is amended to state
the polarity explicitly — the existing "blanking can only ever HIDE text, so
discovery is fail-closed" claim is true for the three credit registries and
**false for this pass**, which is what made the gap easy to miss.

### 4.5 Rule E5 — the binding wrappers may not author error strings

E3 gates *gated-field initializers*. ffi-py's platform sink is not one:

```rust
FfiVaultError::NotAuthor { expected_fingerprint_hex, got_fingerprint_hex }
    => VaultNotAuthor::new_err(format!("expected={expected_fingerprint_hex}, got={got_fingerprint_hex}")),
```

That is a function argument. No extension of E3's initializer model reaches it,
and modelling "which function arguments become platform errors" is the dataflow
problem #488 was reframed to avoid.

**Rule E5:** in `ffi/secretary-ffi-py/src/**` and
`ffi/secretary-ffi-uniffi/src/**`, a `format!` invocation outside that crate's
`error/detail.rs` is a finding.

This is the same sink-pinning move `SecretaryLog` makes for logcat (#472),
`diagnosticDetail` for `privacy: .public` (#467) and `error/detail.rs` for the
bridge (#480) — do not police call sites, make the unsafe call unrepresentable
and review the one file that defines what safe means. §1.3 is what makes it
viable: 30/30 production `format!` sites are error-bound, so confinement costs
zero legitimate-use allowlist entries.

**E5 is scoped to the two wrapper crates, and the bridge is deliberately
excluded.** The asymmetry is empirical, not arbitrary. In the wrapper crates
100% of production `format!` is error-bound (§1.3), so confinement costs
nothing. In the bridge it is not: the majority of its 24 sites build
**filenames** — `format!("{}.cbor.enc", …)`, `format!("{}.card", …)` in
`record/`, `contacts/` (×5), `trash/`, `share/`, `sync/` — which are a
legitimate, non-error use of string composition. Confining `format!` there
would buy one rule at the price of ~9 allowlist entries for path building,
diluting exactly the signal the allowlist's highest-weight sections exist to
carry. The bridge's error strings are already gated at their initializers by
E3, and #487's carrier gap (§4.2) is the one path that bypassed that; closing
it is what the bridge needs, not confinement.

**Scope boundary, stated not papered over.** E5 covers `format!`, not
`.to_string()`. `format!` *composes* a new string from runtime parts;
`.to_string()` *renders* one value's `Display`. Every current `.to_string()`
receiver in the error-mapping path is a bridge error type this guard already
scans (18 sites in ffi-py's `errors.rs`, receiver `e: &FfiVaultError`). The
implementation censuses every receiver; if any is not an already-gated type,
E5 extends to cover it and this paragraph changes accordingly. `#[cfg(test)]`
exclusion carries over unchanged.

---

## 5. Testing

Every rule in this guard is pinned by controls in the self-test, and every
control is **mutation-verified** — remove the rule (or the specific arm), watch
exactly the intended control go red. A control that stays green under its own
mutation is not a control. This slice adds, at minimum:

- **P40** (§4.4), mutation-proven in both directions.
- **E3 candidate forms**: positive controls for `let <gated> = <ungated>`,
  `let mut <gated> = <ungated>`, `x.<gated> = <ungated>`,
  `io::Error::new(kind, <ungated>)`, `io::Error::other(<ungated>)`; negative
  controls for the legitimate `let <gated> = detail::gated(&e)`, the pattern
  binding, the function parameter, and the four literal-payload io sites.
- **E3 shape 5**: positive control for a field access whose last segment is
  *not* the gated name; negative for the DTO pass-through that is.
- **E5**: positive controls for `format!` in each wrapper crate outside
  `error/detail.rs`; negatives for `format!` inside it and inside
  `#[cfg(test)]`.
- **Root separation**: a wrapper-local alias/const/enum must not vouch for a
  bridge or core field (the discipline `_discover_tier_inputs` already
  enforces per root), pinned by a control.

Rust-side: the two new `error/detail.rs` modules get unit tests pinning each
constructor's rendered output, following `ffi/secretary-ffi-bridge/src/error/detail.rs`'s
own `mod tests`. Per #475's discipline, assertions are on message **content**,
not merely on error type — asserting only the type is how the #472 wrapper
regression shipped unnoticed.

Full gate list for the branch is the standard one from CLAUDE.md (workspace
tests, clippy, rustdoc, fmt, both hygiene shell guards, both conformance
runners, desktop, `:vault-access:test` + `:kit:compileDebugKotlin`), plus the
guard's own self-test and real scan.

---

## 6. Risks and open questions

- **Phase 1 is the risk concentration.** Moving 5k lines of a security control
  can silently disable a rule. §3.4's planted-violation diff is the mitigation,
  and it is a hard gate, not a nicety.
- **E5's `.to_string()` boundary** (§4.5) is a scope decision resolved by a
  census during implementation, not an assumption. If the census is not clean,
  the rule widens.
- **Rule count is growing.** Five rules, three roots, four candidate forms.
  The entry-point docstring must keep a single readable statement of what is
  and is not covered; a guard nobody can summarize is one nobody can review.
- **Allowlist growth is expected to be near zero** — two entries at most (the
  test-module `let` site of §4.1, and any test-module io site of §4.2). If
  implementation finds it needs more, that is a signal the rule is mis-shaped
  and should come back for discussion rather than being absorbed into the
  allowlist's highest-review-weight section.
- **`InvalidArgument`'s platform-authored payload stays out of scope** and
  stays redacted on both platforms. Do not sweep it into "align the platforms"
  — #473/#476 own the separate question of these diagnostics being rendered
  as on-screen copy.

---

## 7. Definition of done

- `uv run scripts/check-error-payload-hygiene.py --self-test` green, with the
  new controls counted, every one mutation-verified.
- `uv run scripts/check-error-payload-hygiene.py` green over **three** roots
  (core, bridge, both wrapper crates), with no more than two allowlist
  additions.
- `#486`, `#482`, `#487`, `#488` all closable — each with its acceptance met
  structurally, none recorded as "accepted residual".
- No `.udl` diff, no `FfiVaultError` change, no KAT regeneration.
- CLAUDE.md's guard section rewritten: three named residuals → zero; wrapper
  boundary CI-enforced; macro/trait-alias invisibility retained as the honest
  remaining limit.
