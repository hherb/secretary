# Design: `Detail` — making the gated position a type the compiler enforces

**Issues:** #500 (the newtype) · #504 (ffi-py's two `&str` constructors) ·
#503 (un-zeroized `[u8; 32]` stack copy) · #498 *partial* (hint arguments must
be string literals)
**Date:** 2026-08-09 · **Base:** `main` @ `3775ef5`
**Predecessors:** #474 (PR #479, `core` payloads data-free) → #480/#481/#478
(PR #489, bridge detail strings gated at construction) → #486/#487/#488/#482
(PR #496, wrapper roots + laundering shapes + `io::Error` carrier)

---

## 1. Why this exists

Three consecutive slices have built a text-matching guard around one invariant:
*no error payload crossing the FFI carries a runtime string nobody vouched
for.* Each slice closed real holes. Each also shipped a longer LIMITS section
than the one before it, because a guard that reads source text can always be
evaded by source text it does not model.

The current residual list in CLAUDE.md names four E3 laundering shapes the
guard structurally cannot see — pattern-destructuring binds, build-then-mutate
through a method call, the function-parameter case, and dotless local
reassignment — and records that **two of the four are in daily use**. Closing
them was scoped as needing "local dataflow / interprocedural analysis this
construction-site guard does not do."

That framing accepts a premise worth rejecting. The reason `detail:
format!("{secret}")` is expressible at all is that the field is declared
`String`, and Rust enum-variant fields are unconditionally public. The
compiler is asked to enforce nothing; the entire invariant rides on a Python
script matching text.

This design moves the invariant into the type system for the bridge. After it,
a `String` produced by *any* laundering shape — modelled or not, present or
future — does not typecheck in a gated position. The guard stops being the
enforcement and becomes defence in depth.

### 1.1 Measured surface

All figures measured on the worktree at `3775ef5`; the command is given so
each can be re-derived rather than trusted.

| Quantity | Measured | How |
|---|---|---|
| Gated field declarations in the bridge | **27** | `grep -rnE '^\s*(pub )?<G>: String,?$' ffi/secretary-ffi-bridge/src/` |
| — of which `detail` | 15 | same, narrowed |
| — of which hex-flavoured | 12 | same, narrowed |
| `detail::…` constructor call sites (non-test) | **109** | `grep -rn 'detail::' …` minus `error/vault/tests.rs` and doc lines |
| Bridge in-crate test constructions of a gated field | **29** | `grep -rnE '^\s*<G>: .*\.to_string\(\)'` |
| Wrapper-crate **constructions** of `FfiVaultError` | **12** | see §1.2 — all in one file, all inside one `#[cfg(test)]` module |
| Gated-name mentions in the three projection files | 150 / 14 / 29 | `errors/vault.rs`, `errors/unlock.rs`, ffi-py `errors.rs`, net of doc lines and `detail::` module paths |
| `repair/preview` DTO hex mentions in wrappers | 18 | `grep -rnE '\b(uuid_hex\|block_uuid_hex)\b'` over wrapper `namespace/` + ffi-py `src/` |

`<G>` is the six-name alternation
`(detail|uuid_hex|block_uuid_hex|recipient_fingerprint_hex|expected_fingerprint_hex|got_fingerprint_hex)`.

The projection-file mention counts are **upper bounds on work, not arm
counts** — a pass-through arm mentions a gated name on both sides
(`FfiVaultError::X { detail } => VaultError::X { detail }`). They are recorded
because they bound the review surface; the exact set is enumerated by the
compiler during implementation, which is the point of the change.

Two of the 27 declarations (`repair/preview.rs:35`, `:53`) sit on a DTO
struct — `FfiAddedRecipient`, `FfiWideningReport` — rather than an error enum.
**Rule E2 does not sweep them**, and an earlier draft of this spec wrongly said
it did: sweep 1 anchors on a `#[error(` attribute these plain
`#[derive(Debug, Clone)]` structs do not have, and sweep 2 keys on the
`*Error`/`*Warning` NAME convention neither matches. Only rule E3 gates them
today, at their construction sites.

They are still in scope, and the correction strengthens rather than weakens
the case: for these two fields the newtype is the **only** declaration-level
enforcement available, because E2's inversion (§6) structurally cannot reach
them.

One caveat to carry into implementation. These DTOs deliberately carry
decrypted plaintext in *sibling* fields — `FfiAddedRecipient::display_name`,
`FfiWideningReport::block_name` ("the block's plaintext name, for display") —
which stay `String` and must. So after this change the two structs hold a mix
of `Detail` and plaintext `String` fields. That is correct but reads as
inconsistent, so `Detail`'s docstring must say what the type actually claims:
*produced by a sanctioned constructor*, *not* *this struct carries no
secrets*. Conflating the two would be an overclaim on exactly these structs.

### 1.2 Who actually needs the test hatch — corrected by execution

A first pass at this count said 19 wrapper constructions. That was wrong: the
grep counted **multi-line match-arm patterns** as constructions, because an
arm's `=>` sits on a later line than its `FfiVaultError::X {`. Re-derived by
inspecting each hit:

| Site class | Count | Needs a `Detail` it cannot construct? |
|---|---|---|
| `secretary-ffi-uniffi` `errors/vault.rs`, inside the single `#[cfg(test)] mod tests` (starts line 223; hits at 333–666) | **12** | **Yes** |
| `secretary-ffi-py` `errors.rs` | **0** | No — every hit is a match arm (`FfiVaultError::InvalidMnemonic { detail } => …`) |
| Bridge integration tests `ffi/secretary-ffi-bridge/tests/*.rs` | **0** | No — the 3 hits *destructure* a gated field and interpolate it into an assertion message (`"detail: {detail}"`), which keeps working via `Display` |

So **only `secretary-ffi-uniffi` takes the `test-support` dev-dependency.**
`secretary-ffi-py` and the bridge's own integration tests need no change at
all. §5 is scoped accordingly.

### 1.3 What the census does *not* say

The 109 `detail::` call sites are already sanctioned. This design does not
find a leak in them — it removes the possibility of a future site that is not
one of them. That distinction matters for how the result is described: this is
**prevention, not remediation**, and no live exposure is being fixed by the
newtype. (The `#503` rider is a separate, real hygiene defect; see §7.)

---

## 2. The type

In `ffi/secretary-ffi-bridge/src/error/detail.rs`:

```rust
/// A string that a sanctioned constructor in THIS module produced.
///
/// The inner field is private, so `Detail` is constructible only from inside
/// `detail.rs`. Every gated payload position in the bridge is declared
/// `Detail`, which makes `detail: format!(…)` — and every other way of
/// producing a `String` — a type error at every call site in this crate and
/// in every downstream crate.
pub struct Detail(String);

impl Detail {
    pub fn as_str(&self) -> &str { &self.0 }
    pub fn into_string(self) -> String { self.0 }
}

impl std::fmt::Display for Detail { /* writes self.0 */ }
```

`Debug` is `#[derive]`d on the struct (the bridge error enums derive `Debug`,
so every field must).

Deliberately **absent**: `From<String>`, `From<&str>`, `Deref<Target = str>`,
`Default`, `Clone` unless a call site needs it, and any `pub` constructor
outside the feature gate in §5. Each would reopen the door the private field
closes.

`Display` is required — `thiserror`'s `#[error("… {detail}")]` renders the
field — and is safe: `Display` *reads* a `Detail`, it cannot mint one.

Visibility: the module stays `pub(crate) mod detail;` and `lib.rs` gains
`pub use error::detail::Detail;`. Re-exporting a `pub` item out of a private
module is legal and is what lets downstream crates **name and read** `Detail`
while remaining unable to **construct** one.

### 2.1 Constructor signatures

`detail.rs` has **eleven** sanctioned constructors: `gated`,
`gated_with_context`, `uuid_hex`, `uuid_hyphenated`, `fingerprint_hex`,
`gated_for_uuid`, `literal_for_uuid`, `counted`, `gated_with_path`,
`gated_with_path_and_advice`, and `io_gated_with_path_and_advice`.

**Ten of the eleven** change return type `String` → `Detail`. Their parameters
are unchanged. Because all 109 call sites already delegate to them, the change
flows through those sites untouched — the diff is concentrated in `detail.rs`
and the 27 declarations.

The eleventh, `io_gated_with_path_and_advice`, is the exception: it returns
`std::io::Error`, whose payload must be `Into<Box<dyn Error + Send + Sync>>`.
It will build its `Detail` internally and pass `.into_string()` to
`io::Error::new`. The newtype therefore does **not** reach the io-payload
position, which is why rule E3 keeps that check (§6).

---

## 3. What changes in the bridge

1. All 27 gated field declarations: `String` → `Detail`.
2. Ten constructor return types: `String` → `Detail` (§2.1).
3. 29 in-crate test constructions move to the feature-gated constructor (§5).
4. `#[error("…")]` attributes: unchanged, `Display` covers them.

Nothing else. The 109 production call sites are expected to be byte-unchanged;
any that is not is a site that was *not* going through a constructor, which is
a finding in its own right and gets recorded.

---

## 4. Where the guarantee stops — stated plainly

This is the section most likely to drift into an overclaim later, so it is
written as a boundary rather than as a caveat.

The wrapper crates' **own** error types keep `detail: String`:
`secretary-ffi-uniffi`'s `VaultError` must project as `string` through the
UDL, and `secretary-ffi-py`'s exceptions take a message. Consequently:

- **Bridge — compiler-enforced.** All four documented E3 laundering shapes die
  here, along with every shape nobody has thought of yet. This is unqualified.
- **Wrapper crates — still text-guarded**, by rules E2/E3/E5 exactly as today.
  Their posture is *unchanged*, not improved.

Each wrapper pass-through arm gains one `.into_string()` at the point where a
bridge `Detail` becomes a wrapper `String`. That unwrap point is immediately
adjacent to the wrapper's own construction site, so it confers no protection
on the wrapper — it is a projection, not a gate.

Making the wrappers' types `Detail` too was considered and rejected: it would
require a uniffi `custom_type!` conversion, adding UDL surface for a type
whose whole purpose is to be unwrapped one line later.

---

## 5. The test hatch, and the CI gate it requires

**12** unit tests in `secretary-ffi-uniffi`'s `errors/vault.rs` construct
`FfiVaultError` values directly, from a *different crate*. A private inner
field locks them out, and this repo's `--cfg test` gotcha means a
`#[cfg(test)]` constructor in the bridge is invisible to them.

Per §1.2 this is the **only** consumer that needs the hatch: `secretary-ffi-py`
constructs no bridge errors, and the bridge's own integration tests only
destructure and `Display` them. The bridge's 29 in-crate test constructions are
inside the bridge, so a plain `#[cfg(test)]` constructor would reach them — but
they use the same feature-gated one, so there is a single hatch to review
rather than two.

The hatch is a non-default Cargo feature:

```toml
# ffi/secretary-ffi-bridge/Cargo.toml
[features]
test-support = []
```
```rust
#[cfg(feature = "test-support")]
impl Detail {
    /// Test-only. Absent from every non-test build; see the CI gate below.
    pub fn for_test(s: &str) -> Detail { Detail(s.to_string()) }
}
```
```toml
# ffi/secretary-ffi-uniffi/Cargo.toml — [dev-dependencies] ONLY
[dev-dependencies]
secretary-ffi-bridge = { path = "…", features = ["test-support"] }
```

### 5.1 Verified behaviour of the feature gate

The workspace sets `resolver = "2"` (root `Cargo.toml:2`, edition 2021), under
which dev-dependency features are not unified into non-test builds. Verified by
execution in a throwaway two-crate workspace reproducing this exact shape
(`resolver = "2"`, normal dep + dev-dep with the feature, a production fn
calling the hatch), on the pinned toolchain 1.97.0:

| Gate | Production call to `Detail::for_test(runtime_string)` |
|---|---|
| `cargo test --release --workspace` | **compiles — NOT caught** |
| `cargo clippy --release --workspace --tests` | **compiles — NOT caught** |
| `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace` | **caught** for the bridge — see §5.1.1 |
| `cargo clippy --release --workspace` (no `--tests`) | `error[E0599]` — caught |
| `cargo build --release --workspace` | `error[E0599]` — caught |

**Two of the five gates secretary's CI runs today miss it**, and they are the
two that run on every PR. The feature gate is a real compile-time guarantee —
the function does not exist in the shipped artifact — but only if a non-test
build runs.

#### 5.1.1 The rustdoc row depends on the crate's position in the graph

The rustdoc row was wrong in two earlier drafts of this spec, in both
directions, and the correction is worth keeping because it is not obvious.

Measured on the same throwaway workspace, cold `target/`, resolver 2, toolchain
1.97.0, varying only WHERE the leaking call lives:

| Leak lives in | `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace` |
|---|---|
| a LEAF crate (nothing depends on it) | `rc=0` — compiles clean, a genuine blind spot |
| a DEPENDED-UPON crate | `rc=101`, `error[E0599]` — caught |

Rustdoc does not type-check the bodies of the crate it is *documenting*, which
is why the leaf row is clean. But to document a crate's dependents, cargo must
build the dependency's rmeta, and that build *is* a real compilation.

`secretary-ffi-bridge` is depended on by `secretary-ffi-py`,
`secretary-ffi-uniffi` and `desktop/src-tauri`, so it is the second row: a leak
inside the bridge IS caught by the rustdoc gate. Do not generalise this to the
wrapper crates — `secretary-ffi-py` and `secretary-ffi-uniffi` are leaves, so
the same leak in either of them would be the first row.

This narrows §5.2's justification but does not remove it: `cargo test` and
`cargo clippy --tests` remain blind wherever the leak lives.

### 5.2 Required CI additions

1. **`cargo build --release --workspace`** in `test.yml`. Without it the hatch
   is decorative.
2. A guard asserting `test-support` is reachable **only** from
   `[dev-dependencies]`, in every `Cargo.toml`. Follows the house pattern:
   `--self-test` first, proving the matcher fires on known-positive controls.

   An earlier draft called a normal-dependency line "the single way to defeat
   the isolation". Review found at least four, so the guard is a TOML parse
   over the feature graph rather than a line matcher:

   - a normal `[dependencies]` / `[build-dependencies]` /
     `[target.'cfg(...)'.dependencies]` / `[workspace.dependencies]` entry
     requesting the feature;
   - `default = ["test-support"]` in the bridge's own `[features]`;
   - cross-crate forwarding, `extra = ["secretary-ffi-bridge/test-support"]`;
   - **an alias**, `hatch = ["test-support"]` plus `default = ["hatch"]` — the
     feature graph reaches the hatch without the string `test-support` ever
     appearing in a denied position. This one needs closure over the feature
     graph, not a name match.

   The guard must also fail closed on a scan root that does not exist. A root
   whose path moved contributing zero files silently is the exact fail-open
   #496 spent its final review closing in the payload guard; do not
   reintroduce it here.

---

## 6. Guard changes

No rule retires. E3's demotion is in what it *guarantees*, not in what it runs.

| Rule | Change |
|---|---|
| **E1** | Learns `Detail` as a data-free-by-construction payload type — **bridge root only**. Default-deny is preserved: the type is accepted because its constructors are the reviewed set in `detail.rs`, not because its name looks safe. |
| **E2** | **Inverts on the bridge**, from *"a `String` field is permitted only under one of six pinned names"* to the strictly stronger *"no field under a gated name may be `String`; it must be `Detail`."* Unchanged on the two wrapper roots. |
| **E3** | Keeps the `io::Error` payload position (§2.1 — the newtype does not reach it) and stays fully live on both wrapper roots. **Gains #498's literal check** (§6.1). Its bridge gated-field arms become defence in depth. |
| **E4** | Unchanged. `impl GatedDetail` stays pinned to `detail.rs`, still sealed. |
| **E5** | Unchanged. Wrapper-only `format!` confinement. |

### 6.1 #498's cheaper half

Every sanctioned constructor takes its hint in a `&'static str` parameter
(`context`, `field`, `advice`). #498 demonstrated by execution that
`Box::leak(format!(…).into_boxed_str())` mints a `&'static str` from runtime
data in safe stable Rust, passes `#![forbid(unsafe_code)]`, and scans clean.

E3 gains a requirement that every hint-position argument at a sanctioned call
site be a **string literal**. Hint positions are derived from each
constructor's own signature (its `&'static str` parameters), not from a
hand-maintained name list.

**The census was re-run at implementation time, and #498's was wrong by five.**
#498 reported the domain as entirely literal apart from `detail.rs`'s own
internal re-forward. There are **six** non-literal hint arguments: that one,
plus five in `ffi/secretary-ffi-uniffi/src/namespace/mod.rs` —
`uuid_from_vec`, `array32_from_vec`, `uuid_from_vec_at`,
`array32_from_vec_at`, `uuid_from_vec_nested_at` — each forwarding its **own**
`&'static str` parameter one hop. `git show 3775ef5:` confirms all five
predate this branch, so it is an inherited undercount, not something this work
introduced. All 54 call sites across the six enclosing functions were read and
pass a literal.

They are recorded as six individually-justified allowlist entries (Section 5),
**not** waved through by widening the rule. A "shape rule" accepting any
function that forwards its own `&'static str` parameter was considered and
rejected: it is not enforcement but a strictly **wider acceptance** — nothing
would check that function's callers, so it reopens #498's attack one frame up,
permanently and unwatched, and it deletes a real checkpoint (a new *direct*
forwarder currently fails CI). It would also need an enclosing-item concept
this offset-and-regex guard has nowhere else — more parsing than anything in
the package, to buy a weaker rule.

Two evasions of the Section 5 entries scan clean today and are recorded in the
allowlist header rather than left implicit: a **caller-side leak**
(`uuid_from_vec(bytes, e.to_string().leak())`, which has no `format!` so E5
also has nothing to say) and a **chain** (a new pass-through wrapper creates no
gated-field construction site, so it produces no finding at all). The six
entries are placeholders that #498's structural option deletes.

**Honest limit:** this watches the door, it does not remove it. Unlike the
newtype, a text rule cannot make a leaked `&'static str` unrepresentable.
#498's structural option — a closed `enum Context`, or for the five uniffi
cases a closed `enum ArgField` in that crate's own `detail.rs` — remains the
only fix that would, and **#498 stays open** recording that.

**Honest limit:** this watches the door, it does not remove it. Unlike the
newtype, a text rule cannot make a leaked `&'static str` unrepresentable.
#498's structural option (a closed `enum Context`) remains the only fix that
would, and #498 stays open recording that.

### 6.2 `roots.py` bookkeeping

`_EXPECTED_ROOT_FLAGS` in `selftest.py` is the #496 tripwire that catches a
rule flag being switched off tree-wide. Any rule-flag change here updates it in
the same commit.

---

## 7. Riders

### 7.1 #503 — the second `[u8; 32]` frame

`array32_from_vec` materializes its `[u8; 32]` in its own frame and returns it
by value; only the caller's copy is zeroized, and the helper is not `#[inline]`.
Release-mode inlining will usually collapse the frames, but CLAUDE.md's
zeroize discipline is explicit about not resting on codegen.

The helper is shared between device secrets (3 sites) and non-secret 32-byte
fingerprints, so it is not changed wholesale. A sibling is added and used at
the three `device_secret` sites only:

```rust
pub(crate) fn array32_from_vec_into(
    bytes: &[u8],
    out: &mut [u8; 32],
    field: &'static str,
) -> Result<(), VaultError>
```

The array then exists in exactly one place — the caller's slot — as a
source-level fact. Sites: `namespace/mod.rs:598`, `namespace/repair.rs:228`,
`namespace/repair.rs:356`. The stale doc comment at `namespace/mod.rs:580-581`
("the transient `[u8; 32]` stack copy … is zeroized on all paths", singular
where there are currently two) is corrected in the same commit.

### 7.2 #504 — ffi-py's two `&str` constructors

`fingerprint_mismatch(expected_hex: &str, got_hex: &str)` and
`uuid_prefixed(uuid_part: &str, detail_part: &str)` are the only sanctioned
constructors in the tree taking a bare `&str`, and are permitted by the pinned
`STR_PARAM_CTOR_EXCEPTIONS` set in `rules/e3.py`.

Once the bridge fields are `Detail`, both take `&Detail` instead. Then:

- `STR_PARAM_CTOR_EXCEPTIONS` **empties**, and `SAFE_PARAM_TYPES` gains
  `&Detail`.
- The PROVENANCE comment in ffi-py's `detail.rs` — which currently traces by
  hand why each argument is trustworthy, and explicitly records that
  `detail_part` is *not* re-verified by E3 — becomes a compile-time fact and
  shrinks accordingly.

#504 also flags that `errors.rs:144` and `:203` each pass two same-typed
arguments that are silently swappable, tested only for exception class. Taking
`&Detail` does **not** fix swappability — both parameters remain the same
type. That is addressed instead by content-asserting unit tests in ffi-py's
`detail.rs`, which run under `cargo test` (unlike the pytest suite, which #501
records as never running in CI).

---

## 8. Non-goals

- **The wrapper crates' own error types.** §4. Their posture is unchanged.
- **#497** (E3 shape 5's unbounded receiver), **#499** (`format!` spellings),
  **#501** (ffi-py pytest in CI), **#502** (`desktop/src-tauri`'s `AppError`),
  **#494** (`cli/`'s `io::Error`), **#495** (splitting `discovery.py`, now 1005
  lines). All remain open and are not touched.
- **#498's structural half.** §6.1.
- **Any change to the FFI surface.** No `FfiVaultError` variant is added,
  removed, or renamed; no field is added or removed; `secretary.udl` must diff
  empty. `Detail` is bridge-internal and never crosses the FFI.
- **Any on-disk format change**, KAT regeneration, or `core/` change.

---

## 9. Testing

TDD per task, in this order:

1. **Guard controls first.** A planted fixture — a bridge error declaring a
   gated field as `String` — must make E2 go RED *before* E1/E2 learn
   `Detail`. A second fixture plants a non-literal hint argument for §6.1.
   Both then go GREEN only via the intended rule change.
2. **Rust move**, compiler-driven. Every missing `.into_string()` is a type
   error, so completeness is mechanical rather than a review judgement.
3. **The feature-gate probe, in-tree.** A test asserting the §5.1 matrix on
   the real workspace: `cargo build --release --workspace` must fail when a
   production call to `Detail::for_test` is planted. This is the control that
   proves the CI gate is not vacuous.
4. **#504's content assertions** — message text and argument order, not
   exception class.

### 9.1 The identity harness

`scripts/dev/payload_guard_identity.sh` captured byte-identical guard
behaviour across #496's package split. **This slice legitimately changes guard
behaviour**, so the harness will not diff empty. The baseline is re-taken and
the diff is reviewed line by line, with every changed line attributed to a
specific rule change in §6. A harness diff containing a line no §6 change
predicts is a defect.

---

## 10. Risks

- **Diff size.** 27 declarations, 11 signatures, 12 + 29 test constructions,
  and the wrapper projection arms. Mostly mechanical and compiler-verified,
  but large enough that a whole-branch review at the end is required, not
  optional — #496's real regression was invisible to every per-task review and
  surfaced only in an old-vs-new differential.
- **The guard diff and the Rust diff can mask each other.** E2 inverting on
  the bridge and the bridge fields changing type are the same fact from two
  directions; if both land in one commit, neither is independently verified.
  They land in separate commits, and the guard commit is proven RED against
  the pre-change tree.
- **`Clone` pressure.** If a projection site needs to read a `Detail` twice,
  the temptation is to derive `Clone`. That is fine — `Clone` cannot mint a
  `Detail` from a `String` — but it should be added only when a call site
  demands it, and noted.
- **Feature unification surprises.** §5.1 was verified on a synthetic
  workspace, not this one. Task 1 re-verifies the matrix against the real
  workspace before anything depends on it.

---

## 11. Definition of done

- All 27 bridge gated fields are `Detail`; `grep` for a gated name declared
  `String` under `ffi/secretary-ffi-bridge/src/` returns **zero**.
- A planted `detail: format!("{x}")` in the bridge is a **compile error**, and
  that is demonstrated, not asserted.
- A planted production `Detail::for_test(…)` fails `cargo build --release
  --workspace`, and CI runs that command.
- `test-support` appears only under `[dev-dependencies]`, enforced by a
  self-tested grep.
- Guard: `--self-test` green with updated counts; real scan OK across four
  roots; `STR_PARAM_CTOR_EXCEPTIONS` empty.
- `git diff main… -- ffi/secretary-ffi-uniffi/src/secretary.udl` is **empty**.
- Full gate sweep green: `cargo test --release --workspace`, clippy
  `-D warnings` (with **and** without `--tests`), rustdoc `-D warnings`, fmt,
  `conformance.py`, the four hygiene guards, desktop `pnpm test` +
  `svelte-check`, Gradle `:kit`.
- CLAUDE.md's residual list updated: the four E3 laundering shapes are closed
  **for the bridge** and explicitly still open **for the wrapper roots** — the
  distinction is the whole point of §4 and must not be flattened.
