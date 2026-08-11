# Panic- and error-safe secret slots (#513, #518, #503)

**Status:** approved design, pre-implementation.
**Date:** 2026-08-11. **Base:** `main` @ `9c18794`.
**Branch:** `feature/513-panic-safe-secret-slots`; worktree `.worktrees/513-panic-safe-secret-slots`.

---

## 1. Problem

`#513` says three `device_secret` sites in `ffi/secretary-ffi-uniffi` wipe their
32-byte stack slot with a `.zeroize()` placed *after* the bridge call returns, so
an unwinding panic skips the wipe. It rates the severity low, on the reasoning
that "a panic inside the bridge is not an expected path, the process is typically
about to die, and `panic = "abort"` would make it moot."

**All three clauses of that reasoning are wrong,** and the defect is a different
shape than the issue describes.

### 1.1 The panic is caught, and the process survives

Both FFI boundaries wrap every call in `catch_unwind`:

| binding | site | behaviour |
|---|---|---|
| uniffi 0.32.0 | `uniffi_core/src/ffi/rustcalls.rs:207` | `panic::catch_unwind(callback)` → an unexpected-error return |
| pyo3 0.29.0 | `pyo3/src/impl_/trampoline.rs:301` | `catch_unwind` → `PanicException::from_panic_payload` |

So a panic unwinding through a bridge frame becomes a Python exception or a
Swift/Kotlin internal error, and **the host process keeps running** — with the
un-wiped secret sitting on a stack frame that subsequent calls reuse. The process
is not about to die; it is about to serve the next request over the same stack.

`panic = "abort"` does not apply either: it appears in no `.toml` in the
workspace. Unwinding is the real behaviour in both `dev` and `release`.

### 1.2 The real defect is wider than panics

A secret slot is dirty between its **last write** and its **wipe**. Anything that
leaves the function inside that window skips the wipe. There are three such exit
classes, and `#513` names only the first:

| | exit class | in `#513`? |
|---|---|---|
| **E1** | unwinding panic | yes |
| **E2** | `?` early return | **no** |
| **E3** | explicit `return Err(…)` | **no** |

E2 and E3 are ordinary, expected paths — not failure modes. The census
(§3) found two live instances, filed as **#518**:

**`core/src/unlock/mnemonic.rs::parse`** — `normalized: String` holds the user's
complete 24-word recovery phrase. `nfkd` and `parts` are deliberately wiped
before the branches; `normalized` is wiped only on the happy path:

```rust
let mut normalized = parts.join(" ");
nfkd.zeroize();
parts.iter_mut().for_each(Zeroize::zeroize);

let tokens: Vec<&str> = normalized.split_whitespace().collect();
if tokens.len() != 24 {
    return Err(MnemonicError::WrongLength { got: tokens.len() });   // E3 — not wiped
}
let bip = Bip39Mnemonic::parse_in_normalized(Language::English, &normalized)
    .map_err(|e| /* … */)?;                                          // E2 — not wiped
drop(tokens);
normalized.zeroize();                                                // happy path only
```

`String`'s heap buffer is freed **unwiped** on both. The E2 path is
`UnknownWord` — one mistyped word, the most common way this function fails, and
one a user recovering a vault typically hits several times in a row.

**`core/src/unlock/bundle.rs::from_canonical_cbor`** — `x25519_sk_bytes` /
`ed25519_sk_bytes` are `Option<[u8; N]>` (`Copy`, so the struct construction
copies rather than moves). An explicit block wipes them before the
`NonCanonicalCbor` return, but the `.ok_or(BundleError::MissingField(_))?` chain
above returns first on malformed input, leaving the already-decoded secret keys
on the stack.

### 1.3 Consequence for scope

The defect is **not** "107 call sites use a manual `.zeroize()`". Most are
adjacent statements with no fallible operation between them:

```rust
let mut sk_bytes = sk.to_bytes();
let secret = Sensitive::new(sk_bytes);   // kem.rs:294-296 — cannot panic,
sk_bytes.zeroize();                      // cannot return: no window at all
```

Converting those would churn security-critical crypto code for zero gain. The
work is: find the slots with a real window, and fix those.

---

## 2. Approach — wrap first, don't fill-then-wipe

A secret local becomes **wrapper-typed at the point it is created**, and is
filled and read through the wrapper. `Drop` then wipes it on every exit path —
return, `?`, and unwind — with no statement for control flow to skip.

```rust
// before — correct only if control reaches the last line
let mut secret_arr = [0u8; 32];
array32_from_vec_into(src, &mut secret_arr, "device_secret")?;
let result = bridge::open_with_device_secret(&path, &uuid, &secret_arr);
secret_arr.zeroize();

// after — wiped unconditionally by Drop
let secret = Sensitive::try_build([0u8; 32],
    |slot| array32_from_vec_into(src, slot, "device_secret"))?;
let result = bridge::open_with_device_secret(&path, &uuid, secret.expose());
```

### 2.1 Why the existing wrappers, and not `zeroize::Zeroizing`

`#513` suggests `Zeroizing<[u8; 32]>`. `zeroize 1.8.2` declares:

```rust
#[derive(Debug, Default, Eq, PartialEq)]
pub struct Zeroizing<Z: Zeroize>(Z);
```

It therefore **forwards `Debug`** — a `{:?}` prints the secret bytes — and
supplies a **derived, variable-time `==`**. Both are properties this repo's
wrappers deliberately reject:

| wrapper | `Debug` | `PartialEq` |
|---|---|---|
| `Sensitive<T>` | redacted (`<redacted>`) | **intentionally absent**, with the reasoning written out at `secret.rs:166-190` |
| `SecretBytes` / `SecretString` | redacted (length only) | constant-time via `subtle::ConstantTimeEq` |
| `zeroize::Zeroizing<Z>` | **forwards to `Z`** | **derived, variable-time** |

Adopting `Zeroizing` would add a fourth secret wrapper that regresses on exactly
the two properties `memory-hygiene-audit-internal.md` records as deliberate. All
three FFI crates already depend on `secretary-core`, so its wrappers are
available at every site in question.

### 2.2 A fill-in-place constructor, not a `&mut` accessor

Most windowed sites need **no new API at all**. `SecretBytes::new(password)` and
`SecretString::new(parts.join(" "))` already fit the `Vec<u8>` and `String`
cases; those functions simply were not using the wrappers that exist. New API is
needed only where a **fallible fill writes through a `&mut`** — a handful of
sites in `crypto/kdf.rs` and the FFI device-secret paths.

Two shapes were considered and rejected before settling:

**Rejected — `expose_mut(&mut self) -> &mut T`.** This hands out a mutable borrow
of the secret, permanently, on every live `Sensitive` in the codebase. It enables
the following in safe code, with nothing for a guard to catch:

```rust
let mut plain = [0u8; 32];
std::mem::swap(secret.expose_mut(), &mut plain);   // secret escapes the wrapper
// `secret` drops and wipes the zeros. `plain` is never wiped.
```

That silently defeats `ZeroizeOnDrop` — the same laundering-shape class #474 →
#480 → #486 → #500 were spent closing, reintroduced at the type level.

**Rejected — a `Scratch<T>` newtype.** It does not fix the above: if `Scratch`
also exposes `&mut T`, it has the identical hole. It costs a fourth wrapper
spelling in a codebase that deliberately standardised on three, plus its own
tests and review surface, and buys only the confinement of a capability that
need not exist at all.

**Adopted — `Sensitive::try_build`.** The fill sites do not need a mutable borrow
*available at any time*; they need one *once, at construction*. That is a
constructor, not an accessor:

```rust
/// Build a secret by filling a zeroed slot IN PLACE. The wrapper is live for
/// the whole fill, so an early `?` or an unwinding panic inside `f` drops it
/// and wipes — there is no window (#513).
pub fn try_build<E>(init: T, f: impl FnOnce(&mut T) -> Result<(), E>) -> Result<Self, E> {
    let mut s = Self { inner: init };   // wrapped FIRST
    f(&mut s.inner)?;                   // private field — no public `&mut` escapes
    Ok(s)
}
```

```rust
// ffi/uniffi
let secret = Sensitive::try_build([0u8; 32],
    |slot| array32_from_vec_into(device_secret, slot, "device_secret"))?;

// core/src/crypto/kdf.rs — closes E1 here too, which the deferred-`?`
// restructure alone would not
let kek = Sensitive::try_build([0u8; 32],
    |slot| argon2.hash_password_into(pw, salt, slot)
                 .map_err(|_| KdfError::Argon2ParamsRejected))?;
```

The `&mut` is scoped to one closure written at the call site rather than being a
capability on the type forever. A closure could still `mem::swap`, but that is
one reviewable expression, not an open door for all future code. `Sensitive`'s
"you cannot get a mutable borrow of a live secret" invariant survives — and
stays *statable*, which is what keeps it reviewable. A constructor is also a
safer category of API than an accessor: it runs once, before anyone holds the
value.

Simpler *and* safer than both alternatives, so there is no trade to record here:
one type instead of two, ~6 lines instead of ~30, strictly additive, and no
existing `Sensitive` call site changes.

A non-fallible `build` is deliberately **not** added — no site needs one today.

---

## 3. Census

### 3.1 Method, and its limits

Classification is **per site and manual**. A script can shortlist; it cannot
decide. `Sensitive::new(x)` is syntactically a call but cannot panic, so a naive
"is there a call in the span" matcher reports every site as windowed — the first
pass of this census did exactly that and returned `adjacent=0` across all four
roots, which is an artifact, not a result. Conversely `copy_from_slice` *can*
panic, on a length mismatch that the surrounding code may already have made
unreachable.

So the census output in the implementation must be a **table of judgements, each
with a one-line reason**, not a script's exit code. It is a point-in-time claim
of exactly the kind `scripts/error-payload-hygiene-allowlist.txt` Section 3
holds, and it is recorded as such.

### 3.2 Provisional shortlist

Refined pass (excluding infallible wrapper constructions from the span), to be
confirmed site-by-site during implementation:

| root | windowed | notes |
|---|---|---|
| `core/src` | ~27 | includes both #518 leaks; many are multi-line *fills* the matcher mis-attributes and will reclassify as adjacent |
| `ffi/secretary-ffi-bridge/src` | **0** | all four sites are adjacent `wrap; zeroize;` pairs — **the crate needs no conversion** |
| `ffi/secretary-ffi-py/src` | 33 | every one is a marshalled param or scratch slot live across a full bridge call |
| `ffi/secretary-ffi-uniffi/src` | 3 | the sites `#513` names |

The ffi-py sites carry the most hand-maintained choreography:
`open_with_device_secret` has **six** `.zeroize()` calls across its early
returns, one inside a `map_err` closure, plus a comment recording a live bug that
shape already caused (`len()` read after `zeroize()`, so every wrong-length
secret reported `got 0`).

---

## 4. Components

1. **`Sensitive::try_build`** — [`core/src/crypto/secret.rs`](../../../core/src/crypto/secret.rs). The only new API in the slice, and needed only at the fallible-fill-through-`&mut` sites (§2.2).
2. **Convert the windowed sites** to wrapper-typed locals. Adjacent sites are left exactly as they are.
3. **Fix the two #518 leaks** — `mnemonic::parse` and `bundle::from_canonical_cbor`.
4. **`array32_or_value_error(…) -> PyResult<[u8; 32]>` → write-through** ([`ffi/secretary-ffi-py/src/errors.rs:263`](../../../ffi/secretary-ffi-py/src/errors.rs)), mirroring `array32_from_vec_into` on the uniffi side. Removes the by-value producer, so the unsafe shape is awkward to write rather than merely discouraged — and closes **#503's ffi-py half**, which is still open (`#503` only ever fixed uniffi).
5. **Census table into [`memory-hygiene-audit-internal.md`](../../manual/contributors/memory-hygiene-audit-internal.md)** — per-site window classification with reasons, so the next reviewer inherits the judgement instead of re-deriving it. Its "Stack-residue gaps fixed in this pass" table is the established shape; this extends it with a window column. The memo's header still declares cross-FFI hygiene out of scope while its later "Cross-sub-project discipline" section already covers the bridge; that inconsistency is resolved in the same edit rather than deepened.

---

## 5. Testing

Test-first throughout. Three tiers, with genuinely different strengths — stated
separately because collapsing them would overclaim.

### 5.1 Mechanism — a real test, written first

A `catch_unwind` test proving the wrapper's `Drop` wipes when the stack
**unwinds**, not merely when the function returns. This is the single premise the
entire slice rests on, and **nothing in the tree demonstrates it today**. It is
observable, so it is a real assertion:

```rust
#[test]
fn sensitive_wipes_when_the_stack_unwinds() {
    // a Drop-observing witness proves Drop ran during unwind,
    // then assert the wrapped bytes were wiped, not merely dropped
}
```

### 5.2 API — `try_build`, written before the method exists

Three cases, all observable: the closure's writes reach the wrapped value; a
closure returning `Err` propagates it and yields no `Sensitive`; and — the one
that matters — a closure that **panics** still wipes, asserted with the same
`Drop`-witness technique as §5.1. That last case is what distinguishes
`try_build` from a plain `new` after the fill, so it is the test that must fail
first.

### 5.3 Sites — behaviour-preservation plus path coverage

Each converted site keeps its existing tests green (the conversion is
behaviour-preserving), plus new regression tests that **exercise the specific
paths that were leaking** — `WrongLength`, `UnknownWord`, `MissingField` — so the
converted code is covered by execution rather than by inspection.

### 5.4 Stated limit

**A wipe of a freed heap buffer or a dead stack frame is not observable from
safe Rust.** There is no per-site "assert the bytes are gone" test, and this
slice will not pretend there is.

The per-site argument is instead **type-level**: once a local is wrapper-typed,
`Drop` is unconditional and no control-flow path opts out. That is strictly
stronger than what it replaces, where every site's correctness was an
independent claim about statement ordering — and where, as §1.2 shows, two of
those claims were false. §5.1 pins the mechanism that argument rests on; §5.3
pins that the paths are reached.

---

## 6. Out of scope

- **No new CI guard.** The regression pressure here is structural (§4 item 4)
  and type-level (§5.4), not textual. A matcher for "a call sits in this slot's
  dirty window" would need the per-site judgement §3.1 says a script cannot make.
- **No fourth secret wrapper**, and no `zeroize::Zeroizing` (§2.1).
- **No conversion of the no-window sites**, in `core/src` or the bridge.
- **No on-disk format change, no FFI surface change, no `.udl` change, no KAT
  regeneration.** `secretary.udl` must diff empty against `main`.
- **The codec-boundary residue** the memo already carves out (`ciborium::Value`
  and the canonical-CBOR output buffer holding plaintext between encode and
  AEAD) is untouched. It is a different defect with a different fix.
- **The upstream-managed items** — `hkdf` internal HMAC state, `ml-kem` /
  `ml-dsa` scratch memory — remain deferred exactly as the memo records.

---

## 7. Risks and open questions

- **`try_build`'s closure still receives a `&mut T`** (§2.2), so a closure
  written to `mem::swap` the secret out would defeat the wrapper. The borrow is
  confined to one expression at the call site rather than exposed on the type,
  which makes this reviewable; it does not make it impossible. Every closure
  added under this API is a review point. This is the residual of the rejected
  `expose_mut`, reduced but not eliminated — recorded so a future reviewer sees
  it was a decision, not an oversight.
- **The census is a point-in-time claim** (§3.1). It will drift as `core/`
  changes. Recording it in the memo with per-site reasons is what makes the drift
  detectable by a reader; nothing makes it detectable by CI.
- **Reclassification is expected.** The provisional shortlist over-reports
  `core/src`: several entries are multi-line *fill* expressions the matcher
  mis-attributes to the window. The implementation must reclassify each rather
  than convert the shortlist wholesale — converting a non-windowed crypto site
  is churn on frozen-adjacent code.
- **`#518`'s severity ordering is deliberate.** The `mnemonic::parse` leak is the
  serious one (full recovery phrase, most common failure path). The
  `bundle::from_canonical_cbor` leak is real but lower: reaching that code means
  the bundle already decrypted, so an attacker holding the ciphertext already had
  the KEK.
