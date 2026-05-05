# secretary-ffi-py

PyO3 + maturin bindings for [secretary-core](../../core/). Sub-project B.1 boilerplate — proves the binding pipeline works end-to-end with two trivial round-trip functions (`add`, `version`). Vault crypto exposure comes in B.2.

## Build & test

This crate ships **two** test layers: a Rust unit-test layer that runs as part of the workspace `cargo test`, and a Python pytest layer that exercises the maturin-built wheel through Python's import machinery. They cross-validate each other.

### Rust layer

Runs as part of the normal workspace sweep — no Python / maturin / uv required:

```bash
cargo test --release --workspace
cargo clippy --release --workspace -- -D warnings
```

The three FFI unit tests appear in the workspace total (448 passed + 6 ignored after this crate is fully wired up).

### Python layer

```bash
# One-time setup (after first checkout): uv sync invokes the maturin
# build-backend automatically and installs the editable wheel into
# ffi/secretary-ffi-py/.venv/.
uv sync --directory ffi/secretary-ffi-py

# Run the smoke tests:
uv run --directory ffi/secretary-ffi-py pytest
```

`uv sync` resolves the `[build-system] requires` table (which lists `maturin>=1.9.4,<2.0`), spins up an isolated PEP 517 build env, runs `maturin build`, and installs the resulting wheel as an editable package into the project venv at `ffi/secretary-ffi-py/.venv/`. The compiled `.so` (or `.dylib` on macOS) lives in the venv's `site-packages/` — **not** in the source tree, so there are no rogue binaries to gitignore.

**Cold build** is ~30–60s on M-class hardware (compiles `pyo3` + transitive deps for the first time). **Warm rebuilds** after a `src/lib.rs` edit are ~2–3s.

### Iteration loop

After editing `src/lib.rs`, you need an explicit rebuild — `uv sync` won't notice Rust source changes. Use `maturin develop` (it's in the `[dependency-groups] dev` table so `uv run` finds it):

```bash
# Edit src/lib.rs, then:
uv run --directory ffi/secretary-ffi-py maturin develop --release
uv run --directory ffi/secretary-ffi-py pytest
```

`--release` matches the project's "always --release" posture (the underlying crypto crates are slow in debug; PyO3 + transitive deps benefit from the same posture).

### Cache-stickiness gotcha when iterating on the Python surface

If you rename or add a `#[pyfunction]` and pytest reports `module 'secretary_ffi_py' has no attribute '<new_name>'` — but `cargo test --release --workspace` passes the renamed Rust unit tests — the build is fine; the install is stale.

Cause: uv's editable-install cache (`~/.cache/uv/sdists-v9/editable/*` and `~/.cache/uv/archive-v0/*`) keys on `<package>-<version>`, and `pyproject.toml` declares a static `version = "0.1.0"` (via `dynamic = ["version"]` falling through to `Cargo.toml`'s workspace version). Every rebuild produces wheels with the same name+version, so uv treats them as equivalent and on the next `uv run` / `uv sync` it auto-restores the *first* wheel's `.so` into the venv — silently undoing the freshly-built one.

Quick diagnostic:

```bash
shasum target/maturin/libsecretary_ffi_py.dylib \
       ffi/secretary-ffi-py/.venv/lib/python3.12/site-packages/secretary_ffi_py/*.so
# Hashes should match. If they don't, the install is stale.
```

Nuclear fix that always works (≈ 8s rebuild from clean state):

```bash
rm -rf ffi/secretary-ffi-py/.venv
find ~/.cache/uv -name "*secretary*" -exec rm -rf {} +
uv sync --directory ffi/secretary-ffi-py
```

`uv sync` invokes the maturin build-backend automatically and installs the editable wheel fresh, so a separate `maturin develop` is not needed after this. The trap is **specific to maturin + uv editable installs** — the sibling [secretary-ffi-uniffi](../secretary-ffi-uniffi/) crate has no equivalent (cargo + swiftc only, no Python-style sticky-install layer).

> **Don't substitute `uv cache clean secretary-ffi-py` for the `find ... -name '*secretary*'` line.** They look equivalent but aren't — `uv cache clean <pkg>` removes a subset of cache entries (it'll cheerfully report "Removed 96 files") but leaves stale hardlinks in `~/.cache/uv/archive-v0/<hash>/secretary_ffi_py/` and `~/.cache/uv/wheels-v5/url/<hash>/secretary-ffi-py/`. Those stale entries are exactly what the next `uv run` will hardlink back into the venv. Verify with `find ~/.cache/uv -name "*secretary*" | wc -l` — should be `0` after the find-rm. (Reproduced 2026-05-05 post-PR-26 merge; cost ~30 min.)
>
> **After a long-lived branch's squash-merge, also nuke `target/`.** If the nuclear fix above runs but pytest still reports missing symbols, full-workspace `cargo clean` (not `cargo clean -p secretary-ffi-py`) plus `rm -rf target/wheels/` clears stale build artifacts that cargo's per-crate clean misses when the source hash changed across the merge. Reproduced 2026-05-05 alongside the uv-cache issue; both fixes were needed.

## Scope (B.1)

> **B.3a (this version) adds the recovery-phrase unlock path on top of B.2's password-path surface; see [Vault unlock — recovery path (B.3a)](#vault-unlock--recovery-path-b3a) at the bottom of this README. B.2 (`open_with_password`) is still current; see [Vault unlock (B.2)](#vault-unlock-b2). The sections below are kept as historical context.**


Exposed Python surface:

| Function | Signature | Notes |
|---|---|---|
| `add(a, b)` | `(int, int) -> int` | Rust `u32::wrapping_add`; matches default release-build `+` semantics, which silently wrap on overflow (B.2 will reconsider when `PyResult` becomes first-class). Named `add` rather than `sum` to avoid shadowing Python's builtin. |
| `version()` | `() -> int` | Returns `secretary_core::version::FORMAT_VERSION` (currently 1). |

## What B.1 deliberately does NOT do

- **No vault crypto.** No `unlock`, no `open_vault`, no `Record` types. Comes in B.2.
- **No exception marshalling.** All B.1 functions are infallible. Fallible operations (and `PyResult` ergonomics) come with the first crypto-bearing function in B.2.
- **No CI integration for the Python pytest layer.** Repo has no `.github/workflows/` yet (matches the deferred-CI pattern from `core/tests/python/spec_test_name_freshness.py`); the manual invocation above is the source of truth until CI infrastructure lands.
- **No multi-version Python matrix.** Whatever `uv` resolves under `requires-python = ">=3.11"`.
- **No abi3 / stable ABI.** Build for whatever Python version `uv` resolves; abi3 is a release-engineering decision for a future B.x.
- **No Swift / Kotlin bindings.** Lives in [secretary-ffi-uniffi](../secretary-ffi-uniffi/) (Swift landed in B.1.1; Kotlin smoke runner deferred to B.1.1.1).

## Lint discipline

This crate replaces the inherited workspace `unsafe_code = "forbid"` with crate-local `unsafe_code = "deny"` (PyO3 macros expand to `unsafe` blocks; `forbid` is non-overridable). The lib.rs carries a single crate-level `#![allow(unsafe_code)]` with a comment pointing at the design doc. Workspace `forbid` stays intact for `core/`. The sibling [secretary-ffi-uniffi](../secretary-ffi-uniffi/) crate adopted the same `forbid → deny` carve-out in B.1.1 for its uniffi macro expansions.

Any new `unsafe` block elsewhere in this crate would still trigger `deny` and require an explicit `#[allow]` with justification at that site.

## References

- Design: [docs/superpowers/specs/2026-05-03-ffi-b1-py-bindings-boilerplate-design.md](../../docs/superpowers/specs/2026-05-03-ffi-b1-py-bindings-boilerplate-design.md)
- Plan: [docs/superpowers/plans/2026-05-03-ffi-b1-py-bindings-boilerplate.md](../../docs/superpowers/plans/2026-05-03-ffi-b1-py-bindings-boilerplate.md)
- Project conventions inherited from the wider codebase: FFI crates are the isolated reviewed boundary for `unsafe_code` relaxation; all cargo invocations use `--release` (the underlying crypto crates are slow in debug); Python tooling is `uv` exclusively (never `pip`).

## Vault unlock (B.2)

Three new symbols at the module level: `open_with_password()`,
`UnlockedIdentity` (opaque handle class), and three exception classes
`WrongPasswordOrCorrupt` / `VaultMismatch` / `CorruptVault`.

### Idiomatic usage

```python
import secretary_ffi_py

with open(".../vault.toml", "rb") as f:
    toml = f.read()
with open(".../identity.bundle.enc", "rb") as f:
    bundle = f.read()

with secretary_ffi_py.open_with_password(toml, bundle, b"my password") as identity:
    print(identity.display_name())   # str
    print(identity.user_uuid())      # bytes (16 bytes)
# `with` block exit → identity.close() → Sensitive<...> fields zeroized
```

### Error handling

```python
try:
    identity = secretary_ffi_py.open_with_password(toml, bundle, password)
except secretary_ffi_py.WrongPasswordOrCorrupt:
    # User's password is wrong, OR the vault has been tampered with.
    # These are deliberately indistinguishable per the §13 anti-oracle property.
    ...
except secretary_ffi_py.VaultMismatch:
    # vault.toml and identity.bundle.enc reference different vaults.
    # User should re-pair the two files from backups.
    ...
except secretary_ffi_py.CorruptVault as e:
    # Vault file is malformed beyond recovery. str(e) carries inner diagnostic.
    print(f"Vault corrupt: {e}")
```

### Password-input discipline (caller-zeroize)

Passwords are accepted as **bytes** (not `str`):

```python
# Convenience: bytes literal (not zeroizable)
secretary_ffi_py.open_with_password(toml, bundle, b"my password")

# First-party / disciplined caller: bytearray (zeroizable)
pw = bytearray(b"my password")
try:
    with secretary_ffi_py.open_with_password(toml, bundle, pw) as identity:
        ...
finally:
    for i in range(len(pw)):
        pw[i] = 0
```

**Third-party library consumers:** the bytes-input shape is intentional
to enable caller-side zeroize. Wrap your password handling in a
zeroizing context manager if you handle credentials over the long term.
First-party clients of this crate (the future `secretary-ui-py`,
desktop / web frontends) MUST zero their input buffers after the call;
this is the documented discipline.

### Lifecycle

`UnlockedIdentity` supports the context-manager protocol (`with ... as
id:`) AND has an explicit `close()` method:

```python
identity = secretary_ffi_py.open_with_password(toml, bundle, password)
try:
    print(identity.display_name())
finally:
    identity.close()   # explicit; pin drop time
```

After `close()`, accessors return empty / zero values rather than
raising — this matches the non-throwing pattern from B.1's `add` /
`version`.

### Test coverage

16 pytests (`uv run --directory ffi/secretary-ffi-py pytest`): 3 B.1
smoke (`add`, `add wraps`, `version`) + 7 B.2 (`open_with_password`
success, wrong password, vault mismatch, corrupt vault, idempotent
close, use-after-close, bytearray caller-zeroize discipline) + 6 B.3a
(see the [B.3a section](#vault-unlock--recovery-path-b3a) below).

## Vault unlock — recovery path (B.3a)

Adds `open_with_recovery()` and two new exception classes
(`WrongMnemonicOrCorrupt`, `InvalidMnemonic`) to the module surface.
Mirrors B.2's password path with mnemonic input replacing the password
input — same opaque-handle output (`UnlockedIdentity`), same
context-manager protocol, same caller-zeroize discipline on the
`bytearray` input.

### Idiomatic usage

```python
import secretary_ffi_py

with open(".../vault.toml", "rb") as f:
    toml = f.read()
with open(".../identity.bundle.enc", "rb") as f:
    bundle = f.read()

# Mnemonic input as bytearray for caller-zeroize discipline
phrase = bytearray(b"abandon abandon abandon ... 24 words")
try:
    with secretary_ffi_py.open_with_recovery(toml, bundle, phrase) as identity:
        print(identity.display_name())   # str
        print(identity.user_uuid())      # bytes (16 bytes)
finally:
    for i in range(len(phrase)):
        phrase[i] = 0   # caller-side zeroize — matches B.2 password path
```

### Error handling

```python
try:
    secretary_ffi_py.open_with_recovery(toml, bundle, phrase)
except secretary_ffi_py.WrongMnemonicOrCorrupt:
    # Phrase is wrong, OR the vault has been tampered with.
    # Deliberately indistinguishable per the §13 anti-oracle property
    # (same conflation as WrongPasswordOrCorrupt for the password path).
    ...
except secretary_ffi_py.InvalidMnemonic as e:
    # Pre-decryption validation failure: wrong word count, unknown word,
    # bad checksum, or invalid UTF-8. NOT an oracle. str(e) carries
    # diagnostic text suitable for UI rendering ("expected 24 words,
    # got 3", "word not in BIP-39 English list: xyzzy", etc.).
    print(f"Invalid phrase: {e}")
except secretary_ffi_py.VaultMismatch:
    # vault.toml and identity.bundle.enc reference different vaults.
    ...
except secretary_ffi_py.CorruptVault as e:
    # Vault file is malformed beyond recovery. str(e) carries inner diagnostic.
    print(f"Vault corrupt: {e}")
```

### Mnemonic-input discipline (caller-zeroize)

Same shape as the password input: bytes (`bytes` literal or mutable
`bytearray`), not `str`. The mnemonic is *more secret* than the
password (it derives the recovery KEK; compromising it permanently
unlocks the vault), so first-party clients MUST pass a `bytearray` and
zero it after the call — strings are immutable in Python and cannot be
zeroized.

The bridge crate wraps the input slice in a transient `Vec<u8>` that
is zeroized after the bridge returns; first-party clients should zero
their foreign-side buffer too. Wrap your phrase handling in a
zeroizing context manager if you handle credentials over the long
term.

### Lifecycle

`open_with_recovery` returns the same `UnlockedIdentity` opaque handle
type as `open_with_password`. Both unlock paths produce byte-identical
secret state on success — accessors, `close()`, the context-manager
protocol, and the use-after-close non-throwing semantics all work
identically regardless of which entry point produced the handle.

### Vault creation (B.3b)

```python
import secretary_ffi_py as sec
import time

output = sec.create_vault(
    password=b"my-strong-password",
    display_name="Owner",
    created_at_ms=int(time.time() * 1000),
)

# Read the recovery phrase ONCE. Display to user, then zeroize the buffer.
with output.mnemonic as mn:
    phrase = bytearray(mn.take_phrase())  # one-shot; second call returns None
    show_recovery_phrase_to_user(phrase)
    for i in range(len(phrase)):
        phrase[i] = 0   # caller-side zeroize discipline

# Persist the byte artifacts atomically. Caller's responsibility.
write_atomic(vault_dir / "vault.toml", output.vault_toml_bytes)
write_atomic(vault_dir / "identity.bundle.enc", output.identity_bundle_bytes)

# Use the live identity directly — no second open_with_password call needed.
with output.identity as identity:
    print(identity.display_name())
```

Two new `#[pyclass]` types:

- `secretary_ffi_py.CreateVaultOutput` — the four-field result struct.
  `vault_toml_bytes` / `identity_bundle_bytes` are `bytes` (non-secret).
  `identity` and `mnemonic` are take-once getters that move ownership
  out of the parent struct.
- `secretary_ffi_py.MnemonicOutput` — one-shot opaque handle.
  `take_phrase()` returns `bytes` once, then `None`. `close()` (or
  `__exit__` via `with`) wipes idempotently.

> **`output.identity` and `output.mnemonic` are *destructive* getters.**
> Although they read like ordinary properties, accessing each one
> *moves* ownership out of the parent `CreateVaultOutput`; a second
> read of the same property raises `RuntimeError`. The shape is
> deliberate: holding the live handle inside the parent struct would
> couple the `with`-block lifetime to the parent value in ways that
> are awkward at the FFI boundary, so the take-once pattern sidesteps
> the problem. Practical consequences:
>
> - **Don't introspect** `output.identity` / `output.mnemonic` for
>   debugging (e.g. by calling `repr(output.identity)` and then trying
>   to use it again) — the first read consumes the field.
> - **Idiomatic use** is to bind the property directly to a `with`
>   block: `with output.identity as id: ...`, `with output.mnemonic
>   as mn: ...`. This guarantees a single read at a deterministic
>   site.
> - **Order doesn't matter** between the two: take whichever you need
>   first. The non-secret `vault_toml_bytes` / `identity_bundle_bytes`
>   getters are *not* destructive — they copy out of the underlying
>   `Vec<u8>` each call, so they remain usable for as long as the
>   parent `CreateVaultOutput` is alive.

The bridge instantiates `OsRng` and `Argon2idParams::V1_DEFAULT`
internally; foreign callers cannot tune either. Cost: ~1s per
`create_vault` call for real Argon2id at V1_DEFAULT (256 MiB / 3 iter).

