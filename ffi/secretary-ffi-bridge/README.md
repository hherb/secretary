# secretary-ffi-bridge

The FFI-friendly facade of `secretary-core`. Single source of code truth
for the FFI surface shared between [`secretary-ffi-py`](../secretary-ffi-py/)
(PyO3 → Python) and [`secretary-ffi-uniffi`](../secretary-ffi-uniffi/)
(uniffi → Swift / Kotlin).

## Why this crate exists

Both binding-flavor crates need the same logic:
- Map `core::UnlockError`'s 7 internal variants to a thinned 3-variant
  FFI surface
- Wrap `core::UnlockedIdentity` in an opaque handle with explicit close
- Forward `open_with_password` calls into core

Without a shared crate, this logic would duplicate in both binding
crates and **drift** as new operations land. With this crate, drift is
**impossible at compile time** — both binding flavors share the same
underlying methods and project them through their respective binding
macros.

## Surface

- `FfiUnlockError` — 3-variant thinned error: `WrongPasswordOrCorrupt`,
  `VaultMismatch`, `CorruptVault { message }`. Expresses user-actionable
  intent rather than mirroring core's internal enum structure.
- `UnlockedIdentity` — opaque handle. Two non-secret accessors
  (`display_name`, `user_uuid`) plus explicit `close()`. The wrapped
  secret material stays Rust-side.
- `open_with_password` — fallible operation: vault unlock by master
  password.

## Design rationale

### Thinned error type

Core's `UnlockError` has 7 reachable-from-`open_with_password` variants,
three wrapping inner enums (`MalformedVaultToml(VaultTomlError)`, etc.).
Mirroring exactly to the foreign side either re-exposes ~15 inner types
per language (huge surface, churns on every `core/` internal refactor)
or collapses inners to strings (anti-pattern; foreign callers parse
strings to understand failure causes).

The thinned 3-variant shape:
- `WrongPasswordOrCorrupt` — "your password is wrong, try again".
  **Deliberately conflates wrong-password and corruption** per
  [`docs/threat-model.md`](../../docs/threat-model.md) §13's anti-oracle
  property; **MUST NOT** be split into separate variants on the foreign
  side.
- `VaultMismatch` — "vault.toml and identity.bundle.enc reference
  different vaults; re-pair from backups".
- `CorruptVault { message }` — collapses {core::CorruptVault, all
  MalformedX, KdfFailure}. The `message` field carries the inner
  Display text for diagnostics; structured pattern-matching on the
  inner cause is intentionally not supported (corruption recovery is
  "restore from backup", not "branch on which file was malformed").

Internal core refactors fold automatically into `CorruptVault {
message: <new Display> }` without rippling foreign-API changes.

### `Mutex<Option<...>>` inside `UnlockedIdentity`

Provides:
- **idempotent close** via `Option::take()` (multiple `close()` calls
  don't panic)
- **thread-safe accessors** (sub-microsecond locks for cloning a
  `String` or copying 16 bytes)
- **use-after-close non-throwing** semantics (`as_ref()` on `None`
  yields default values, matching the B.1 non-throwing accessor
  pattern)
- **prompt zeroize** — `take()` consumes the inner Option, `Drop`
  cascades through `Sensitive<...> ZeroizeOnDrop`

Mutex overhead is acceptable for the opaque-handle pattern; if profile
data ever shows it as a hot path (it won't — accessors are unlock-time
operations, not record-read-time), `RwLock` is a drop-in upgrade.

## Foreign-side projection notes

- The PyO3 projection (`secretary-ffi-py`) renames nothing. Python sees
  `WrongPasswordOrCorrupt`, `VaultMismatch`, `CorruptVault` exception
  classes; `CorruptVault.args[0]` carries the message; `UnlockedIdentity`
  exposes `display_name() / user_uuid() / close()` and the `with` /
  `__enter__` / `__exit__` context-manager protocol.
- The uniffi projection (`secretary-ffi-uniffi`) is forced by uniffi 0.31's
  Kotlin codegen to rename two surface elements:
  - `CorruptVault.message` → `CorruptVault.detail` to avoid collision
    with `Throwable.message` on Kotlin.
  - `UnlockedIdentity::close()` → `UnlockedIdentity::wipe()` because
    uniffi 0.31's Kotlin codegen auto-generates `AutoCloseable.close()`
    on every interface handle (releases the Rust refcount). The bridge
    crate's `close()` stays named `close()`; only the uniffi projection
    renames it. See `secretary-ffi-uniffi/src/lib.rs` for the rationale
    rustdoc.

  Both renames are uniffi-side only — the bridge crate's API is
  unchanged.

## Lints / invariants

- Pure-safe Rust. Workspace's `#![forbid(unsafe_code)]` applies; no
  carve-out (the binding-flavor crates carry their FFI-macro
  `unsafe_code = "deny"` carve-outs locally).
- `cargo clippy --release --workspace -- -D warnings` clean.
- `From<core::unlock::UnlockError>` impl uses explicit match arms with
  no wildcard so future core variants force a compile error instead of
  silently mapping to a default.

## Testing

```bash
cargo test --release -p secretary-ffi-bridge
```

Tests embed both `golden_vault_001/` and `golden_vault_002/` via
`include_bytes!` so no runtime filesystem dependency. Pinned KAT values
(display_name, user_uuid) match those asserted in the foreign-side
smoke runners — KAT drift cannot land silently.

## References

- Design: [docs/superpowers/specs/2026-05-04-ffi-b2-vault-unlock-design.md](../../docs/superpowers/specs/2026-05-04-ffi-b2-vault-unlock-design.md)
- Plan: [docs/superpowers/plans/2026-05-04-ffi-b2-vault-unlock.md](../../docs/superpowers/plans/2026-05-04-ffi-b2-vault-unlock.md)
- Sibling Python crate: [../secretary-ffi-py/README.md](../secretary-ffi-py/README.md)
- Sibling uniffi crate: [../secretary-ffi-uniffi/README.md](../secretary-ffi-uniffi/README.md)
