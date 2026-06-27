# #183 — Re-key signature hardening (UUID newtypes + parameter object)

**Date:** 2026-06-27
**Issue:** [#183](https://github.com/hherb/secretary/issues/183) — Reduce positional-arg count on the `rewrite_block_with_recipients` re-key engine.
**Scope:** `core/src/vault/orchestrators.rs` (engine + `share_block` + `revoke_block_recipient`), a new `core/src/vault/ids.rs`, the 2 bridge call sites that invoke core directly, and the ~21 core test call sites. **No on-disk format / spec / `conformance.py` / KAT-JSON / FFI-surface change.**

## Problem

The shared re-key engine `rewrite_block_with_recipients` takes 14 positional arguments behind `#[allow(clippy::too_many_arguments)]`. Its public callers thread several adjacent same-typed `[u8; 16]` values:

- `revoke_block_recipient` carries **three** `[u8; 16]`s — `block_uuid`, `revoked_recipient_uuid`, `device_uuid` — with the last two **adjacent**.
- `share_block` carries `block_uuid` and `device_uuid`, both `[u8; 16]`.

Because they share a type, a transposition at a call site **compiles silently**. The current sites are guarded by the integration + KAT suites, so this is not a correctness bug today — but a future caller is one easy mistake away from a wrong-block / wrong-recipient re-key that type-checks. This is a security-critical path (BCK rotation + hybrid re-sign), so the project's "enforcement over assumptions" practice warrants a focused, reviewed change.

The existing `Fingerprint = [u8; 16]` is a *type alias*, so it provides no transposition safety and is not a usable precedent.

## Approach (chosen)

**True UUID newtypes through the public API + a parameter object for the engine.** Selected over (a) named param-structs without newtypes — which still type-check when the wrong `[u8;16]` goes into a correctly-named field — and (b) an engine-only struct that leaves the headline public-API transposition risk in `revoke` unaddressed. Only true newtypes make a transposition *fail to compile*, which is the issue's literal goal.

## Design

### 1. `core/src/vault/ids.rs` — scalar-role UUID newtypes

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockUuid([u8; 16]);      // which block is being re-keyed
pub struct RecipientUuid([u8; 16]);  // a recipient role: share target / revoke target / card-to-persist owner
pub struct DeviceUuid([u8; 16]);     // which device performed the write (ticks the manifest clock)
```

Each newtype provides:
- `pub const fn new(bytes: [u8; 16]) -> Self`
- `pub const fn as_bytes(&self) -> &[u8; 16]` and `pub const fn into_inner(self) -> [u8; 16]` (cheap; `Copy`)
- `impl From<[u8; 16]>` and `impl From<X> for [u8; 16]`
- role doc comments explaining *why* the type is distinct (anti-transposition)
- unit tests: byte round-trip, `From`/`Into` symmetry, equality.

**Scalar-only:** the `Vec<[u8; 16]>` recipient lists (`final_recipient_uuids`) and the on-disk `BlockEntry.recipients` type stay raw `[u8; 16]`. Newtyping only the transposition-prone scalar params keeps the change out of the frozen on-disk format and the manifest types.

**Accepted local inconsistency:** these newtypes exist only on the re-key functions; the rest of `core` keeps raw `[u8; 16]`. Expanding the convention codebase-wide is explicitly out of scope for #183.

### 2. Engine parameter object — drop the clippy allow

Collapse the engine's 14 positional args into a parameter object built from cohesive groups:

```rust
struct AuthorSigner<'a> {
    card: &'a ContactCard,
    fingerprint: Fingerprint,
    sk_ed: &'a Ed25519Secret,
    sk_pq: &'a MlDsa65Secret,
}

struct BlockRekey<'a> {
    block_file: &'a block::BlockFile,
    entry_idx: usize,
    signer: AuthorSigner<'a>,
    final_recipient_cards: &'a [&'a ContactCard],
    final_recipient_uuids: Vec<[u8; 16]>,
    card_to_persist: Option<(&'a [u8], RecipientUuid)>,
    device_uuid: DeviceUuid,
    now_ms: u64,
}

fn rewrite_block_with_recipients(
    folder: &Path,
    open: &mut OpenVault,
    req: BlockRekey<'_>,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(), VaultError>
```

→ 4 positional args; `#[allow(clippy::too_many_arguments)]` **removed** from the engine. Field-name construction is inherently transposition-proof. `AuthorSigner` and `BlockRekey` are private to the module (the engine is private). **No behavior change** — `entry_idx` is still caller-supplied (callers already compute it for their own steps), the engine body is unchanged apart from reading fields off `req`.

### 3. Public-API transposition fix

`share_block` and `revoke_block_recipient` keep their flat parameter lists (user-facing API) but their `[u8; 16]` UUID params become newtypes:

```rust
pub fn share_block(folder, open, block_uuid: BlockUuid, author_card, author_sk_ed,
                   author_sk_pq, existing_recipient_cards, new_recipient,
                   device_uuid: DeviceUuid, now_ms, rng) -> Result<(), VaultError>

pub fn revoke_block_recipient(folder, open, block_uuid: BlockUuid, author_card, author_sk_ed,
                              author_sk_pq, existing_recipient_cards,
                              revoked_recipient_uuid: RecipientUuid, device_uuid: DeviceUuid,
                              now_ms, rng) -> Result<(), VaultError>
```

A swap of the adjacent `revoked_recipient_uuid`/`device_uuid` (or any UUID role) now **fails to compile**. These two functions keep their own `#[allow(clippy::too_many_arguments)]`: their arg count is inherent public-API surface, and the issue's complaint about *them* is transposition, which is now fixed. They unwrap the newtypes (`.into_inner()` / `.as_bytes()`) where they pass values into block lookups and the manifest, and build a `BlockRekey` to call the engine.

### 4. Enforcement artifact — `compile_fail` doctest

A `compile_fail` doctest (built-in; zero new deps) on the newtype module proves a transposition is rejected by the compiler — e.g. constructing a call that passes a `DeviceUuid` where a `BlockUuid` is expected does not compile. This is the "enforcement, proven, not assumed" artifact for the security path.

### 5. Call-site updates

- **2 bridge sites** that call core directly wrap raw `[u8; 16]` at the boundary:
  - `ffi/secretary-ffi-bridge/src/share/orchestration.rs` (`core::share_block`)
  - `ffi/secretary-ffi-bridge/src/revoke/orchestration.rs` (`core::revoke_block_recipient`)
  The bridge's own public signatures (what uniffi/pyo3 see) stay `[u8; 16]`/`Vec<u8>` — no `.udl`/FFI-surface change.
- **~21 core test sites** (`share_block.rs`, `revoke_block.rs`, `revoke_kat.rs`, conformance-KAT dispatch helpers, fixture builders) wrap UUIDs at the call boundary.

## Testing strategy

- The compiler is the primary new test: transposition = type error (proven by the `compile_fail` doctest).
- Newtype unit tests in `ids.rs` (round-trip, `From`/`Into`, equality).
- **Behavior-unchanged regression net:** the existing `share_block`, `revoke_block`, `revoke_kat`, and conformance-KAT suites must stay green unchanged — this refactor is byte-for-byte behavior-preserving.
- Full gate: `cargo test --release --workspace`, `cargo clippy --release --workspace --tests -- -D warnings`, `cargo fmt --all -- --check`, and the #189 lean-binding guard.

## Out of scope

- Codebase-wide adoption of the UUID newtypes (only the re-key path here).
- Newtyping the `Vec<[u8;16]>` recipient lists / `BlockEntry.recipients` (would touch on-disk types).
- Any change to `share_block_to` / desktop / uniffi / pyo3 public signatures (they route through the bridge, which keeps `[u8;16]`).
- Removing the `#[allow]` from the public `share_block`/`revoke_block_recipient` (inherent API arg count; not the issue's complaint there).

## Risks

- **None to product behavior** — compile-time-only wrappers; serialized bytes, manifest types, and the FFI surface are untouched.
- Mechanical churn at ~23 call sites; mitigated by the green regression suite proving behavior is preserved.
