# C.1 Sync Detection — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the first slice of Sub-project C — a pure-Rust `sync_once` free function that classifies a vault folder's on-disk state against caller-persisted "highest vector clock seen" into one of `NothingToDo` / `AppliedAutomatically { new_state }` / `ForkDetected` / `RollbackRejected`.

**Architecture:** A new `core::sync` directory module (5 files, all under 500 LOC each). Pure free functions, no mutable engine struct. State is a serializable `SyncState` value the caller persists between calls. Algorithm reuses `core::vault::orchestrators::open_vault` via a new additive `Unlocker::Bundle(&UnlockedIdentity)` variant so `sync_once` does not re-run Argon2.

**Tech Stack:** Rust 1.x stable, `thiserror = "2"` (already in `core/Cargo.toml`), `ciborium = "0.2"` (already in `core/Cargo.toml`) for canonical CBOR via `core::vault::canonical`, `proptest` for property tests. No new crate dependencies.

**Spec reference:** [docs/superpowers/specs/2026-05-17-c1-sync-detection-design.md](../specs/2026-05-17-c1-sync-detection-design.md)

**Branch:** `feature/c1-sync-detection` (this worktree at `.worktrees/c1-sync-detection`).

**Working directory discipline reminder:** Per the project's CLAUDE.md, before every path-sensitive command run `pwd && git branch --show-current && git worktree list`. This plan assumes the implementer is `cd`-ed into `.worktrees/c1-sync-detection`.

---

## Phase A — Module scaffolding and data types

### Task 1: Scaffold the `core/src/sync/` module tree

**Files:**
- Create: `core/src/sync/mod.rs`
- Create: `core/src/sync/error.rs`
- Create: `core/src/sync/state.rs`
- Create: `core/src/sync/outcome.rs`
- Create: `core/src/sync/once.rs`
- Modify: `core/src/lib.rs` (add `pub mod sync;`)

- [ ] **Step 1: Create the module directory and empty files**

```bash
mkdir -p core/src/sync
touch core/src/sync/mod.rs core/src/sync/error.rs core/src/sync/state.rs core/src/sync/outcome.rs core/src/sync/once.rs
```

- [ ] **Step 2: Write `core/src/sync/mod.rs`**

```rust
//! Sync orchestration — phase C.1 (detection only).
//!
//! This module reconciles one local vault folder against caller-persisted
//! "highest vector clock seen" state. It implements the §10 rollback
//! resistance algorithm from `docs/crypto-design.md` as a pure-function
//! dispatch over `clock_relation` outcomes:
//!
//! - `NothingToDo` — disk has nothing new since last sync.
//! - `AppliedAutomatically { new_state }` — disk strictly dominates local
//!   state; caller persists `new_state` and proceeds.
//! - `ForkDetected` — disk and local state are concurrent. Per
//!   `docs/threat-model.md` §4 limit 3, detection is sufficient at this
//!   layer; C.1.1 will extend this branch with automatic merge.
//! - `RollbackRejected` — disk is strictly older than local state per §10.
//!
//! Automatic merge of concurrent states, veto-on-tombstone, and conflict-
//! copy file ingestion are scoped to a separate C.1.1 slice with its own
//! design.

pub mod error;
pub mod once;
pub mod outcome;
pub mod state;

pub use error::SyncError;
pub use once::sync_once;
pub use outcome::{RollbackEvidence, SyncOutcome};
pub use state::SyncState;
```

- [ ] **Step 3: Add temporary minimal stubs in each new file so the crate compiles**

`core/src/sync/error.rs`:
```rust
//! Typed errors surfaced by `sync_once` and `SyncState` codec.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("placeholder")]
    Placeholder,
}
```

`core/src/sync/state.rs`:
```rust
//! `SyncState` — per-vault sync orchestration state, caller-persisted.

pub struct SyncState;
```

`core/src/sync/outcome.rs`:
```rust
//! `SyncOutcome` — typed result of `sync_once`.

pub struct RollbackEvidence;

pub enum SyncOutcome {
    Placeholder,
}
```

`core/src/sync/once.rs`:
```rust
//! `sync_once` — pure-function reconcile of one vault folder against
//! caller-persisted state.
```

- [ ] **Step 4: Register the module in `core/src/lib.rs`**

Read the file first to find where existing `pub mod` declarations live:

```bash
grep -n "^pub mod" core/src/lib.rs
```

Insert `pub mod sync;` in alphabetical order (between `pub mod identity;` / `pub mod unlock;` and `pub mod vault;` — verify exact placement after reading).

- [ ] **Step 5: Verify the crate still compiles**

```bash
cargo check --release --workspace
```

Expected: clean compile, no warnings, no errors.

- [ ] **Step 6: Commit**

```bash
git add core/src/sync/ core/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(c1): scaffold core::sync module skeleton

Empty mod.rs + four stub submodules (error, state, outcome, once)
registered in lib.rs. Subsequent commits fill in the types and
algorithm per docs/superpowers/specs/2026-05-17-c1-sync-detection-design.md.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: `SyncError` enum

**Files:**
- Modify: `core/src/sync/error.rs`

- [ ] **Step 1: Write the failing test (inline in the module)**

Replace the placeholder body of `core/src/sync/error.rs` with the test:

```rust
//! Typed errors surfaced by `sync_once` and `SyncState` codec.

use thiserror::Error;

use crate::vault::VaultError;

#[derive(Debug, Error)]
pub enum SyncError {
    #[error(
        "vault_uuid in SyncState ({state_vault_uuid:?}) does not match \
         vault.toml ({folder_vault_uuid:?})"
    )]
    VaultUuidMismatch {
        state_vault_uuid: [u8; 16],
        folder_vault_uuid: [u8; 16],
    },

    #[error("SyncState CBOR decode failed: {detail}")]
    StateDecodeFailed { detail: String },

    #[error("SyncState CBOR encode failed: {detail}")]
    StateEncodeFailed { detail: String },

    #[error(transparent)]
    Vault(#[from] VaultError),

    #[error("I/O failure: {context}")]
    Io {
        context: &'static str,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid argument: {detail}")]
    InvalidArgument { detail: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_uuid_mismatch_display_is_stable() {
        let err = SyncError::VaultUuidMismatch {
            state_vault_uuid: [1u8; 16],
            folder_vault_uuid: [2u8; 16],
        };
        let s = format!("{err}");
        assert!(s.contains("vault_uuid in SyncState"));
        assert!(s.contains("does not match vault.toml"));
    }

    #[test]
    fn state_decode_failed_display_is_stable() {
        let err = SyncError::StateDecodeFailed {
            detail: "trailing bytes".into(),
        };
        assert_eq!(format!("{err}"), "SyncState CBOR decode failed: trailing bytes");
    }

    #[test]
    fn state_encode_failed_display_is_stable() {
        let err = SyncError::StateEncodeFailed {
            detail: "encoder primitive error".into(),
        };
        assert_eq!(
            format!("{err}"),
            "SyncState CBOR encode failed: encoder primitive error"
        );
    }

    #[test]
    fn io_display_is_stable_and_carries_context() {
        let err = SyncError::Io {
            context: "failed to read vault.toml",
            source: std::io::Error::from(std::io::ErrorKind::NotFound),
        };
        let s = format!("{err}");
        assert!(s.contains("I/O failure"));
        assert!(s.contains("failed to read vault.toml"));
    }

    #[test]
    fn invalid_argument_display_is_stable() {
        let err = SyncError::InvalidArgument {
            detail: "duplicate device_uuid".into(),
        };
        assert_eq!(format!("{err}"), "invalid argument: duplicate device_uuid");
    }

    #[test]
    fn vault_error_forwards_via_from() {
        // VaultError variants are tested in core::vault; here we only
        // certify the From impl exists and folds into the Vault arm.
        // Pick a small variant that doesn't need fixture setup —
        // OwnerUuidMismatch is a plain two-field struct variant.
        let inner: VaultError = VaultError::OwnerUuidMismatch {
            vault: [0u8; 16],
            found: [1u8; 16],
        };
        let outer: SyncError = inner.into();
        assert!(matches!(outer, SyncError::Vault(_)));
    }
}
```

- [ ] **Step 2: Run tests to verify the new error tests pass**

```bash
cargo test --release -p secretary-core --lib sync::error -- --nocapture
```

Expected: 6 tests, all PASS.

- [ ] **Step 3: Commit**

```bash
git add core/src/sync/error.rs
git commit -m "$(cat <<'EOF'
feat(c1): SyncError enum with 6 typed variants

Anti-conflation discipline: every variant maps to one observable
cause. VaultError forwarded via #[from] preserves the underlying
typed surface at the umbrella level. Display strings pinned by
6 unit tests.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: `SyncState` struct + sorted/deduped invariant constructor

**Files:**
- Modify: `core/src/sync/state.rs`

- [ ] **Step 1: Write the failing tests for the constructor invariants**

Replace `core/src/sync/state.rs` with:

```rust
//! `SyncState` — per-vault sync orchestration state, caller-persisted.
//!
//! Holds the `vault_uuid` (binding the state to one specific vault) and
//! `highest_vector_clock_seen` (per `docs/crypto-design.md` §10).
//!
//! Invariant on `highest_vector_clock_seen`: entries sorted ascending by
//! `device_uuid` and no duplicate `device_uuid`. The constructor
//! `SyncState::new` and the CBOR decoder enforce this in both
//! directions (per the design spec — both paths validate so a
//! programmer-error path produces a typed error rather than corrupting
//! merge dispatch).

use crate::sync::error::SyncError;
use crate::vault::block::VectorClockEntry;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncState {
    pub vault_uuid: [u8; 16],
    pub highest_vector_clock_seen: Vec<VectorClockEntry>,
}

impl SyncState {
    /// Fresh state for a vault we've never synced on this device.
    /// First `sync_once` call will produce `AppliedAutomatically` for
    /// any non-empty disk clock (the empty vector clock is the lattice
    /// bottom).
    pub fn empty(vault_uuid: [u8; 16]) -> Self {
        Self {
            vault_uuid,
            highest_vector_clock_seen: Vec::new(),
        }
    }

    /// Construct with explicit clock entries; validates the sorted +
    /// deduped invariant.
    pub fn new(
        vault_uuid: [u8; 16],
        highest_vector_clock_seen: Vec<VectorClockEntry>,
    ) -> Result<Self, SyncError> {
        validate_clock_canonical(&highest_vector_clock_seen)?;
        Ok(Self {
            vault_uuid,
            highest_vector_clock_seen,
        })
    }
}

/// Shared validator used by `SyncState::new` and the CBOR decoder.
/// Returns `InvalidArgument` if entries are unsorted or duplicated.
pub(crate) fn validate_clock_canonical(
    entries: &[VectorClockEntry],
) -> Result<(), SyncError> {
    for pair in entries.windows(2) {
        match pair[0].device_uuid.cmp(&pair[1].device_uuid) {
            std::cmp::Ordering::Less => continue,
            std::cmp::Ordering::Equal => {
                return Err(SyncError::InvalidArgument {
                    detail: "duplicate device_uuid in highest_vector_clock_seen".into(),
                });
            }
            std::cmp::Ordering::Greater => {
                return Err(SyncError::InvalidArgument {
                    detail:
                        "highest_vector_clock_seen entries not sorted ascending by device_uuid"
                            .into(),
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(b: u8, counter: u64) -> VectorClockEntry {
        VectorClockEntry {
            device_uuid: [b; 16],
            counter,
        }
    }

    #[test]
    fn empty_constructor_produces_empty_clock() {
        let s = SyncState::empty([0u8; 16]);
        assert_eq!(s.vault_uuid, [0u8; 16]);
        assert!(s.highest_vector_clock_seen.is_empty());
    }

    #[test]
    fn new_accepts_sorted_unique_entries() {
        let s = SyncState::new([7u8; 16], vec![entry(1, 5), entry(2, 3), entry(3, 9)])
            .expect("sorted unique entries must be accepted");
        assert_eq!(s.highest_vector_clock_seen.len(), 3);
    }

    #[test]
    fn new_accepts_empty_clock() {
        let s = SyncState::new([7u8; 16], vec![]).expect("empty clock must be accepted");
        assert!(s.highest_vector_clock_seen.is_empty());
    }

    #[test]
    fn new_rejects_unsorted_entries() {
        let err = SyncState::new([0u8; 16], vec![entry(2, 1), entry(1, 1)]).unwrap_err();
        assert!(matches!(err, SyncError::InvalidArgument { .. }));
        assert!(format!("{err}").contains("not sorted ascending"));
    }

    #[test]
    fn new_rejects_duplicate_device_uuid() {
        let err = SyncState::new([0u8; 16], vec![entry(1, 1), entry(1, 2)]).unwrap_err();
        assert!(matches!(err, SyncError::InvalidArgument { .. }));
        assert!(format!("{err}").contains("duplicate device_uuid"));
    }
}
```

- [ ] **Step 2: Run the new tests**

```bash
cargo test --release -p secretary-core --lib sync::state -- --nocapture
```

Expected: 5 tests, all PASS.

- [ ] **Step 3: Commit**

```bash
git add core/src/sync/state.rs
git commit -m "$(cat <<'EOF'
feat(c1): SyncState type with sorted/deduped clock invariant

Constructor validates entries sorted ascending by device_uuid with
no duplicates. The shared validate_clock_canonical helper is reused
by the CBOR decoder in the next commit so both entry paths produce
typed InvalidArgument errors rather than corrupting downstream merge
dispatch.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: `SyncState` canonical CBOR round-trip

**Files:**
- Modify: `core/src/sync/state.rs`

- [ ] **Step 1: Identify the canonical-CBOR helpers already in the project**

```bash
grep -nE "pub fn encode_canonical_map|pub fn canonical_sort_entries" core/src/vault/canonical.rs
```

Use the same helpers (`encode_canonical_map`, `canonical_sort_entries`) the rest of the codebase uses; do NOT roll a parallel CBOR layer.

- [ ] **Step 2: Write the failing tests (round-trip, malformed-bytes, unsorted-on-decode, duplicate-on-decode)**

Append to `core/src/sync/state.rs` after the existing test module:

```rust
// --- CBOR codec ---

const SYNC_STATE_KEY_VAULT_UUID: &str = "vault_uuid";
const SYNC_STATE_KEY_HIGHEST_VECTOR_CLOCK_SEEN: &str = "highest_vector_clock_seen";
const VECTOR_CLOCK_ENTRY_KEY_DEVICE_UUID: &str = "device_uuid";
const VECTOR_CLOCK_ENTRY_KEY_COUNTER: &str = "counter";

impl SyncState {
    /// Canonical-CBOR encoding suitable for OS-keystore persistence.
    /// Map keys sorted lex; bytes for `vault_uuid` and entry
    /// `device_uuid`; integer for entry `counter`. Forward-compat: a
    /// future C.1.x adding new keys uses the same `unknown` opaque
    /// round-trip pattern as `Record`/`Manifest`.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, SyncError> {
        use ciborium::value::Value;

        let entries = self
            .highest_vector_clock_seen
            .iter()
            .map(|e| {
                Value::Map(vec![
                    (
                        Value::Text(VECTOR_CLOCK_ENTRY_KEY_DEVICE_UUID.into()),
                        Value::Bytes(e.device_uuid.to_vec()),
                    ),
                    (
                        Value::Text(VECTOR_CLOCK_ENTRY_KEY_COUNTER.into()),
                        Value::Integer(e.counter.into()),
                    ),
                ])
            })
            .collect::<Vec<_>>();

        let root = Value::Map(vec![
            (
                Value::Text(SYNC_STATE_KEY_VAULT_UUID.into()),
                Value::Bytes(self.vault_uuid.to_vec()),
            ),
            (
                Value::Text(SYNC_STATE_KEY_HIGHEST_VECTOR_CLOCK_SEEN.into()),
                Value::Array(entries),
            ),
        ]);

        let mut out = Vec::new();
        ciborium::ser::into_writer(&root, &mut out).map_err(|e| SyncError::StateEncodeFailed {
            detail: format!("{e}"),
        })?;
        Ok(out)
    }

    /// Decode canonical CBOR. Validates the sorted/deduped invariant
    /// on `highest_vector_clock_seen` symmetrically with `SyncState::new`.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SyncError> {
        use ciborium::value::Value;

        let value: Value = ciborium::de::from_reader(bytes).map_err(|e| {
            SyncError::StateDecodeFailed {
                detail: format!("CBOR parse: {e}"),
            }
        })?;
        let map = match value {
            Value::Map(m) => m,
            _ => {
                return Err(SyncError::StateDecodeFailed {
                    detail: "root value is not a CBOR map".into(),
                })
            }
        };

        let mut vault_uuid: Option<[u8; 16]> = None;
        let mut entries: Option<Vec<VectorClockEntry>> = None;

        for (k, v) in map {
            let key = match k {
                Value::Text(t) => t,
                _ => continue, // forward-compat: ignore non-text keys
            };
            match key.as_str() {
                SYNC_STATE_KEY_VAULT_UUID => {
                    let b = match v {
                        Value::Bytes(b) => b,
                        _ => {
                            return Err(SyncError::StateDecodeFailed {
                                detail: "vault_uuid is not a CBOR byte string".into(),
                            })
                        }
                    };
                    if b.len() != 16 {
                        return Err(SyncError::StateDecodeFailed {
                            detail: format!("vault_uuid must be 16 bytes, got {}", b.len()),
                        });
                    }
                    let mut arr = [0u8; 16];
                    arr.copy_from_slice(&b);
                    vault_uuid = Some(arr);
                }
                SYNC_STATE_KEY_HIGHEST_VECTOR_CLOCK_SEEN => {
                    let arr = match v {
                        Value::Array(a) => a,
                        _ => {
                            return Err(SyncError::StateDecodeFailed {
                                detail: "highest_vector_clock_seen is not a CBOR array".into(),
                            })
                        }
                    };
                    let mut out = Vec::with_capacity(arr.len());
                    for entry_val in arr {
                        out.push(decode_vector_clock_entry(entry_val)?);
                    }
                    entries = Some(out);
                }
                _ => continue, // forward-compat: ignore unknown keys
            }
        }

        let vault_uuid = vault_uuid.ok_or_else(|| SyncError::StateDecodeFailed {
            detail: "missing vault_uuid key".into(),
        })?;
        let entries = entries.unwrap_or_default();
        validate_clock_canonical(&entries)?;
        Ok(Self {
            vault_uuid,
            highest_vector_clock_seen: entries,
        })
    }
}

fn decode_vector_clock_entry(
    value: ciborium::value::Value,
) -> Result<VectorClockEntry, SyncError> {
    use ciborium::value::Value;

    let map = match value {
        Value::Map(m) => m,
        _ => {
            return Err(SyncError::StateDecodeFailed {
                detail: "vector clock entry is not a CBOR map".into(),
            })
        }
    };

    let mut device_uuid: Option<[u8; 16]> = None;
    let mut counter: Option<u64> = None;

    for (k, v) in map {
        let key = match k {
            Value::Text(t) => t,
            _ => continue,
        };
        match key.as_str() {
            VECTOR_CLOCK_ENTRY_KEY_DEVICE_UUID => {
                let b = match v {
                    Value::Bytes(b) => b,
                    _ => {
                        return Err(SyncError::StateDecodeFailed {
                            detail: "device_uuid is not a CBOR byte string".into(),
                        })
                    }
                };
                if b.len() != 16 {
                    return Err(SyncError::StateDecodeFailed {
                        detail: format!("device_uuid must be 16 bytes, got {}", b.len()),
                    });
                }
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&b);
                device_uuid = Some(arr);
            }
            VECTOR_CLOCK_ENTRY_KEY_COUNTER => {
                let n: u64 = match v {
                    Value::Integer(i) => i.try_into().map_err(|_| SyncError::StateDecodeFailed {
                        detail: "counter does not fit in u64".into(),
                    })?,
                    _ => {
                        return Err(SyncError::StateDecodeFailed {
                            detail: "counter is not a CBOR integer".into(),
                        })
                    }
                };
                counter = Some(n);
            }
            _ => continue,
        }
    }

    Ok(VectorClockEntry {
        device_uuid: device_uuid.ok_or_else(|| SyncError::StateDecodeFailed {
            detail: "vector clock entry missing device_uuid".into(),
        })?,
        counter: counter.ok_or_else(|| SyncError::StateDecodeFailed {
            detail: "vector clock entry missing counter".into(),
        })?,
    })
}

#[cfg(test)]
mod cbor_tests {
    use super::*;

    fn entry(b: u8, counter: u64) -> VectorClockEntry {
        VectorClockEntry {
            device_uuid: [b; 16],
            counter,
        }
    }

    #[test]
    fn empty_state_round_trip() {
        let original = SyncState::empty([0xABu8; 16]);
        let bytes = original.to_canonical_cbor().unwrap();
        let decoded = SyncState::from_canonical_cbor(&bytes).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn three_entry_state_round_trip() {
        let original = SyncState::new(
            [0x42u8; 16],
            vec![entry(1, 5), entry(2, 17), entry(0xAA, 1)],
        )
        .unwrap();
        let bytes = original.to_canonical_cbor().unwrap();
        let decoded = SyncState::from_canonical_cbor(&bytes).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn malformed_cbor_rejects_with_typed_error() {
        let bytes = b"not actually cbor at all";
        let err = SyncState::from_canonical_cbor(bytes).unwrap_err();
        assert!(matches!(err, SyncError::StateDecodeFailed { .. }));
    }

    #[test]
    fn decoder_rejects_unsorted_clock_entries() {
        // Hand-craft a CBOR payload with entries in DESCENDING order.
        // The encoder always emits canonical sorted order, so we have
        // to bypass it. Construct via ciborium directly.
        use ciborium::value::Value;
        let bad_entries = vec![
            Value::Map(vec![
                (
                    Value::Text(VECTOR_CLOCK_ENTRY_KEY_DEVICE_UUID.into()),
                    Value::Bytes(vec![0x02u8; 16]),
                ),
                (
                    Value::Text(VECTOR_CLOCK_ENTRY_KEY_COUNTER.into()),
                    Value::Integer(1i64.into()),
                ),
            ]),
            Value::Map(vec![
                (
                    Value::Text(VECTOR_CLOCK_ENTRY_KEY_DEVICE_UUID.into()),
                    Value::Bytes(vec![0x01u8; 16]),
                ),
                (
                    Value::Text(VECTOR_CLOCK_ENTRY_KEY_COUNTER.into()),
                    Value::Integer(1i64.into()),
                ),
            ]),
        ];
        let root = Value::Map(vec![
            (
                Value::Text(SYNC_STATE_KEY_VAULT_UUID.into()),
                Value::Bytes(vec![0u8; 16]),
            ),
            (
                Value::Text(SYNC_STATE_KEY_HIGHEST_VECTOR_CLOCK_SEEN.into()),
                Value::Array(bad_entries),
            ),
        ]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&root, &mut bytes).unwrap();

        let err = SyncState::from_canonical_cbor(&bytes).unwrap_err();
        assert!(matches!(err, SyncError::InvalidArgument { .. }));
        assert!(format!("{err}").contains("not sorted ascending"));
    }

    #[test]
    fn decoder_rejects_duplicate_device_uuid() {
        use ciborium::value::Value;
        let dup_entries = vec![
            Value::Map(vec![
                (
                    Value::Text(VECTOR_CLOCK_ENTRY_KEY_DEVICE_UUID.into()),
                    Value::Bytes(vec![0xCC; 16]),
                ),
                (
                    Value::Text(VECTOR_CLOCK_ENTRY_KEY_COUNTER.into()),
                    Value::Integer(1i64.into()),
                ),
            ]),
            Value::Map(vec![
                (
                    Value::Text(VECTOR_CLOCK_ENTRY_KEY_DEVICE_UUID.into()),
                    Value::Bytes(vec![0xCC; 16]),
                ),
                (
                    Value::Text(VECTOR_CLOCK_ENTRY_KEY_COUNTER.into()),
                    Value::Integer(2i64.into()),
                ),
            ]),
        ];
        let root = Value::Map(vec![
            (
                Value::Text(SYNC_STATE_KEY_VAULT_UUID.into()),
                Value::Bytes(vec![0u8; 16]),
            ),
            (
                Value::Text(SYNC_STATE_KEY_HIGHEST_VECTOR_CLOCK_SEEN.into()),
                Value::Array(dup_entries),
            ),
        ]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&root, &mut bytes).unwrap();

        let err = SyncState::from_canonical_cbor(&bytes).unwrap_err();
        assert!(matches!(err, SyncError::InvalidArgument { .. }));
        assert!(format!("{err}").contains("duplicate device_uuid"));
    }

    #[test]
    fn decoder_rejects_missing_vault_uuid() {
        use ciborium::value::Value;
        let root = Value::Map(vec![(
            Value::Text(SYNC_STATE_KEY_HIGHEST_VECTOR_CLOCK_SEEN.into()),
            Value::Array(vec![]),
        )]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&root, &mut bytes).unwrap();

        let err = SyncState::from_canonical_cbor(&bytes).unwrap_err();
        assert!(matches!(err, SyncError::StateDecodeFailed { .. }));
        assert!(format!("{err}").contains("missing vault_uuid"));
    }

    #[test]
    fn decoder_ignores_unknown_keys_for_forward_compat() {
        use ciborium::value::Value;
        let root = Value::Map(vec![
            (
                Value::Text(SYNC_STATE_KEY_VAULT_UUID.into()),
                Value::Bytes(vec![0x11u8; 16]),
            ),
            (
                Value::Text(SYNC_STATE_KEY_HIGHEST_VECTOR_CLOCK_SEEN.into()),
                Value::Array(vec![]),
            ),
            (
                Value::Text("future_c1_1_field".into()),
                Value::Integer(42i64.into()),
            ),
        ]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&root, &mut bytes).unwrap();

        let decoded = SyncState::from_canonical_cbor(&bytes).unwrap();
        assert_eq!(decoded.vault_uuid, [0x11u8; 16]);
        assert!(decoded.highest_vector_clock_seen.is_empty());
    }
}
```

- [ ] **Step 3: Run the new CBOR tests**

```bash
cargo test --release -p secretary-core --lib sync::state::cbor_tests -- --nocapture
```

Expected: 7 tests, all PASS.

- [ ] **Step 4: Commit**

```bash
git add core/src/sync/state.rs
git commit -m "$(cat <<'EOF'
feat(c1): SyncState canonical CBOR encode/decode

Two-field map, ciborium-backed, named-string keys. Forward-compat
via unknown-key skip (a future C.1.x can add fields without breaking
C.1.0 readers). Decoder symmetrically validates the sorted/deduped
clock invariant — a manually-crafted unsorted or duplicate-key
payload produces InvalidArgument, matching the constructor path.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: `SyncOutcome` and `RollbackEvidence` types

**Files:**
- Modify: `core/src/sync/outcome.rs`

- [ ] **Step 1: Write the failing tests**

Replace `core/src/sync/outcome.rs` with:

```rust
//! Typed result of `sync_once` — one of four disjoint outcomes.

use crate::sync::state::SyncState;
use crate::vault::block::VectorClockEntry;

/// Evidence accompanying a `RollbackRejected` outcome. Both the disk
/// state and the local-remembered state are surfaced so a caller's UX
/// (e.g., "I am restoring from backup, accept anyway") can show the
/// user what would be overwritten.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackEvidence {
    pub disk_vector_clock: Vec<VectorClockEntry>,
    pub local_highest_seen: Vec<VectorClockEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncOutcome {
    /// Disk has nothing new since the last sync. No state mutation.
    NothingToDo,

    /// Disk strictly dominates local highest_seen. The disk state is
    /// the new canonical truth. Caller persists `new_state` to OS
    /// keystore before the next call.
    AppliedAutomatically { new_state: SyncState },

    /// Disk and local highest_seen are concurrent (incomparable). The
    /// vault has forked across devices. Per `docs/threat-model.md` §4
    /// limit 3, detection is sufficient at this layer; C.1.1 extends.
    ForkDetected {
        disk_vector_clock: Vec<VectorClockEntry>,
        local_highest_seen: Vec<VectorClockEntry>,
    },

    /// Disk vector clock is strictly dominated by local highest_seen.
    /// Per `docs/crypto-design.md` §10 — rollback rejected.
    RollbackRejected(RollbackEvidence),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_to_do_eq() {
        assert_eq!(SyncOutcome::NothingToDo, SyncOutcome::NothingToDo);
    }

    #[test]
    fn applied_automatically_eq_when_new_state_matches() {
        let s = SyncState::empty([1u8; 16]);
        assert_eq!(
            SyncOutcome::AppliedAutomatically { new_state: s.clone() },
            SyncOutcome::AppliedAutomatically { new_state: s },
        );
    }

    #[test]
    fn rollback_evidence_carries_both_clocks() {
        let entry = VectorClockEntry {
            device_uuid: [1u8; 16],
            counter: 5,
        };
        let evidence = RollbackEvidence {
            disk_vector_clock: vec![entry.clone()],
            local_highest_seen: vec![entry.clone()],
        };
        assert_eq!(evidence.disk_vector_clock.len(), 1);
        assert_eq!(evidence.local_highest_seen.len(), 1);
    }
}
```

- [ ] **Step 2: Run the tests**

```bash
cargo test --release -p secretary-core --lib sync::outcome -- --nocapture
```

Expected: 3 tests, all PASS.

- [ ] **Step 3: Commit**

```bash
git add core/src/sync/outcome.rs
git commit -m "$(cat <<'EOF'
feat(c1): SyncOutcome and RollbackEvidence types

Four-variant outcome enum matching the §10 algorithm's terminal
states: NothingToDo, AppliedAutomatically { new_state },
ForkDetected, RollbackRejected. RollbackEvidence surfaces both
clocks so a caller's "restoring from backup" UX can render the
divergence.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Phase B — Extend `Unlocker` with the `Bundle` variant

### Task 6: Add `Unlocker::Bundle(&UnlockedIdentity)` + `open_vault` match arm

**Files:**
- Modify: `core/src/unlock/mod.rs` (derive `Clone` on `UnlockedIdentity` if not already)
- Modify: `core/src/vault/orchestrators.rs` (extend `Unlocker` enum + `open_vault` match arm)

- [ ] **Step 1: Verify `UnlockedIdentity` `Clone` status**

```bash
grep -nB 3 "pub struct UnlockedIdentity" core/src/unlock/mod.rs
```

If `#[derive(Clone)]` is not on `UnlockedIdentity`, the inner `IdentityBundle` and `Sensitive<[u8; 32]>` types both `derive(Clone)` already (verified during plan drafting), so add `Clone` to the derive list. Otherwise skip.

- [ ] **Step 2: Write the failing integration test**

Append to `core/tests/open_vault.rs` (or create a new sibling test file `core/tests/open_vault_bundle.rs` if a test for the bundle path doesn't fit the existing file's organisation — check the file's structure first):

```rust
use secretary_core::unlock::open_with_password;
use secretary_core::vault::orchestrators::{open_vault, OpenVault, Unlocker};

#[test]
fn open_vault_with_bundle_unlocker_yields_same_handle_as_password() {
    // Use the existing golden_vault_001 fixture's password + folder.
    let folder = std::path::Path::new("tests/data/golden_vault_001");
    let password_bytes = std::fs::read(folder.join("password.bytes"))
        .expect("golden_vault_001 must include password.bytes for tests");
    let secret_password = secretary_core::crypto::secret::SecretBytes::from(password_bytes);

    // Path 1: open via password (drives Argon2 + bundle unwrap).
    let vault_toml = std::fs::read(folder.join("vault.toml")).unwrap();
    let bundle_bytes = std::fs::read(folder.join("identity.bundle.enc")).unwrap();
    let unlocked = open_with_password(&vault_toml, &bundle_bytes, &secret_password)
        .expect("password unlock must succeed on golden fixture");
    let via_bundle: OpenVault = open_vault(folder, Unlocker::Bundle(&unlocked), None)
        .expect("Bundle unlocker must produce an OpenVault");

    // Path 2 (control): open via password directly.
    let via_password = open_vault(folder, Unlocker::Password(&secret_password), None)
        .expect("Password unlocker must produce an OpenVault");

    // The two OpenVault values must agree on the observable manifest
    // surface. We compare a few stable projections rather than the
    // whole opaque struct. `OpenVault.manifest` is a public field
    // (a `Manifest` struct) — no accessor needed.
    assert_eq!(
        via_bundle.manifest.vault_uuid,
        via_password.manifest.vault_uuid,
    );
    assert_eq!(
        via_bundle.manifest.vector_clock,
        via_password.manifest.vector_clock,
    );
}
```

> **Password fixture:** the golden vault's password lives in `core/tests/data/golden_vault_001_inputs.json` (a sibling of the vault folder, not inside it). The existing `core/tests/golden_vault_001.rs::load_inputs(inputs_path())` helper deserialises it into an `Inputs` struct that exposes `.password: String`. The new sync tests reuse the same JSON file via a small loader in `core/tests/fixtures/mod.rs` (defined in Task 7 Step 1). For this Task 6 test, inline the same `load_inputs` invocation or pre-build the fixture helper as part of Task 6 (then Task 7 imports it).

- [ ] **Step 3: Run the test to verify it fails (variant not defined yet)**

```bash
cargo test --release -p secretary-core --test open_vault open_vault_with_bundle -- --nocapture 2>&1 | head -30
```

Expected: compile error — `Unlocker::Bundle` not a variant. If using `open_vault_bundle.rs` substitute that file's test name.

- [ ] **Step 4: Add the `Bundle` variant to `Unlocker`**

In `core/src/vault/orchestrators.rs`, locate the `Unlocker<'a>` enum (around line 356) and extend:

```rust
pub enum Unlocker<'a> {
    Password(&'a SecretBytes),
    Recovery(&'a str),
    /// Bypass the unlock step entirely — the caller already holds an
    /// `UnlockedIdentity` from an earlier `open_with_password` /
    /// `open_with_recovery` call. Used by `core::sync::sync_once` so a
    /// sync poll does not re-run Argon2.
    Bundle(&'a UnlockedIdentity),
}
```

Add `use crate::unlock::UnlockedIdentity;` at the top of the file if not already imported.

- [ ] **Step 5: Extend the `open_vault` match arm**

Locate the match (around line 480) and add the third arm:

```rust
let unlocked = match unlocker {
    Unlocker::Password(p) => {
        unlock::open_with_password(&vault_toml_bytes, &identity_bundle_bytes, p)?
    }
    Unlocker::Recovery(words) => {
        unlock::open_with_recovery(&vault_toml_bytes, &identity_bundle_bytes, words)?
    }
    Unlocker::Bundle(bundle) => {
        // The bundle was unwrapped by a prior call to open_with_password
        // or open_with_recovery; clone it for downstream OpenVault
        // construction. UnlockedIdentity derives Clone via Sensitive<T>
        // and IdentityBundle both being Clone.
        bundle.clone()
    }
};
```

- [ ] **Step 6: Add `#[derive(Clone)]` to `UnlockedIdentity` if it's not already present**

If Step 1 showed no `Clone` derive on `UnlockedIdentity`, update the struct in `core/src/unlock/mod.rs`:

```rust
#[derive(Clone)]
pub struct UnlockedIdentity {
    pub identity_block_key: Sensitive<[u8; 32]>,
    pub identity: bundle::IdentityBundle,
}
```

Note: the custom `Debug` impl already in the file is preserved — `derive(Clone)` does not affect it.

If `IdentityBundle` does not derive `Clone`, add it there too. Run `grep -nB 2 "pub struct IdentityBundle" core/src/identity/bundle.rs` to inspect first.

- [ ] **Step 7: Run the test to verify it now passes**

```bash
cargo test --release -p secretary-core --test open_vault open_vault_with_bundle -- --nocapture
```

Expected: 1 test PASS.

- [ ] **Step 8: Run the full workspace to ensure no existing tests broke from the variant addition**

```bash
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{
  for (i=1; i<=NF; i++) {
    if ($i == "passed;") p += $(i-1)
    if ($i == "failed;") f += $(i-1)
    if ($i == "ignored;") ig += $(i-1)
  }
} END { printf("TOTAL: %d passed; %d failed; %d ignored\n", p, f, ig) }'
```

Expected: 642 + 1 (new) = 643 passed, 0 failed, 10 ignored (or higher if Tasks 2-5's unit tests already landed; the absolute number changes per task — but `failed` MUST be zero).

- [ ] **Step 9: Commit**

```bash
git add core/src/vault/orchestrators.rs core/src/unlock/mod.rs core/tests/open_vault.rs
# also add core/src/identity/bundle.rs if you had to derive Clone there
git commit -m "$(cat <<'EOF'
feat(c1): add Unlocker::Bundle variant for caller-held UnlockedIdentity

Open_vault gains a third Unlocker variant that bypasses the Argon2 +
identity-bundle-decrypt step when the caller already holds an
UnlockedIdentity (typically from an earlier open_with_password call
in the same session). The bundle is cloned into the downstream
OpenVault. core::sync::sync_once (next commits) uses this so each
sync poll runs in milliseconds rather than ~1 second of Argon2.

#[derive(Clone)] added to UnlockedIdentity. The custom redacting
Debug impl is preserved.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Phase C — `sync_once` algorithm

### Task 7: `sync_once` skeleton + vault.toml UUID mismatch path (first failing path)

**Files:**
- Modify: `core/src/sync/once.rs`
- Create: `core/tests/sync.rs`

- [ ] **Step 1: Write the failing integration test**

Create `core/tests/sync.rs`:

```rust
//! Integration tests for `core::sync::sync_once`.

use secretary_core::sync::{sync_once, SyncError, SyncState};
use secretary_core::unlock::open_with_password;

mod fixtures;

#[test]
fn sync_once_wrong_vault_uuid_typed_error() {
    // Build a SyncState bound to a different vault_uuid than golden_vault_001's.
    let folder = std::path::Path::new("tests/data/golden_vault_001");
    let password = fixtures::golden_vault_001_password();
    let vault_toml = std::fs::read(folder.join("vault.toml")).unwrap();
    let bundle = std::fs::read(folder.join("identity.bundle.enc")).unwrap();
    let identity = open_with_password(&vault_toml, &bundle, &password).unwrap();

    let wrong_state = SyncState::empty([0xDE; 16]);
    let err = sync_once(folder, &identity, &wrong_state, 0u64).unwrap_err();
    assert!(matches!(err, SyncError::VaultUuidMismatch { .. }));
}
```

Create `core/tests/fixtures/mod.rs`:

```rust
//! Shared test fixtures used by sync.rs (and future sync_proptest.rs /
//! sync_kat.rs). Re-uses the golden_vault_001 inputs JSON sourced
//! by the existing golden_vault_001 integration test.

use std::path::PathBuf;

use secretary_core::crypto::secret::SecretBytes;
use serde::Deserialize;

/// Mirrors the `Inputs` struct in `core/tests/golden_vault_001.rs`.
/// Kept private to this module; only `golden_vault_001_password()` is
/// exposed so callers don't depend on the JSON's full shape.
#[derive(Deserialize)]
struct Inputs {
    password: String,
    // other fields exist in the JSON but are not used here.
}

fn inputs_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("data");
    p.push("golden_vault_001_inputs.json");
    p
}

/// Loads the fixture password from `golden_vault_001_inputs.json` and
/// wraps it in a `SecretBytes` for `open_with_password`.
pub fn golden_vault_001_password() -> SecretBytes {
    let raw = std::fs::read_to_string(inputs_path())
        .expect("golden_vault_001_inputs.json must exist");
    let inputs: Inputs =
        serde_json::from_str(&raw).expect("golden_vault_001_inputs.json must be valid JSON");
    SecretBytes::new(inputs.password.into_bytes())
}
```

> **If `Inputs` already has a different field layout in the existing test:** run `grep -nB 2 -A 8 "struct Inputs" core/tests/golden_vault_001.rs` to inspect the actual fields. Only `password: String` is needed for the sync tests; ignore the rest via `#[serde(other)]` or by listing them with the right types.

- [ ] **Step 2: Run the test to verify it fails**

```bash
cargo test --release -p secretary-core --test sync sync_once_wrong_vault_uuid -- --nocapture 2>&1 | head -30
```

Expected: compile error — `sync_once` not yet defined.

- [ ] **Step 3: Implement the minimal `sync_once` that handles the UUID-mismatch path**

Write `core/src/sync/once.rs`:

```rust
//! `sync_once` — pure-function reconcile of one vault folder against
//! caller-persisted `SyncState`.

use std::path::Path;

use crate::sync::error::SyncError;
use crate::sync::outcome::{RollbackEvidence, SyncOutcome};
use crate::sync::state::SyncState;
use crate::unlock::{vault_toml, UnlockedIdentity};
use crate::vault::block::VectorClockEntry;
use crate::vault::conflict::{clock_relation, ClockRelation};
use crate::vault::orchestrators::{open_vault, Unlocker};

const VAULT_TOML_FILENAME: &str = "vault.toml";

/// Reconcile one local vault folder against caller-persisted state.
/// See `docs/superpowers/specs/2026-05-17-c1-sync-detection-design.md`.
///
/// `_now_ms` is unused in C.1 phase 1; the parameter is reserved for
/// C.1.1's merge timestamps so callers can wire the value through
/// without an API break later.
pub fn sync_once(
    vault_folder: &Path,
    identity: &UnlockedIdentity,
    state: &SyncState,
    _now_ms: u64,
) -> Result<SyncOutcome, SyncError> {
    // Step 1: vault.toml UUID cross-check.
    let vault_toml_path = vault_folder.join(VAULT_TOML_FILENAME);
    let vault_toml_string = std::fs::read_to_string(&vault_toml_path).map_err(|e| {
        SyncError::Io {
            context: "failed to read vault.toml",
            source: e,
        }
    })?;
    // Fold path: VaultTomlError → UnlockError::MalformedVaultToml → VaultError::Unlock
    // → SyncError::Vault. The chain preserves the typed error at the umbrella surface
    // (anti-conflation discipline — see core/src/unlock/mod.rs:UnlockError).
    let vt = vault_toml::decode(&vault_toml_string)
        .map_err(|e| SyncError::Vault(crate::vault::VaultError::Unlock(e.into())))?;
    if vt.vault_uuid != state.vault_uuid {
        return Err(SyncError::VaultUuidMismatch {
            state_vault_uuid: state.vault_uuid,
            folder_vault_uuid: vt.vault_uuid,
        });
    }

    // Step 2: open the vault via the new Unlocker::Bundle variant.
    let opened = open_vault(vault_folder, Unlocker::Bundle(identity), None)?;

    // Step 3-4: extract disk vector clock and dispatch.
    let disk_clock: Vec<VectorClockEntry> = opened.manifest_body().vector_clock.clone();
    dispatch(disk_clock, state)
}

fn dispatch(
    disk_clock: Vec<VectorClockEntry>,
    state: &SyncState,
) -> Result<SyncOutcome, SyncError> {
    match clock_relation(&state.highest_vector_clock_seen, &disk_clock) {
        ClockRelation::Equal => Ok(SyncOutcome::NothingToDo),
        ClockRelation::IncomingDominates => Ok(SyncOutcome::AppliedAutomatically {
            new_state: SyncState {
                vault_uuid: state.vault_uuid,
                highest_vector_clock_seen: disk_clock,
            },
        }),
        ClockRelation::IncomingDominated => Ok(SyncOutcome::RollbackRejected(RollbackEvidence {
            disk_vector_clock: disk_clock,
            local_highest_seen: state.highest_vector_clock_seen.clone(),
        })),
        ClockRelation::Concurrent => Ok(SyncOutcome::ForkDetected {
            disk_vector_clock: disk_clock,
            local_highest_seen: state.highest_vector_clock_seen.clone(),
        }),
    }
}

/// Test hook: exercise `dispatch` without going through the disk-IO
/// path. Per the `project_secretary_cfg_test_not_propagated` memory,
/// `#[cfg(test)]` items on the lib crate are invisible to integration
/// tests in `tests/*.rs`. `#[doc(hidden)] pub` makes the helper
/// reachable from both unit tests and integration tests while keeping
/// it out of the rendered API docs.
#[doc(hidden)]
pub fn __test_dispatch(
    disk_clock: Vec<VectorClockEntry>,
    state: &SyncState,
) -> Result<SyncOutcome, SyncError> {
    dispatch(disk_clock, state)
}
```

> **`OpenVault.manifest` is a public field** — `core/src/vault/orchestrators.rs:391` declares `pub manifest: Manifest`. No accessor; just read the field. The Task 7 sync_once code uses `opened.manifest.vector_clock.clone()` accordingly.

> **`vault_toml::decode` error fold** — uses the chain `VaultTomlError → UnlockError::MalformedVaultToml(#[from]) → VaultError::Unlock(#[from]) → SyncError::Vault(#[from])`. Verified by inspection at plan-write time; the single closure does the double `.into()` explicitly.

- [ ] **Step 4: Run the failing test again to verify it now passes**

```bash
cargo test --release -p secretary-core --test sync sync_once_wrong_vault_uuid -- --nocapture
```

Expected: 1 test PASS.

- [ ] **Step 5: Commit**

```bash
git add core/src/sync/once.rs core/tests/sync.rs core/tests/fixtures/
git commit -m "$(cat <<'EOF'
feat(c1): sync_once skeleton with vault.toml UUID cross-check

Reads vault.toml, decodes via unlock::vault_toml::decode, compares
vault_uuid against caller state. Mismatch fires SyncError::
VaultUuidMismatch before any unlock work. open_vault is called via
Unlocker::Bundle so the existing identity is reused without re-running
Argon2. Algorithm dispatch (clock_relation → SyncOutcome variants) is
in place but not yet exercised by tests — next commits add the four
branch-coverage integration tests.

#[doc(hidden)] pub __test_dispatch test-hook exposes the dispatch
function to integration tests per the established cross-target test
pattern.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: All four `clock_relation` branches via `__test_dispatch`

**Files:**
- Modify: `core/tests/sync.rs`

- [ ] **Step 1: Write the four failing tests**

Append to `core/tests/sync.rs`:

```rust
use secretary_core::sync::__test_dispatch;
use secretary_core::sync::{RollbackEvidence, SyncOutcome};
use secretary_core::vault::block::VectorClockEntry;

fn entry(b: u8, c: u64) -> VectorClockEntry {
    VectorClockEntry {
        device_uuid: [b; 16],
        counter: c,
    }
}

#[test]
fn dispatch_equal_clocks_yields_nothing_to_do() {
    let state = SyncState::new([0x42; 16], vec![entry(1, 5)]).unwrap();
    let outcome = __test_dispatch(vec![entry(1, 5)], &state).unwrap();
    assert_eq!(outcome, SyncOutcome::NothingToDo);
}

#[test]
fn dispatch_disk_strictly_ahead_yields_applied_automatically() {
    let state = SyncState::new([0x42; 16], vec![entry(1, 5)]).unwrap();
    let outcome = __test_dispatch(vec![entry(1, 7)], &state).unwrap();
    match outcome {
        SyncOutcome::AppliedAutomatically { new_state } => {
            assert_eq!(new_state.vault_uuid, [0x42; 16]);
            assert_eq!(new_state.highest_vector_clock_seen, vec![entry(1, 7)]);
        }
        other => panic!("expected AppliedAutomatically, got {other:?}"),
    }
}

#[test]
fn dispatch_disk_strictly_behind_yields_rollback_rejected() {
    let state = SyncState::new([0x42; 16], vec![entry(1, 9)]).unwrap();
    let outcome = __test_dispatch(vec![entry(1, 5)], &state).unwrap();
    match outcome {
        SyncOutcome::RollbackRejected(RollbackEvidence {
            disk_vector_clock,
            local_highest_seen,
        }) => {
            assert_eq!(disk_vector_clock, vec![entry(1, 5)]);
            assert_eq!(local_highest_seen, vec![entry(1, 9)]);
        }
        other => panic!("expected RollbackRejected, got {other:?}"),
    }
}

#[test]
fn dispatch_concurrent_clocks_yields_fork_detected() {
    let state = SyncState::new([0x42; 16], vec![entry(1, 5), entry(2, 3)]).unwrap();
    let outcome = __test_dispatch(vec![entry(1, 3), entry(2, 5)], &state).unwrap();
    match outcome {
        SyncOutcome::ForkDetected {
            disk_vector_clock,
            local_highest_seen,
        } => {
            assert_eq!(disk_vector_clock, vec![entry(1, 3), entry(2, 5)]);
            assert_eq!(local_highest_seen, vec![entry(1, 5), entry(2, 3)]);
        }
        other => panic!("expected ForkDetected, got {other:?}"),
    }
}

#[test]
fn dispatch_empty_state_disk_present_yields_applied_automatically() {
    let state = SyncState::empty([0x42; 16]);
    let outcome = __test_dispatch(vec![entry(1, 5)], &state).unwrap();
    assert!(matches!(outcome, SyncOutcome::AppliedAutomatically { .. }));
}

#[test]
fn dispatch_both_empty_yields_nothing_to_do() {
    let state = SyncState::empty([0x42; 16]);
    let outcome = __test_dispatch(vec![], &state).unwrap();
    assert_eq!(outcome, SyncOutcome::NothingToDo);
}
```

- [ ] **Step 2: Run the new tests**

```bash
cargo test --release -p secretary-core --test sync dispatch_ -- --nocapture
```

Expected: 6 tests, all PASS (implementation from Task 7 already covers them — these tests verify the dispatch logic works, not that you need to add code).

- [ ] **Step 3: Commit**

```bash
git add core/tests/sync.rs
git commit -m "$(cat <<'EOF'
test(c1): dispatch branch coverage for all four ClockRelation outcomes

Exercises core::sync::__test_dispatch via the #[doc(hidden)] test
hook for each disjoint branch: Equal → NothingToDo,
IncomingDominates → AppliedAutomatically (carries the new disk
clock as new_state), IncomingDominated → RollbackRejected (both
clocks surfaced as evidence), Concurrent → ForkDetected. Plus the
boundary cases — empty state + disk present, both empty.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 9: End-to-end `sync_once` tests via real golden_vault fixtures

**Files:**
- Modify: `core/tests/sync.rs`
- Create: `core/tests/sync_helpers/mod.rs` (utility for tweaking vector clocks in a per-test temp copy of the golden vault)

- [ ] **Step 1: Write the fixture helper**

Create `core/tests/sync_helpers/mod.rs`:

```rust
//! Per-test temp-folder copies of golden_vault_001 with the manifest's
//! vector clock re-written to a caller-supplied value. Used by the
//! end-to-end sync_once tests in sync.rs so each test asserts a
//! specific clock_relation outcome end-to-end (open_vault path, not
//! just the dispatch hook).

use std::path::{Path, PathBuf};

use secretary_core::vault::block::VectorClockEntry;

/// Recursively copies `golden_vault_001/` into a fresh temp dir, then
/// rewrites the manifest's vector clock to the supplied value
/// (preserving every other byte of the manifest body — re-signs with
/// the owner identity from the bundle).
///
/// Returns the temp folder path; caller is responsible for keeping the
/// `tempfile::TempDir` alive for the duration of the test.
pub fn fresh_vault_with_clock(
    new_clock: Vec<VectorClockEntry>,
) -> (PathBuf, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dest = tmp.path().to_path_buf();
    recursive_copy(Path::new("tests/data/golden_vault_001"), &dest);

    // Rewrite the manifest's vector clock. Use the existing
    // open_vault → mutate-manifest-body → re-sign primitives.
    // The exact API surface here depends on what's exposed; consult
    // core/src/vault/manifest.rs for the manifest mutator path. The
    // smoke runners do this for their save/share fixtures —
    // ffi/secretary-ffi-uniffi/tests/swift/SmokeHelpers.swift's
    // `_freshWritableVault` is a parallel example.
    rewrite_manifest_clock(&dest, new_clock);

    (dest, tmp)
}

fn recursive_copy(src: &Path, dest: &Path) {
    // Implementation mirrors SmokeHelpers.swift's `_recursiveCopy` —
    // walk src, create matching dirs, copy files. Use walkdir if
    // available; otherwise std::fs::read_dir recursion.
    todo!("recursive copy — port from existing smoke-runner pattern");
}

fn rewrite_manifest_clock(folder: &Path, new_clock: Vec<VectorClockEntry>) {
    // Open vault with the golden password, mutate manifest body's
    // vector_clock, re-sign via the existing core::vault::manifest
    // re-sign helpers, atomic-write back. The save_block orchestrator
    // does this kind of mutate-and-rewrite per call — borrow its
    // re-sign + atomic-write helpers from core::vault::orchestrators
    // and core::vault::io.
    todo!("rewrite manifest vector_clock and re-sign — port the pattern from save_block");
}
```

> **`todo!` markers are intentional placeholders for the implementer.** Before merging this task, replace both with concrete implementations. The smoke runners' `_recursiveCopy` / `_freshWritableVault` (Swift) and `recursiveCopy` / `freshWritableVault` (Kotlin) are direct references; the Rust port is straightforward but requires touching the manifest re-sign primitives. If a Rust helper for "rewrite manifest with new vector clock and re-sign" already exists in `core/src/vault/`, prefer it.

- [ ] **Step 2: Write the failing end-to-end tests**

Append to `core/tests/sync.rs`:

```rust
mod sync_helpers;

#[test]
fn sync_once_empty_state_accepts_golden_disk() {
    let folder = std::path::Path::new("tests/data/golden_vault_001");
    let password = fixtures::golden_vault_001_password();
    let identity = {
        let vt = std::fs::read(folder.join("vault.toml")).unwrap();
        let bundle = std::fs::read(folder.join("identity.bundle.enc")).unwrap();
        open_with_password(&vt, &bundle, &password).unwrap()
    };
    let golden_vault_uuid = extract_golden_vault_uuid();
    let state = SyncState::empty(golden_vault_uuid);

    let outcome = sync_once(folder, &identity, &state, 0u64).unwrap();
    assert!(matches!(outcome, SyncOutcome::AppliedAutomatically { .. }));
}

#[test]
fn sync_once_unchanged_disk_after_apply_yields_nothing_to_do() {
    let folder = std::path::Path::new("tests/data/golden_vault_001");
    let password = fixtures::golden_vault_001_password();
    let identity = {
        let vt = std::fs::read(folder.join("vault.toml")).unwrap();
        let bundle = std::fs::read(folder.join("identity.bundle.enc")).unwrap();
        open_with_password(&vt, &bundle, &password).unwrap()
    };
    let golden_vault_uuid = extract_golden_vault_uuid();
    let initial = SyncState::empty(golden_vault_uuid);
    let first = sync_once(folder, &identity, &initial, 0u64).unwrap();
    let new_state = match first {
        SyncOutcome::AppliedAutomatically { new_state } => new_state,
        other => panic!("first run must be AppliedAutomatically, got {other:?}"),
    };
    let second = sync_once(folder, &identity, &new_state, 0u64).unwrap();
    assert_eq!(second, SyncOutcome::NothingToDo);
}

#[test]
fn sync_once_disk_strictly_behind_rejects_rollback() {
    use sync_helpers::fresh_vault_with_clock;
    let (folder, _tmp) = fresh_vault_with_clock(vec![entry(1, 1)]);

    let password = fixtures::golden_vault_001_password();
    let vt = std::fs::read(folder.join("vault.toml")).unwrap();
    let bundle = std::fs::read(folder.join("identity.bundle.enc")).unwrap();
    let identity = open_with_password(&vt, &bundle, &password).unwrap();

    let golden_vault_uuid = extract_golden_vault_uuid();
    // State is at counter=9 for device 1; disk we just rewrote is at 1.
    let state = SyncState::new(golden_vault_uuid, vec![entry(1, 9)]).unwrap();
    let outcome = sync_once(&folder, &identity, &state, 0u64).unwrap();
    assert!(matches!(outcome, SyncOutcome::RollbackRejected(_)));
}

#[test]
fn sync_once_concurrent_disk_detects_fork() {
    use sync_helpers::fresh_vault_with_clock;
    // Disk has device 2 only; state has device 1 only → concurrent.
    let (folder, _tmp) = fresh_vault_with_clock(vec![entry(2, 5)]);

    let password = fixtures::golden_vault_001_password();
    let vt = std::fs::read(folder.join("vault.toml")).unwrap();
    let bundle = std::fs::read(folder.join("identity.bundle.enc")).unwrap();
    let identity = open_with_password(&vt, &bundle, &password).unwrap();

    let golden_vault_uuid = extract_golden_vault_uuid();
    let state = SyncState::new(golden_vault_uuid, vec![entry(1, 7)]).unwrap();
    let outcome = sync_once(&folder, &identity, &state, 0u64).unwrap();
    assert!(matches!(outcome, SyncOutcome::ForkDetected { .. }));
}

/// Helper: extract the golden vault's vault_uuid from its vault.toml
/// (so we don't hard-code the value here — it's pinned in the fixture
/// builder).
fn extract_golden_vault_uuid() -> [u8; 16] {
    let s = std::fs::read_to_string("tests/data/golden_vault_001/vault.toml").unwrap();
    let vt = secretary_core::unlock::vault_toml::decode(&s).unwrap();
    vt.vault_uuid
}
```

- [ ] **Step 3: Implement the `sync_helpers` `todo!` markers**

Replace both `todo!()` bodies with concrete implementations:

- `recursive_copy`: walk `src` via `std::fs::read_dir` recursion, mirror to `dest`. ~20 lines.
- `rewrite_manifest_clock`: open the vault, get the manifest body, rewrite `vector_clock`, re-sign + atomic-write via the same primitives `save_block` uses. ~40-60 lines. Look at `core::vault::orchestrators::save_block`'s implementation as the reference pattern.

> **If extracting the re-sign helpers proves invasive (would require pub-promoting private helpers), do the simpler thing: have `rewrite_manifest_clock` go via `save_block` itself — supply an empty record-edit so the manifest is re-signed with the side effect of bumping the vector clock to the desired value. If even that is awkward, use `core::vault::manifest::encrypt_and_sign_manifest` directly. The plan's goal is to get end-to-end tests working; pick the cheapest path.**

- [ ] **Step 4: Run the end-to-end tests**

```bash
cargo test --release -p secretary-core --test sync sync_once_ -- --nocapture
```

Expected: 4 tests PASS (the 4 new end-to-end ones, plus the prior 1 UUID-mismatch from Task 7 — 5 total in this filter).

- [ ] **Step 5: Commit**

```bash
git add core/tests/sync.rs core/tests/sync_helpers/
git commit -m "$(cat <<'EOF'
test(c1): end-to-end sync_once coverage via fresh_vault_with_clock helper

Four integration tests drive sync_once against per-test temp copies
of golden_vault_001 with the manifest vector clock rewritten to
each of the four ClockRelation branches:

- empty_state_accepts_golden_disk → AppliedAutomatically
- unchanged_disk_after_apply_yields_nothing_to_do → NothingToDo
- disk_strictly_behind_rejects_rollback → RollbackRejected
- concurrent_disk_detects_fork → ForkDetected

fresh_vault_with_clock helper (core/tests/sync_helpers/mod.rs) ports
the recursive_copy + manifest-re-sign pattern from the existing
Swift/Kotlin smoke runners' freshWritableVault helpers, adapted for
Rust integration tests.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 10: Error propagation paths

**Files:**
- Modify: `core/tests/sync.rs`

- [ ] **Step 1: Write the failing tests**

Append to `core/tests/sync.rs`:

```rust
#[test]
fn sync_once_missing_vault_toml_yields_io_error() {
    let tmp = tempfile::tempdir().unwrap();
    // No vault.toml in tmp.path() — should fire Io.
    let password = fixtures::golden_vault_001_password();
    let identity = {
        let vt = std::fs::read("tests/data/golden_vault_001/vault.toml").unwrap();
        let bundle = std::fs::read("tests/data/golden_vault_001/identity.bundle.enc").unwrap();
        open_with_password(&vt, &bundle, &password).unwrap()
    };
    let state = SyncState::empty([0u8; 16]);
    let err = sync_once(tmp.path(), &identity, &state, 0u64).unwrap_err();
    assert!(matches!(err, SyncError::Io { .. }));
    if let SyncError::Io { context, .. } = err {
        assert_eq!(context, "failed to read vault.toml");
    }
}

#[test]
fn sync_once_corrupted_manifest_yields_vault_error() {
    use sync_helpers::fresh_vault_with_clock;
    let (folder, _tmp) = fresh_vault_with_clock(vec![entry(1, 5)]);

    // Flip a byte in the middle of the manifest to corrupt it.
    let manifest_path = folder.join("manifest.cbor.enc");
    let mut manifest_bytes = std::fs::read(&manifest_path).unwrap();
    let mid = manifest_bytes.len() / 2;
    manifest_bytes[mid] ^= 0xFF;
    std::fs::write(&manifest_path, &manifest_bytes).unwrap();

    let password = fixtures::golden_vault_001_password();
    let vt = std::fs::read("tests/data/golden_vault_001/vault.toml").unwrap();
    let bundle = std::fs::read("tests/data/golden_vault_001/identity.bundle.enc").unwrap();
    let identity = open_with_password(&vt, &bundle, &password).unwrap();

    let state = SyncState::empty(extract_golden_vault_uuid());
    let err = sync_once(&folder, &identity, &state, 0u64).unwrap_err();
    assert!(matches!(err, SyncError::Vault(_)));
}
```

- [ ] **Step 2: Run the tests**

```bash
cargo test --release -p secretary-core --test sync sync_once_missing sync_once_corrupted -- --nocapture
```

Expected: 2 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add core/tests/sync.rs
git commit -m "$(cat <<'EOF'
test(c1): error propagation paths for sync_once

Missing vault.toml folds to SyncError::Io with the established
context string. Corrupted manifest (byte-flip) folds to
SyncError::Vault, preserving the typed error from the layer below
without conflation.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Phase D — Property tests and KAT

### Task 11: Proptest convergence + idempotence properties

**Files:**
- Create: `core/tests/sync_proptest.rs`

- [ ] **Step 1: Write the proptest properties**

Create `core/tests/sync_proptest.rs`:

```rust
//! Property tests for `core::sync::sync_once` and `__test_dispatch`.

use proptest::prelude::*;
use secretary_core::sync::{
    __test_dispatch, RollbackEvidence, SyncOutcome, SyncState,
};
use secretary_core::vault::block::VectorClockEntry;

fn entry_strategy() -> impl Strategy<Value = VectorClockEntry> {
    (any::<[u8; 16]>(), any::<u64>()).prop_map(|(device_uuid, counter)| VectorClockEntry {
        device_uuid,
        counter,
    })
}

/// Generates a canonical (sorted, deduped) vector clock — same
/// invariant SyncState enforces.
fn canonical_clock_strategy() -> impl Strategy<Value = Vec<VectorClockEntry>> {
    prop::collection::vec(entry_strategy(), 0..6).prop_map(|mut v| {
        v.sort_by_key(|e| e.device_uuid);
        v.dedup_by_key(|e| e.device_uuid);
        v
    })
}

proptest! {
    /// `sync_once`'s dispatch is deterministic: calling it twice with
    /// identical inputs must yield identical outputs.
    #[test]
    fn prop_dispatch_idempotent_under_repeat(
        vault_uuid in any::<[u8; 16]>(),
        state_clock in canonical_clock_strategy(),
        disk_clock in canonical_clock_strategy(),
    ) {
        let state = SyncState::new(vault_uuid, state_clock).unwrap();
        let first = __test_dispatch(disk_clock.clone(), &state).unwrap();
        let second = __test_dispatch(disk_clock, &state).unwrap();
        prop_assert_eq!(first, second);
    }

    /// After `AppliedAutomatically`, re-running the dispatch with the
    /// returned new_state and the same disk_clock yields `NothingToDo`.
    #[test]
    fn prop_applied_then_nothing_to_do(
        vault_uuid in any::<[u8; 16]>(),
        state_clock in canonical_clock_strategy(),
        disk_clock in canonical_clock_strategy(),
    ) {
        let state = SyncState::new(vault_uuid, state_clock).unwrap();
        if let SyncOutcome::AppliedAutomatically { new_state } =
            __test_dispatch(disk_clock.clone(), &state).unwrap()
        {
            let second = __test_dispatch(disk_clock, &new_state).unwrap();
            prop_assert_eq!(second, SyncOutcome::NothingToDo);
        }
        // Other outcomes — nothing to assert for this property.
    }

    /// Branch coverage is disjoint: exactly one of the four variants
    /// is returned, no panics, no overlaps.
    #[test]
    fn prop_branches_disjoint_and_total(
        vault_uuid in any::<[u8; 16]>(),
        state_clock in canonical_clock_strategy(),
        disk_clock in canonical_clock_strategy(),
    ) {
        let state = SyncState::new(vault_uuid, state_clock).unwrap();
        let outcome = __test_dispatch(disk_clock, &state).unwrap();
        // Pattern coverage — any future variant addition compile-errors here.
        let _classified: u8 = match outcome {
            SyncOutcome::NothingToDo => 0,
            SyncOutcome::AppliedAutomatically { .. } => 1,
            SyncOutcome::ForkDetected { .. } => 2,
            SyncOutcome::RollbackRejected(RollbackEvidence { .. }) => 3,
        };
    }
}
```

- [ ] **Step 2: Run the proptest**

```bash
cargo test --release -p secretary-core --test sync_proptest -- --nocapture
```

Expected: 3 tests PASS (each running 256 cases by default).

- [ ] **Step 3: Commit**

```bash
git add core/tests/sync_proptest.rs
git commit -m "$(cat <<'EOF'
test(c1): proptest properties — idempotence + applied-then-nothing + disjoint branches

Three properties drive 256 cases each over random (vault_uuid,
state_clock, disk_clock) triples:

- prop_dispatch_idempotent_under_repeat: deterministic dispatch.
- prop_applied_then_nothing_to_do: after AppliedAutomatically,
  re-running with the returned new_state yields NothingToDo.
- prop_branches_disjoint_and_total: exactly one of the four
  SyncOutcome variants is returned, exhaustively (the match arms
  guarantee any future variant addition will compile-error here).

canonical_clock_strategy emits the same sorted-and-deduped shape
SyncState::new accepts, so the proptest never trips on the input
canonicalisation invariant.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 12: `sync_kat.json` + Rust-side replay

**Files:**
- Create: `core/tests/data/sync_kat.json`
- Create: `core/tests/sync_kat.rs`

- [ ] **Step 1: Write the KAT vectors**

Create `core/tests/data/sync_kat.json`. Vectors are pure-data inputs to `__test_dispatch` — no fixture vault needed. Format mirrors the established `conflict_kat.json` shape:

```json
{
  "schema_version": 1,
  "description": "C.1 sync dispatch KAT. Inputs: state_vault_uuid + state_highest_vector_clock + disk_vector_clock. Output: enum variant name + (where applicable) the new_state's highest_vector_clock_seen. Python clean-room replay scheduled for C.4 (cross-device convergence conformance).",
  "vectors": [
    {
      "name": "equal_clocks_nothing_to_do",
      "state_vault_uuid": "00112233445566778899AABBCCDDEEFF",
      "state_highest_vector_clock": [
        { "device_uuid": "01010101010101010101010101010101", "counter": 5 }
      ],
      "disk_vector_clock": [
        { "device_uuid": "01010101010101010101010101010101", "counter": 5 }
      ],
      "expected_outcome": "NothingToDo"
    },
    {
      "name": "empty_state_empty_disk_nothing_to_do",
      "state_vault_uuid": "00112233445566778899AABBCCDDEEFF",
      "state_highest_vector_clock": [],
      "disk_vector_clock": [],
      "expected_outcome": "NothingToDo"
    },
    {
      "name": "empty_state_disk_present_applied_automatically",
      "state_vault_uuid": "00112233445566778899AABBCCDDEEFF",
      "state_highest_vector_clock": [],
      "disk_vector_clock": [
        { "device_uuid": "01010101010101010101010101010101", "counter": 1 }
      ],
      "expected_outcome": "AppliedAutomatically",
      "expected_new_state_clock": [
        { "device_uuid": "01010101010101010101010101010101", "counter": 1 }
      ]
    },
    {
      "name": "disk_strictly_ahead_applied_automatically",
      "state_vault_uuid": "00112233445566778899AABBCCDDEEFF",
      "state_highest_vector_clock": [
        { "device_uuid": "01010101010101010101010101010101", "counter": 5 }
      ],
      "disk_vector_clock": [
        { "device_uuid": "01010101010101010101010101010101", "counter": 7 }
      ],
      "expected_outcome": "AppliedAutomatically",
      "expected_new_state_clock": [
        { "device_uuid": "01010101010101010101010101010101", "counter": 7 }
      ]
    },
    {
      "name": "disk_adds_new_device_applied_automatically",
      "state_vault_uuid": "00112233445566778899AABBCCDDEEFF",
      "state_highest_vector_clock": [
        { "device_uuid": "01010101010101010101010101010101", "counter": 5 }
      ],
      "disk_vector_clock": [
        { "device_uuid": "01010101010101010101010101010101", "counter": 5 },
        { "device_uuid": "02020202020202020202020202020202", "counter": 3 }
      ],
      "expected_outcome": "AppliedAutomatically",
      "expected_new_state_clock": [
        { "device_uuid": "01010101010101010101010101010101", "counter": 5 },
        { "device_uuid": "02020202020202020202020202020202", "counter": 3 }
      ]
    },
    {
      "name": "disk_strictly_behind_rollback_rejected",
      "state_vault_uuid": "00112233445566778899AABBCCDDEEFF",
      "state_highest_vector_clock": [
        { "device_uuid": "01010101010101010101010101010101", "counter": 9 }
      ],
      "disk_vector_clock": [
        { "device_uuid": "01010101010101010101010101010101", "counter": 5 }
      ],
      "expected_outcome": "RollbackRejected"
    },
    {
      "name": "disk_missing_seen_device_rollback_rejected",
      "state_vault_uuid": "00112233445566778899AABBCCDDEEFF",
      "state_highest_vector_clock": [
        { "device_uuid": "01010101010101010101010101010101", "counter": 5 },
        { "device_uuid": "02020202020202020202020202020202", "counter": 3 }
      ],
      "disk_vector_clock": [
        { "device_uuid": "01010101010101010101010101010101", "counter": 5 }
      ],
      "expected_outcome": "RollbackRejected"
    },
    {
      "name": "concurrent_disjoint_devices_fork_detected",
      "state_vault_uuid": "00112233445566778899AABBCCDDEEFF",
      "state_highest_vector_clock": [
        { "device_uuid": "01010101010101010101010101010101", "counter": 5 }
      ],
      "disk_vector_clock": [
        { "device_uuid": "02020202020202020202020202020202", "counter": 3 }
      ],
      "expected_outcome": "ForkDetected"
    },
    {
      "name": "concurrent_overlapping_devices_fork_detected",
      "state_vault_uuid": "00112233445566778899AABBCCDDEEFF",
      "state_highest_vector_clock": [
        { "device_uuid": "01010101010101010101010101010101", "counter": 5 },
        { "device_uuid": "02020202020202020202020202020202", "counter": 7 }
      ],
      "disk_vector_clock": [
        { "device_uuid": "01010101010101010101010101010101", "counter": 8 },
        { "device_uuid": "02020202020202020202020202020202", "counter": 4 }
      ],
      "expected_outcome": "ForkDetected"
    }
  ]
}
```

- [ ] **Step 2: Write the Rust-side replay test**

Create `core/tests/sync_kat.rs`:

```rust
//! Replay `sync_kat.json` through `__test_dispatch`. Pinned vector
//! file — any change to the dispatch logic that changes an outcome
//! must be accompanied by a deliberate KAT edit.
//!
//! Python clean-room replay lands in C.4 (cross-device convergence
//! conformance), matching the staging pattern of B.6's
//! conformance_kat.json.

use secretary_core::sync::{__test_dispatch, RollbackEvidence, SyncOutcome, SyncState};
use secretary_core::vault::block::VectorClockEntry;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Kat {
    schema_version: u32,
    #[allow(dead_code)]
    description: String,
    vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    state_vault_uuid: String,
    state_highest_vector_clock: Vec<EntryJson>,
    disk_vector_clock: Vec<EntryJson>,
    expected_outcome: String,
    #[serde(default)]
    expected_new_state_clock: Option<Vec<EntryJson>>,
}

#[derive(Debug, Deserialize)]
struct EntryJson {
    device_uuid: String,
    counter: u64,
}

const EXPECTED_SCHEMA_VERSION: u32 = 1;

fn hex_to_uuid(s: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    let bytes = hex::decode(s).expect("hex");
    assert_eq!(bytes.len(), 16);
    out.copy_from_slice(&bytes);
    out
}

fn entries_from_json(js: &[EntryJson]) -> Vec<VectorClockEntry> {
    js.iter()
        .map(|e| VectorClockEntry {
            device_uuid: hex_to_uuid(&e.device_uuid),
            counter: e.counter,
        })
        .collect()
}

#[test]
fn replay_sync_kat() {
    let raw = std::fs::read_to_string("tests/data/sync_kat.json").unwrap();
    let kat: Kat = serde_json::from_str(&raw).unwrap();
    assert_eq!(
        kat.schema_version, EXPECTED_SCHEMA_VERSION,
        "sync_kat.json schema_version drift"
    );

    for v in &kat.vectors {
        let state_clock = entries_from_json(&v.state_highest_vector_clock);
        let disk_clock = entries_from_json(&v.disk_vector_clock);
        let state = SyncState::new(hex_to_uuid(&v.state_vault_uuid), state_clock)
            .unwrap_or_else(|e| panic!("vector {} state invalid: {e}", v.name));
        let outcome = __test_dispatch(disk_clock.clone(), &state)
            .unwrap_or_else(|e| panic!("vector {} dispatch failed: {e}", v.name));

        match (v.expected_outcome.as_str(), &outcome) {
            ("NothingToDo", SyncOutcome::NothingToDo) => {}
            ("AppliedAutomatically", SyncOutcome::AppliedAutomatically { new_state }) => {
                let expected = entries_from_json(
                    v.expected_new_state_clock
                        .as_ref()
                        .expect("AppliedAutomatically vector must carry expected_new_state_clock"),
                );
                assert_eq!(
                    new_state.highest_vector_clock_seen, expected,
                    "vector {} new_state clock mismatch",
                    v.name
                );
            }
            ("ForkDetected", SyncOutcome::ForkDetected { .. }) => {}
            ("RollbackRejected", SyncOutcome::RollbackRejected(RollbackEvidence { .. })) => {}
            (expected, actual) => panic!(
                "vector {} expected {} got {:?}",
                v.name, expected, actual
            ),
        }
    }

    assert_eq!(kat.vectors.len(), 9, "sync_kat.json vector count drift");
}
```

- [ ] **Step 3: Verify dev-deps are available**

```bash
grep -E "^serde|^hex|^proptest|^tempfile" core/Cargo.toml
```

Expected: `serde`, `serde_json`, `hex`, `proptest`, `tempfile` all present (verified at plan-write time — `proptest = "1"`, `serde_json = "1"` with `preserve_order`, `hex = "0.4"`, `tempfile = "=3.27.0"`). No additions needed.

- [ ] **Step 4: Run the KAT replay**

```bash
cargo test --release -p secretary-core --test sync_kat -- --nocapture
```

Expected: 1 test PASS, all 9 vectors verified.

- [ ] **Step 5: Commit**

```bash
git add core/tests/data/sync_kat.json core/tests/sync_kat.rs core/Cargo.toml
git commit -m "$(cat <<'EOF'
test(c1): sync_kat.json — 9-vector dispatch KAT + Rust replay

Vector file pins the four ClockRelation → SyncOutcome mappings plus
boundary cases (both-empty, empty-state-disk-present, disk-adds-
new-device, disk-missing-seen-device, overlapping-concurrent).
Python clean-room replay scheduled for C.4 per the B.6 staging
pattern; sync_kat.json's schema is JSON-native and binding-agnostic,
so the C.4 Python verifier needs no Rust-side changes to consume it.

EXPECTED_SCHEMA_VERSION and vector-count pin guard against silent
KAT drift on future edits — both are deliberate.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Phase E — Polish, gauntlet, ROADMAP

### Task 13: Module-level doc comments + clippy/fmt sweep

**Files:**
- Modify: `core/src/sync/mod.rs` (expand the doc comment if needed)
- Modify: any file flagged by clippy

- [ ] **Step 1: Run clippy on the whole workspace, tests included**

```bash
cargo clippy --release --workspace --tests -- -D warnings
```

Expected: clean — no warnings. Fix any flagged item in place; common ones for new code are `needless_return`, `redundant_clone`, `useless_vec`.

- [ ] **Step 2: Run `cargo fmt`**

```bash
cargo fmt --all -- --check
```

If it complains, run `cargo fmt --all` and re-stage.

- [ ] **Step 3: Sanity-check doc rendering**

```bash
cargo doc -p secretary-core --no-deps 2>&1 | tail -5
```

Expected: no warnings. The `__test_dispatch` hook is `#[doc(hidden)]` so it should not appear in the public API.

- [ ] **Step 4: Commit (only if anything changed)**

```bash
git diff --stat
# if non-empty:
git add -A
git commit -m "$(cat <<'EOF'
chore(c1): clippy + fmt sweep for the sync module

No semantic changes; cosmetic-only cleanups surfaced by clippy
--release --tests -D warnings and cargo fmt --check.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 14: ROADMAP sentence update

**Files:**
- Modify: `ROADMAP.md`

- [ ] **Step 1: Locate the Sub-project C section**

```bash
grep -n "Sub-project C" ROADMAP.md
```

- [ ] **Step 2: Read the C section to find the right insertion point**

The current text says "Sub-project C — Sync orchestration ⏳ (planned)". Add a sentence at the end of that section's phase-plan block recording that C.1 phase 1 (detection-only) has landed.

- [ ] **Step 3: Edit `ROADMAP.md`**

Add a sentence like:

> **C.1 phase 1 (sync detection)** ✅ — `core::sync::sync_once` exposes the §10 rollback-and-fork-detection algorithm as a pure-function dispatch over `clock_relation`. Conflict-copy ingestion, automatic merge, and veto-on-tombstone are scoped to C.1.1.

And bump the C progress bar from all-dashes to a partial fill (e.g., 8 `=` characters in front of `…sync_once landed`).

- [ ] **Step 4: Commit**

```bash
git add ROADMAP.md
git commit -m "$(cat <<'EOF'
docs(roadmap): record C.1 phase 1 (sync detection) as landed

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 15: Full gauntlet verification

- [ ] **Step 1: Cargo workspace**

```bash
cargo test --release --workspace --no-fail-fast > /tmp/c1-gauntlet.log 2>&1
grep -E "^test result:" /tmp/c1-gauntlet.log | awk '{
  for (i=1; i<=NF; i++) {
    if ($i == "passed;") p += $(i-1)
    if ($i == "failed;") f += $(i-1)
    if ($i == "ignored;") ig += $(i-1)
  }
}
END { printf("TOTAL: %d passed; %d failed; %d ignored\n", p, f, ig) }'
```

Expected: TOTAL ≈ 672 passed (642 pre-C.1 + ~30 from this PR), 0 failed, 10 ignored.

- [ ] **Step 2: Clippy and fmt (re-verify after ROADMAP edit)**

```bash
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
```

Expected: both clean.

- [ ] **Step 3: Python conformance**

```bash
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py
```

Expected: PASS / 96+ resolved (count grows with the new sync.rs test names; the resolved number should increase, unresolved should stay 0).

- [ ] **Step 4: Smoke + conformance runners (cheap sanity)**

```bash
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
```

Expected: 38/38, 39/39, 22/22, 22/22 (unchanged from main — no FFI surface touched by C.1).

- [ ] **Step 5: Push the branch and open the PR**

```bash
git push -u origin feature/c1-sync-detection
gh pr create --title "feat(c1): sync rollback + fork detection (phase 1)" --body "$(cat <<'EOF'
## Summary

- First slice of Sub-project C — pure-Rust `core::sync::sync_once` free function that classifies a vault folder's on-disk state against caller-persisted `SyncState` into one of `NothingToDo` / `AppliedAutomatically { new_state }` / `ForkDetected` / `RollbackRejected`.
- Implements `crypto-design.md` §10 (manifest signing + rollback resistance) as a typed-outcome dispatch over `clock_relation`.
- Adds `Unlocker::Bundle(&UnlockedIdentity)` variant so sync polls reuse the caller's existing unlocked identity without re-running Argon2.
- Veto-on-tombstone, conflict-copy ingestion, and automatic merge are scoped to a separate **C.1.1** slice with its own design.

Spec: [docs/superpowers/specs/2026-05-17-c1-sync-detection-design.md](docs/superpowers/specs/2026-05-17-c1-sync-detection-design.md).
Plan: [docs/superpowers/plans/2026-05-17-c1-sync-detection.md](docs/superpowers/plans/2026-05-17-c1-sync-detection.md).

## Test plan

- [ ] `cargo test --release --workspace` — 672 passed, 0 failed, 10 ignored (642 → 672, +~30 new tests).
- [ ] `cargo clippy --release --workspace --tests -- -D warnings` — clean.
- [ ] `cargo fmt --all -- --check` — OK.
- [ ] `uv run core/tests/python/conformance.py` — PASS.
- [ ] `uv run core/tests/python/spec_test_name_freshness.py` — PASS.
- [ ] `bash ffi/secretary-ffi-uniffi/tests/swift/run.sh` — 38/38.
- [ ] `bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh` — 39/39.
- [ ] `bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh` — 22/22.
- [ ] `bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh` — 22/22.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

> **Confirm before opening the PR:** the implementer should review the diff, run the test plan locally, and only push after green. Don't `gh pr create` ahead of a clean gauntlet.

---

## Self-review checklist (run after completing the plan above)

- [ ] Every section of the design spec maps to at least one task above. Sections covered:
  - Scope and non-goals → no implementation; recorded in plan intro.
  - D1-D4 decisions → recorded in commit messages.
  - Module layout → Task 1.
  - `SyncState` → Tasks 3, 4.
  - `SyncOutcome` + `RollbackEvidence` → Task 5.
  - `SyncError` → Task 2.
  - `sync_once` algorithm → Tasks 7, 8, 9, 10.
  - `Unlocker::Bundle` extension → Task 6.
  - State persistence (CBOR) → Task 4.
  - Testing strategy (unit + integration + proptest + KAT) → Tasks 2-12.
  - Workspace impact (ROADMAP sentence) → Task 14.
  - Open items decisions (constructor+decoder, same-PR Bundle, KAT-populated-with-Rust-replay) → resolved per `args`; reflected in Tasks 3-4, 6, 12.
- [ ] No "TODO" / "TBD" / "implement later" markers left in the task bodies (the two `todo!()` macros in Task 9 Step 1 are intentional implementation-handoff markers that Step 3 explicitly says to replace; flagged in the task itself).
- [ ] Type and method names consistent across tasks (`SyncState`, `SyncOutcome`, `RollbackEvidence`, `SyncError`, `sync_once`, `__test_dispatch`, `validate_clock_canonical`, `Unlocker::Bundle`).
- [ ] Every code step has actual code, not pseudo-code.
- [ ] Test commands include the exact filter to run, not a vague `cargo test`.
