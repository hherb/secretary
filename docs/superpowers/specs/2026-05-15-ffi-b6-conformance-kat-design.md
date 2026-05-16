# Sub-project B.6 — Cross-language FFI conformance KAT (v1: read-only path)

**Date:** 2026-05-15
**Status:** Design approved (brainstormed 2026-05-15; this doc is the input to writing-plans).
**Predecessor:** [B.5 — trash_block / restore_block](2026-05-11-ffi-b5-trash-restore-block-design.md).
**Successor (planned):** B.6 v2 (lifecycle KAT — adds `save_block` / `share_block` / `trash_block` / `restore_block` vectors once `save_block` non-determinism is resolved); thereafter Sub-project C kickoff (sync orchestration).

## 1. Purpose

Add a **cross-language conformance KAT** that pins the observable outputs of the read-only half of the uniffi FFI surface (`open_vault_with_password`, `open_vault_with_recovery`, `read_block`) into a frozen JSON contract that **every** binding — Rust (via the bridge crate), Swift, Kotlin, and any Sub-project D binding added later — must match bit-for-bit.

Today the Swift and Kotlin smoke runners separately assert "output looks right" using hardcoded literals like `displayName == "Owner"` and `blockCount == 1`. Each runner is internally consistent, but there is no cross-language gate: a binding that quietly renamed a typed-error variant, reordered a record's fields, or stripped trailing whitespace from a `display_name` would pass its own assertions while silently diverging from the other.

B.6 makes that divergence impossible to ship: every binding's observable read-side output is pinned in `core/tests/data/conformance_kat.json`, the Rust bridge crate replays the KAT on every `cargo test`, and the Swift/Kotlin host runners replay the same KAT through the uniffi-generated bindings. Drift in any of the three triggers a typed test failure.

**Scope discipline:** v1 is **read-only only**. Lifecycle ops (`save_block` / `share_block` / `trash_block` / `restore_block`) are deferred to a v2 KAT (separate issue, separate PR) because `save_block` uses OS-CSPRNG-driven AEAD nonces and pinning byte output would require either a test-only RNG knob or a shape-only assertion strategy — a non-trivial design decision that should not block v1.

## 2. Architectural decisions (settled in brainstorming)

| Decision | Choice | Rationale |
|---|---|---|
| Primary purpose | **Cross-language parity contract.** All bindings must produce identical observable values from identical inputs against `golden_vault_001`. | The existing smoke runners are functional smoke tests (does the binding work end-to-end); the KAT is a parity contract (do all bindings agree on what the FFI surface emits). Future-proofs the FFI for Sub-project D bindings. |
| KAT scope (v1) | **Read-only path:** `open_vault_with_password` + `open_vault_with_recovery` + `read_block`, happy + error paths. No write/lifecycle operations. | Deterministic against the fixture — no RNG dependency, no writable-vault fixture needed. Lifecycle KAT (v2) is a follow-up that requires a separate determinism design (test-RNG knob vs. shape-only pinning). |
| Golden-truth source | **Rust generator** — `cargo test -- --ignored generate_conformance_kat` writes the KAT from a known-good run of the bridge crate against `golden_vault_001`. The KAT is then frozen in-tree and never regenerated except on intentional protocol change. | Matches the established pattern: [`conflict_kat.json`](../../../core/tests/data/conflict_kat.json) and [`golden_vault_001_inputs.json`](../../../core/tests/data/golden_vault_001_inputs.json) are both Rust-generated and Python-verified. Keeps Rust as the live truth and the bindings as conformance partners. Hand-authoring would be error-prone for the deeply-nested `read_block` record fields. |
| Verification partners | **Three:** Rust bridge crate (`core/tests/conformance_kat.rs`, runs every `cargo test`), Swift uniffi binding (`tests/swift/conformance.swift`), Kotlin uniffi binding (`tests/kotlin/Conformance.kt`). | Three independent partners catch a wider set of regressions than two: a Rust bridge bug that silently drops a field would be caught by Swift + Kotlin diverging from Rust, not just by one binding failing alone. |
| Harness layout | **Separate harness binary + run.sh per host.** New `tests/swift/conformance.swift` + `tests/swift/run_conformance.sh`, plus `tests/kotlin/Conformance.kt` + `tests/kotlin/run_conformance.sh`. | Keeps the existing 1200+ line smoke runners from growing further past the 500-line guideline. Independent PASS/FAIL — a conformance failure does not mask smoke runner success or vice versa. Two run.sh files per host is small extra boilerplate compared to maintaining a 1500-line single binary. |
| Vector identifier | Each vector has a unique `name` (kebab-case snake_case mix following `conflict_kat.json` precedent; e.g. `open_password_happy`, `open_password_wrong`, `read_block_unknown_uuid`) | Stable identifiers for diffing — when a vector's expected output changes, the diff names which contract it broke, not just "vector at index 7". |
| Vector dependencies | Vectors form a small forward-only graph via an optional `after: "<predecessor-vector-name>"` field. The replay engine on each host first executes vectors with no `after` (the open/error paths), caches their successful `UnlockedIdentity` + `OpenVaultManifest` outputs, then runs `read_block` vectors against the cached state from their named predecessor. | Avoids re-opening the vault for every read_block vector (5+ unlock cycles cost ~5 × 200ms = wasted second per host). Keeps each vector individually inspectable in JSON — the dependency is data, not code. |
| `expected.kind` discriminator | Two kinds: `"ok"` (with operation-specific fields like `display_name`, `block_count`, `block_uuid_hex`, `records[]`) or `"err"` (with `variant` string + optional `detail_contains` substring match). | Mirrors the typed-error surface in [`ffi/secretary-ffi-uniffi/src/errors/`](../../../ffi/secretary-ffi-uniffi/src/errors/). One string-typed `variant` field is enough because the FFI's `UnlockError` and `VaultError` are flat enums — a host runner can switch on the variant string and assert the actual error has the matching case. `detail_contains` (substring match) handles fields like `InvalidMnemonic.detail = "expected 24 words, got 3"` where the full string includes implementation-noise but the substring "got 3" is the actual contract. |
| Record-field pinning | For `read_block` happy-path vectors, the `records[]` array pins each record's `record_uuid_hex`, `name` string, and `fields[]` array. Each field pins `type` (discriminator: `"text"` or `"bytes"`) and the corresponding value (`value_utf8` for `text`, `value_hex` for `bytes`). | Captures the entire observable plaintext shape returned by `read_block`. The discriminator string mirrors the actual enum case names emitted across bindings. Hex for bytes (not base64) because hex matches the rest of the project's KATs (`conflict_kat.json`, `golden_vault_001_inputs.json`) and is human-readable on inspection. |
| Field ordering inside a record | Pinned (the JSON `fields[]` array is positional) | Reordering fields would be a wire-format regression — the spec mandates a specific serialization order, and a binding that returns fields in a different order is shipping a different observable surface. |
| Error fixture inputs | Each err-variant vector either references a literal (e.g. `"password_literal_utf8": "wrong"`) or a fixture reference (e.g. `"password_source": "golden_vault_002_inputs.json:password"`). | Reuses the existing input fixtures; no new test data needed. The fixture-reference form keeps the KAT self-documenting (you can read it without inspecting the runner). |
| Path resolution | Each host runner reads two env vars: `SECRETARY_GOLDEN_VAULT_DIR` (already set by smoke `run.sh`) and `SECRETARY_CONFORMANCE_KAT` (new; set by `run_conformance.sh` to `$REPO_ROOT/core/tests/data/conformance_kat.json`). | Follows the established smoke runner pattern. No hardcoded paths in `.swift`/`.kt` files. |
| Regeneration policy | The Rust `#[test] #[ignore] fn generate_conformance_kat` writes the KAT to disk. Running it is a deliberate act ("intentional protocol change"); the diff is human-reviewed before commit. The `#[test] fn replay_conformance_kat` (non-ignored) gates every CI run. | Matches the `generate_golden_inputs` precedent at [`core/tests/golden_vault_001.rs`](../../../core/tests/golden_vault_001.rs) (where the ignored generator emits the frozen inputs). Prevents accidental regeneration from masking a real regression. |

## 3. Module structure

```
core/tests/data/conformance_kat.json
                          NEW. Frozen JSON vectors. Single source of truth
                          for both host runners and the Rust replay test.
                          Generated once by the ignored generator below,
                          then human-reviewed and committed.

core/tests/conformance_kat.rs
                          NEW. Two #[test] entry points:
                            - #[ignore] fn generate_conformance_kat()
                                Runs the bridge crate's read-side
                                orchestrators against golden_vault_001 and
                                emits conformance_kat.json.
                            - #[test] fn replay_conformance_kat()
                                Reads the frozen JSON, replays every
                                vector against the bridge crate, fails on
                                any divergence. ~250 LOC.

ffi/secretary-ffi-uniffi/tests/swift/conformance.swift
                          NEW. Swift host runner. Loads conformance_kat.json
                          via SECRETARY_CONFORMANCE_KAT, executes each
                          vector against the uniffi-generated Swift wrapper,
                          prints one PASS/FAIL per vector + a final summary.
                          ~300 LOC.

ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
                          NEW. Build + bindgen + swiftc pipeline (mirrors
                          run.sh; the cargo build is dedup'd automatically).
                          Sets SECRETARY_GOLDEN_VAULT_DIR + SECRETARY_CONFORMANCE_KAT.
                          ~80 LOC.

ffi/secretary-ffi-uniffi/tests/kotlin/Conformance.kt
                          NEW. Kotlin host runner. Same shape as Swift; JNA
                          + kotlinc + java -cp pipeline. ~300 LOC.

ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
                          NEW. Mirrors swift/run_conformance.sh; differs only
                          in the JNA + kotlinc bits (same as smoke run.sh diff).
                          ~120 LOC (the JNA fetch + SHA verification is the
                          extra mass over Swift).

CLAUDE.md
                          EDIT. Add the two run_conformance.sh entries to the
                          "Commands" section, alongside the existing smoke
                          run.sh entries.

ROADMAP.md
                          EDIT. Mark B.6 v1 (read-only KAT) done; add a
                          B.6 v2 (lifecycle KAT) row as planned next forward
                          progress chunk before Sub-project C.

NO CHANGES to:
  - core/src/**       (no semantic changes; the bridge crate's read-side
                       orchestrators are already exercised — B.6 only
                       freezes their existing observable outputs in JSON)
  - ffi/secretary-ffi-uniffi/src/**  (no UDL changes — no new FFI surface)
  - ffi/secretary-ffi-bridge/src/**  (no orchestrator changes)
  - ffi/secretary-ffi-py/**           (B.6 v1 is uniffi-only; PyO3
                                       could consume the KAT in a future
                                       PR but is explicitly out of scope)
```

Total new code: roughly 1050 lines (250 Rust + 300 Swift + 300 Kotlin + 200 shell).

## 4. KAT vector format

```json
{
  "version": 1,
  "comment": "Cross-language FFI conformance KAT. v1 read-only scope. See docs/superpowers/specs/2026-05-15-ffi-b6-conformance-kat-design.md. Generated by `cargo test --release --workspace -- --ignored generate_conformance_kat --nocapture`; intentional protocol changes regenerate, diffs are human-reviewed. Verified by core/tests/conformance_kat.rs::replay_conformance_kat (every cargo test), ffi/secretary-ffi-uniffi/tests/{swift,kotlin}/conformance.{swift,kt} (manual run_conformance.sh until wired into the documented gauntlet).",
  "vectors": [
    {
      "name": "open_password_happy",
      "description": "open_vault_with_password against golden_vault_001 using the pinned password from golden_vault_001_inputs.json:password → returns UnlockedIdentity(displayName='Owner') + OpenVaultManifest with the single golden block.",
      "operation": "open_vault_with_password",
      "inputs": {
        "vault_dir": "golden_vault_001",
        "password_source": "golden_vault_001_inputs.json:password"
      },
      "expected": {
        "kind": "ok",
        "display_name": "Owner",
        "block_count": 1,
        "block_uuid_hex": "11223344556677889900aabbccddeeff"
      }
    },
    {
      "name": "open_password_wrong",
      "description": "open_vault_with_password with a literal wrong password → typed VaultError.WrongPasswordOrCorrupt.",
      "operation": "open_vault_with_password",
      "inputs": {
        "vault_dir": "golden_vault_001",
        "password_literal_utf8": "wrong"
      },
      "expected": {
        "kind": "err",
        "variant": "WrongPasswordOrCorrupt"
      }
    },
    {
      "name": "open_password_nonexistent_folder",
      "description": "open_vault_with_password against a bogus folder path → typed VaultError.FolderInvalid.",
      "operation": "open_vault_with_password",
      "inputs": {
        "vault_dir_literal": "/this/folder/does/not/exist",
        "password_source": "golden_vault_001_inputs.json:password"
      },
      "expected": {
        "kind": "err",
        "variant": "FolderInvalid"
      }
    },
    {
      "name": "open_recovery_happy",
      "description": "open_vault_with_recovery using the pinned 24-word phrase → same observable as open_password_happy.",
      "operation": "open_vault_with_recovery",
      "inputs": {
        "vault_dir": "golden_vault_001",
        "mnemonic_source": "golden_vault_001_inputs.json:recovery_mnemonic_phrase"
      },
      "expected": {
        "kind": "ok",
        "display_name": "Owner",
        "block_count": 1,
        "block_uuid_hex": "11223344556677889900aabbccddeeff"
      }
    },
    {
      "name": "open_recovery_wrong_phrase",
      "description": "open_vault_with_recovery using vault_002's phrase against vault_001's folder → typed VaultError.WrongMnemonicOrCorrupt.",
      "operation": "open_vault_with_recovery",
      "inputs": {
        "vault_dir": "golden_vault_001",
        "mnemonic_source": "golden_vault_002_inputs.json:recovery_mnemonic_phrase"
      },
      "expected": {
        "kind": "err",
        "variant": "WrongMnemonicOrCorrupt"
      }
    },
    {
      "name": "open_recovery_short_phrase",
      "description": "open_vault_with_recovery with a 3-word phrase → typed VaultError.InvalidMnemonic with detail containing 'got 3'.",
      "operation": "open_vault_with_recovery",
      "inputs": {
        "vault_dir": "golden_vault_001",
        "mnemonic_literal_utf8": "one two three"
      },
      "expected": {
        "kind": "err",
        "variant": "InvalidMnemonic",
        "detail_contains": "got 3"
      }
    },
    {
      "name": "read_block_happy",
      "description": "read_block on golden_vault_001's sole block → pinned record list with field UUIDs, names, types, and values.",
      "operation": "read_block",
      "after": "open_password_happy",
      "inputs": {
        "block_uuid_hex": "11223344556677889900aabbccddeeff"
      },
      "expected": {
        "kind": "ok",
        "records": [
          {
            "record_uuid_hex": "<filled-in-by-generator>",
            "name": "<filled-in-by-generator>",
            "fields": [
              {
                "type": "text",
                "value_utf8": "<filled-in-by-generator>"
              }
            ]
          }
        ]
      }
    },
    {
      "name": "read_block_unknown_uuid",
      "description": "read_block with a UUID not present in the manifest → typed VaultError.BlockNotFound.",
      "operation": "read_block",
      "after": "open_password_happy",
      "inputs": {
        "block_uuid_hex": "00000000000000000000000000000000"
      },
      "expected": {
        "kind": "err",
        "variant": "BlockNotFound"
      }
    },
    {
      "name": "read_block_wrong_length_uuid",
      "description": "read_block with a non-16-byte block_uuid → typed VaultError.InvalidArgument.",
      "operation": "read_block",
      "after": "open_password_happy",
      "inputs": {
        "block_uuid_bytes_hex": "1122"
      },
      "expected": {
        "kind": "err",
        "variant": "InvalidArgument"
      }
    }
  ]
}
```

The `<filled-in-by-generator>` placeholders for `read_block_happy.expected.records` are populated by the Rust generator the first time it runs against `golden_vault_001` — the design doc does not pre-pin these because the exact record content lives in the golden fixture's encrypted block, and re-typing it here risks divergence. The generator's output is then human-reviewed before commit.

## 5. Replay engine (shared semantics across all three partners)

Each replay engine — Rust (`core/tests/conformance_kat.rs::replay_conformance_kat`), Swift (`tests/swift/conformance.swift`), Kotlin (`tests/kotlin/Conformance.kt`) — implements the same algorithm:

```
1. Load conformance_kat.json from $SECRETARY_CONFORMANCE_KAT.
2. Resolve fixture references:
   - "X_source": "golden_vault_NNN_inputs.json:field" → load JSON, take string field, encode utf-8.
   - "X_literal_utf8": "<str>" → encode utf-8.
   - "X_bytes_hex": "<hex>" → decode hex.
   - "vault_dir": "golden_vault_NNN" → join with $SECRETARY_GOLDEN_VAULT_DIR.
   - "vault_dir_literal": "<path>" → use verbatim.
3. Partition vectors: those with no "after" first (sources), those with "after" second (chained).
4. Execute sources in declaration order, cache successful Ok(OpenVaultOutput) (i.e. the `(UnlockedIdentity, OpenVaultManifest)` pair) for later `after:` lookups. Vectors that resolve to Err do not populate the cache.
5. Execute chained vectors. Each looks up its `after` predecessor in the cache:
   - If the predecessor is in the cache (it returned Ok during step 4), use that pair as input to the chained operation.
   - If the predecessor is NOT in the cache (it returned Err, or it doesn't exist by name), the chained vector itself FAILs immediately with reason `"predecessor '<name>' did not produce a cacheable Ok"`. This is a KAT authoring error and surfaces as a per-vector FAIL rather than a cascade abort.
6. For each vector:
   - If expected.kind == "ok":
     - Operation must return Ok; assert per-field shape against expected.
   - If expected.kind == "err":
     - Operation must return Err; assert error case-name == expected.variant.
     - If expected.detail_contains present, assert the error's detail field contains the substring.
7. Print "PASS: <vector_name>" on success, "FAIL: <vector_name>: <reason>" on failure.
8. Exit 0 if all PASS, non-zero otherwise.
```

The three replays differ in language and binding surface but not in semantics. This is the cross-language contract.

### `record` shape assertion

For `read_block_happy.expected.records`, each replay engine asserts:
- `records.len() == expected.records.len()` (exact match, not just length-ge).
- For each `i`: `records[i].record_uuid` (16 bytes) hex-equal to `expected.records[i].record_uuid_hex`.
- For each `i`: `records[i].name` UTF-8-equal to `expected.records[i].name`.
- For each `i`: `records[i].fields.len() == expected.records[i].fields.len()`.
- For each `i, j`: field type discriminator string matches; the corresponding value field is byte-equal (`value_utf8` UTF-8-decoded equals; `value_hex` hex-decoded byte-equal).

Field ordering within a record is pinned (positional comparison), per §2 design decision.

### Error case-name assertion

Each binding's error enum has a discriminator string accessible at runtime:
- **Rust:** matches on the enum variant; the variant ident is the string (e.g. `VaultError::WrongPasswordOrCorrupt` → `"WrongPasswordOrCorrupt"`).
- **Swift:** uniffi-generated enum cases have an `enumDescription()`-like accessor (or pattern-match in a `switch`, mapping each case to its name string).
- **Kotlin:** uniffi-generated sealed-class subtype name (`when (error) { is VaultException.WrongPasswordOrCorrupt -> "WrongPasswordOrCorrupt"; ... }`).

The mapping table is the same across all three; the replay engines each implement their own `case_name(&error)` helper. A binding that renames a variant (or drops one) fails the comparison loudly.

### `detail_contains` substring match

For typed errors with a `detail` payload (`InvalidMnemonic { detail }`, `CorruptVault { detail }`, etc.), the replay engine extracts the detail string and asserts the configured substring is present. Substring-only match (not equality) because the full detail strings include implementation noise (line numbers, byte offsets) that should not be part of the cross-language contract — only the human-readable cause fragment is.

## 6. CI integration

| Surface | New gate | Existing gate | When run |
|---|---|---|---|
| Rust replay | `cargo test --release --workspace replay_conformance_kat` (auto-discovered as part of the standard `cargo test --release --workspace`) | Yes (subsumed by `cargo test`) | Every PR |
| Rust generator | `cargo test --release --workspace -- --ignored generate_conformance_kat` | No | Manual on intentional protocol change |
| Swift conformance | `bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh` | No (parallel to the existing `run.sh` smoke runner) | Documented in CLAUDE.md as part of the PR gauntlet, alongside smoke `run.sh` |
| Kotlin conformance | `bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh` | No (parallel to the existing `run.sh` smoke runner) | Same as Swift |

The expected exit-line shapes match the smoke runner format:
- Each per-vector line: `PASS: <vector_name>: <one-line summary>` or `FAIL: <vector_name>: <reason>`.
- Final summary line per host: `OK: secretary uniffi <lang> conformance — all <N>/<N> vectors passed.` or non-zero exit with a failure tally.

## 7. Spec / docs updates

| File | Change |
|---|---|
| `docs/superpowers/specs/2026-05-15-ffi-b6-conformance-kat-design.md` | This file. New. |
| `CLAUDE.md` Commands section | Add two `bash …/run_conformance.sh` lines, paired with the existing `run.sh` lines. |
| `ROADMAP.md` line 34 (current-state) | Mark B.6 v1 done after PR lands; add a B.6 v2 (lifecycle KAT) row as the next forward chunk. |
| `core/tests/data/conformance_kat.json` `comment` field | Embeds the path to this design doc + the regeneration command (single source of truth pointer). |

**No spec doc changes** to `docs/crypto-design.md` or `docs/vault-format.md` — the KAT pins observable behavior of an existing FFI surface, not a wire-format change.

## 8. Defenses + non-goals

### Designed-against failure modes

| Failure mode | Caught by |
|---|---|
| Binding silently renames a typed-error variant (e.g. `WrongPassword` → `BadPassword`) | The host runner's `case_name(&error)` mapping fails to find the renamed case → FAIL with "no matching variant for renamed enum" |
| Binding's CBOR decoder reorders a record's fields | `records[i].fields` positional comparison surfaces the reordering as a per-index field mismatch |
| Binding strips trailing NUL bytes or normalizes whitespace in `display_name` | The byte-equal UTF-8 comparison on `display_name` catches the divergence |
| One binding silently accepts a 3-word mnemonic phrase | The `open_recovery_short_phrase` vector requires `InvalidMnemonic` with `detail_contains: "got 3"`; a binding that accepts the phrase produces `Ok(...)` and fails the `kind` check |
| Rust bridge regression that drops a `read_block` record field | The Rust replay test fails first (every `cargo test`); the host runners' replays would also fail after the next `run_conformance.sh` invocation |
| Two bindings disagree on the `BlockNotFound` vs. `InvalidArgument` boundary for the empty-UUID case | The vectors pin the specific case-name for each input shape; ambiguity in the FFI surface itself surfaces as a per-binding FAIL on the divergent host |

### Non-goals (explicitly out of scope for v1)

- **Lifecycle ops** (`save_block` / `share_block` / `trash_block` / `restore_block`). v2.
- **PyO3 binding** parity. The KAT file format is binding-agnostic, but the PyO3 host runner is a separate PR (not yet scoped).
- **Fuzz coverage.** Different harness — `core/fuzz/` already covers byte-level corruption on the wire format. The KAT is a positive-path contract, not a fuzz harness.
- **Sub-project C sync semantics.** Vector clocks, merge KATs, and conflict detection are all out of scope; B.6 is a strictly FFI-surface contract.
- **Performance** assertions (timing, allocation, memory residency). The KAT is observable-bytes-only.

## 9. Implementation outline (one PR)

1. **First commit** — `core/tests/data/conformance_kat.json` (skeleton with the 9 vectors and `<filled-in-by-generator>` placeholders for `read_block_happy`); `core/tests/conformance_kat.rs` with the `#[ignore]` generator and the `#[test]` replay.
2. **Second commit** — run the generator (`cargo test ... -- --ignored generate_conformance_kat --nocapture`) and commit the populated `conformance_kat.json` (the generator's diff is human-reviewed; the placeholders become concrete record bytes).
3. **Third commit** — `ffi/secretary-ffi-uniffi/tests/swift/conformance.swift` + `run_conformance.sh`; verify the runner passes against the now-populated KAT.
4. **Fourth commit** — `ffi/secretary-ffi-uniffi/tests/kotlin/Conformance.kt` + `run_conformance.sh`; verify the runner passes.
5. **Fifth commit (docs)** — CLAUDE.md Commands section, ROADMAP.md line 34, NEXT_SESSION.md + handoff snapshot. Per the standing `feedback_next_session_in_pr.md` rule, NEXT_SESSION.md and the handoff snapshot ride inside this PR.

Each commit is independently buildable and tested. The PR opens after step 5.

## 10. Test gauntlet at PR-close

Mirrors the standard project gauntlet, plus the two new run_conformance.sh entries:

```bash
cargo test --release --workspace --no-fail-fast  # Expect: 641+ passed (640 + replay_conformance_kat) + 10 ignored (9 + generate_conformance_kat)
cargo clippy --release --workspace --tests -- -D warnings  # Expect: clean
cargo fmt --all -- --check                                   # Expect: OK
uv run core/tests/python/conformance.py                      # Expect: PASS (unchanged baseline)
uv run core/tests/python/spec_test_name_freshness.py         # Expect: PASS (96 / 0 / 2 unchanged)
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh             # Expect: 37/37 PASS (unchanged)
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh # Expect: 9/9 PASS (new)
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh            # Expect: 37/37 PASS (unchanged)
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh # Expect: 9/9 PASS (new)
```

## 11. Open questions deferred to writing-plans / implementation

- **Generator output format details:** how the Rust generator serializes hex (lowercase, no separators — matches `conflict_kat.json` precedent) and how it pretty-prints the JSON (2-space indent — same precedent). To be settled in writing-plans before writing the generator.
- **Swift error case-name extraction:** whether to use a Swift extension on the generated `VaultError`/`UnlockError` to add a `caseName: String` property, or to inline a `switch` in the runner. Latter is simpler but harder to maintain as variants grow. To be settled in writing-plans.
- **Kotlin equivalent:** same question for the Kotlin sealed-class hierarchy. To be settled in writing-plans.
- **Generator regeneration discipline:** whether to gate `generate_conformance_kat` behind a `SECRETARY_REGEN_KAT=1` env var in addition to `#[ignore]`. To be settled in writing-plans.

These do not change the design — they are implementation-detail decisions that the implementation plan will resolve.

## 12. Acceptance criteria

- `conformance_kat.json` exists and contains 9 vectors covering the 3 open/recover/read happy + 6 error paths.
- `cargo test --release --workspace` passes; the new `replay_conformance_kat` test is part of the count.
- `bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh` exits 0 with 9/9 PASS.
- `bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh` exits 0 with 9/9 PASS.
- CLAUDE.md Commands section documents the two new run_conformance.sh entries.
- ROADMAP.md current-state line marks B.6 v1 done.
- NEXT_SESSION.md + handoff snapshot include the per-binding test counts and a pointer to this design doc.
- The B.6 v2 (lifecycle KAT) follow-up is filed as a new GitHub issue with the deferred determinism design as its open question.
