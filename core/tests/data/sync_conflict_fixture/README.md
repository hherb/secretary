# sync_conflict_fixture (#187, generated)

Two-device divergence: `vault/` holds a canonical manifest + a sibling
conflict-copy manifest that tombstones a record the canonical side
still has live; `state/<uuid>.state.cbor` is a seeded SyncState whose
clock is Concurrent with both manifests. Loading `vault/` with password
"correct horse battery staple" and `state/` as the state dir makes
`sync_vault` return ConflictsPending (vetoes non-empty, collisions
empty — the tombstone merge yields no field collision; see #192).

Regenerate via: cargo test --release -p secretary-cli --test sync_pass_integration -- --ignored generate_sync_conflict_fixture --nocapture
