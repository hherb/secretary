# sync_collision_fixture (#190, generated)

Two-device divergence: `vault/` holds a canonical manifest + a sibling
conflict-copy manifest. Both sides keep the same record LIVE and edit
the same field concurrently, so the merge resolves CLEANLY — zero
tombstone vetoes, but >=1 field-level LWW collision (informational).
`state/<uuid>.state.cbor` is a seeded SyncState whose clock is
Concurrent with both manifests. Loading `vault/` with password
"correct horse battery staple" and `state/` as the state dir makes
the bridge `sync_vault_in` return MergedClean (commits the merge,
advances + persists state, rewrites the block). Contrast
`sync_conflict_fixture` (#187), whose tombstone sibling yields
ConflictsPending instead.

Regenerate via: cargo test --release -p secretary-cli --test sync_pass_integration -- --ignored generate_sync_collision_fixture --nocapture
