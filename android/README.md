# android/

Kotlin / Jetpack Compose Android client (Sub-project E). Bindings live under `ffi/secretary-ffi-uniffi/`.

Gradle modules:

- `:vault-access` — pure host-tested `kotlin("jvm")` sync orchestration core (C.3 slice 1): metadata-only value types, `VaultSyncPort`, `VaultSyncError`, `SyncCoordinator`. No FFI/folder-watch/Compose.
- `:kit` — Android-library module hosting the real `UniffiVaultSyncPort` over the generated uniffi bindings + arm64 `jniLibs` (cross-built via cargo-ndk). Host- and build-verified (the arm64 `.so` packs into the release AAR); the emulator round-trip is slice 2b.
