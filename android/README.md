# android/

Kotlin / Jetpack Compose Android client (Sub-project E). Bindings live under `ffi/secretary-ffi-uniffi/`.

Gradle modules:

- `:vault-access` — pure host-tested `kotlin("jvm")` sync orchestration core (C.3 slice 1): metadata-only value types, `VaultSyncPort`, `VaultSyncError`, `SyncCoordinator`. No FFI/folder-watch/Compose.
- `:kit` — Android-library module hosting the real `UniffiVaultSyncPort` over the generated uniffi bindings + arm64 `jniLibs` (cross-built via cargo-ndk). Host- and build-verified (the arm64 `.so` packs into the release AAR); the emulator round-trip is slice 2b.

## Cloud vault storage (SAF providers)

A cloud vault lives in a folder the user picks through the Android system file picker (Storage
Access Framework). Any provider that exposes a `DocumentsProvider` works, but consistency guarantees
vary:

- **Supported / tested:** the on-device test provider and local document trees — strongly consistent.
- **Best-effort (eventually-consistent):** Google Drive and similar cloud providers cache directory
  listings and defer writes, so a create/sync can fail on the first attempt and succeed on retry.
  `RetryingCloudFolderPort` (vault-access) wraps the SAF port with bounded retry-with-backoff plus a
  read-back verify on every write, which makes these providers usable at the cost of a slower first
  write. See [#330](https://github.com/hherb/secretary/issues/330).

A native provider SDK path (e.g. Dropbox OAuth) — strongly consistent, but pulling a third-party SDK
into the secrets process — is tracked separately as an additive `CloudFolderPort` implementation in
[#334](https://github.com/hherb/secretary/issues/334).
