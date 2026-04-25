//! Cryptographic primitive wrappers.
//!
//! Populated incrementally:
//!   - build-sequence step 1: `secret` (zeroize-on-drop wrappers)
//!   - step 2: `kdf`, `aead`, `hash`
//!   - step 3: `kem`, `sig` (hybrid constructions)

pub mod secret;
