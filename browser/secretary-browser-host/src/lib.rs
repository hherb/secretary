#![forbid(unsafe_code)]
//! `secretary-browser-host` — the Secretary browser-autofill native-messaging
//! host (D.4.1 walking skeleton).
//!
//! The browser spawns this host as a subprocess and exchanges length-prefixed
//! JSON frames over its stdin/stdout. **There is no listening socket** — that
//! structural property (threat-model §6 invariant 3) is the whole point of the
//! D.4.1 slice.
//!
//! This crate is intentionally **pure transport**: it has **no `secretary-core`
//! dependency**, holds no key material, and opens no vault. D.4.2 attaches the
//! crypto behind the same `open_with_device_secret` verify-before-decrypt path.
//!
//! D.4.1 task 1 ships the framing codec ([`frame`]); task 2 adds the protocol
//! message types and the read→dispatch→write loop.

pub mod frame;
