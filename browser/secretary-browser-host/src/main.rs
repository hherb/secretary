#![forbid(unsafe_code)]
//! Entry point for the Secretary native-messaging host.
//!
//! D.4.1 **task 1** ships only the framing codec
//! ([`secretary_browser_host::frame`]); the stdin/stdout read→dispatch→write
//! loop is wired up in **task 2** alongside the `protocol` message types. Until
//! then this binary is a placeholder so the crate builds as a workspace member
//! and the codec stays CI-gated.

fn main() {
    // Intentionally empty: the read→handle→write loop lands in D.4.1 task 2.
}
