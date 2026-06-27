//! Transposition-safe UUID role newtypes for the block re-key path (#183).
//!
//! The shared re-key engine ([`crate::vault::orchestrators::share_block`] /
//! [`crate::vault::orchestrators::revoke_block_recipient`]) threads several
//! `[u8; 16]` UUIDs that play *different roles* — which block, which recipient,
//! which writing device. Because they share the underlying type, a positional
//! transposition at a call site (e.g. swapping `revoked_recipient_uuid` and
//! `device_uuid`, which are adjacent in [`revoke_block_recipient`]) compiles
//! silently. On a security-critical path (block content-key rotation + hybrid
//! re-sign) that is one easy mistake away from a wrong-block / wrong-recipient
//! re-key.
//!
//! These newtypes make each role a *distinct type*, so a transposition becomes a
//! compile error rather than a silent logic bug. They are intentionally scoped to
//! the re-key path: the rest of `core` keeps raw `[u8; 16]`, and the
//! `Vec<[u8; 16]>` recipient lists / on-disk `BlockEntry.recipients` type are
//! untouched (the on-disk format is frozen for v1).
//!
//! # Enforcement
//!
//! The point of these newtypes is that a role transposition is a *compile*
//! error, not a silent logic bug. This is the load-bearing guarantee, so it is
//! pinned by a `compile_fail` doctest (run by `cargo test --doc`): a
//! [`DeviceUuid`] cannot be passed where a [`BlockUuid`] is expected. If the
//! roles ever collapse back to a shared type, this stops failing and the test
//! breaks loudly.
//!
//! ```compile_fail
//! use secretary_core::vault::{BlockUuid, DeviceUuid};
//! fn wants_block(_: BlockUuid) {}
//! let device = DeviceUuid::new([0u8; 16]);
//! wants_block(device); // mismatched types: expected `BlockUuid`, found `DeviceUuid`
//! ```
//!
//! [`revoke_block_recipient`]: crate::vault::orchestrators::revoke_block_recipient
//! [`share_block`]: crate::vault::orchestrators::share_block

/// Length in bytes of every UUID role below (matches the on-disk 16-byte UUIDs).
const UUID_LEN: usize = 16;

/// Generates a transposition-safe `[u8; UUID_LEN]` newtype with the shared
/// constructor / accessor / `From` surface. Each role is its own type, so the
/// compiler rejects passing one role where another is expected.
macro_rules! uuid_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; UUID_LEN]);

        impl $name {
            /// Wrap raw UUID bytes in this role.
            pub const fn new(bytes: [u8; UUID_LEN]) -> Self {
                Self(bytes)
            }

            /// Borrow the underlying UUID bytes (for hashing / formatting).
            pub const fn as_bytes(&self) -> &[u8; UUID_LEN] {
                &self.0
            }

            /// Consume the newtype, returning the raw UUID bytes. Cheap (`Copy`).
            pub const fn into_inner(self) -> [u8; UUID_LEN] {
                self.0
            }
        }

        impl From<[u8; UUID_LEN]> for $name {
            fn from(bytes: [u8; UUID_LEN]) -> Self {
                Self(bytes)
            }
        }

        impl From<$name> for [u8; UUID_LEN] {
            fn from(id: $name) -> Self {
                id.0
            }
        }
    };
}

uuid_newtype! {
    /// The UUID of the block being re-keyed.
    BlockUuid
}

uuid_newtype! {
    /// A recipient-role UUID: the share target, the revoke target, or the owner
    /// of a contact card being persisted alongside a re-key.
    RecipientUuid
}

uuid_newtype! {
    /// The UUID of the device performing the write. Ticks the manifest-level
    /// vector clock; never the block being operated on.
    DeviceUuid
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_then_into_inner_round_trips() {
        let bytes = [0x11; UUID_LEN];
        assert_eq!(BlockUuid::new(bytes).into_inner(), bytes);
        assert_eq!(RecipientUuid::new(bytes).into_inner(), bytes);
        assert_eq!(DeviceUuid::new(bytes).into_inner(), bytes);
    }

    #[test]
    fn as_bytes_borrows_the_wrapped_value() {
        let bytes = [0x22; UUID_LEN];
        assert_eq!(BlockUuid::new(bytes).as_bytes(), &bytes);
    }

    #[test]
    fn from_into_is_symmetric() {
        let bytes = [0x33; UUID_LEN];
        let id = BlockUuid::from(bytes);
        let back: [u8; UUID_LEN] = id.into();
        assert_eq!(back, bytes);
    }

    #[test]
    fn equality_is_value_based() {
        let bytes = [0x44; UUID_LEN];
        assert_eq!(DeviceUuid::new(bytes), DeviceUuid::new(bytes));
        assert_ne!(DeviceUuid::new(bytes), DeviceUuid::new([0x45; UUID_LEN]));
    }
}
