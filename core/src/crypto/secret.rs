//! Secret-bearing wrappers with zeroize-on-drop and constant-time equality.
//!
//! The point of these types is to make every read of secret material visible
//! at use sites — hence [`SecretBytes::expose`] rather than `as_slice` or a
//! `Deref<Target=[u8]>` impl. Equality is constant-time so two secrets with
//! identical lengths cannot be distinguished by timing.
//!
//! `secrecy` was considered but skipped: its `expose_secret()` API is
//! reasonable, but rolling these thin wrappers ourselves keeps the public
//! surface small (one method name to grep for) and avoids tracking another
//! dependency's API stability.

use core::fmt;
use subtle::ConstantTimeEq;
pub use zeroize::{Zeroize, ZeroizeOnDrop};

/// Heap-allocated secret byte buffer. Zeroizes on drop and exposes contents
/// only through the explicit [`expose`](Self::expose) accessor.
///
/// Cloning is intentionally not derived. If a copy is required, callers
/// should write `SecretBytes::new(bytes.expose().to_vec())` so that the new
/// allocation is visible in code review.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes {
    inner: Vec<u8>,
}

impl SecretBytes {
    /// Take ownership of `bytes`. The original `Vec<u8>` is moved in; its
    /// allocation is zeroized when the resulting `SecretBytes` is dropped.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { inner: bytes }
    }

    /// Borrow the secret bytes. Use sites should be visible in code review:
    /// any line containing `.expose()` is reading secret material.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.inner
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretBytes")
            .field("len", &self.inner.len())
            .finish()
    }
}

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        // `ct_eq` short-circuits on length mismatch (returns 0/false) without
        // reading mismatched bytes; for equal lengths it's branch-free over
        // the byte content.
        self.inner.ct_eq(&other.inner).into()
    }
}

impl Eq for SecretBytes {}

/// Generic secret wrapper for any `T: Zeroize`. Useful for fixed-size keys
/// like `[u8; 32]` where heap allocation would be wasteful.
///
/// Intentionally does **not** implement `PartialEq`. `subtle` only provides
/// `ConstantTimeEq` for slices and integer primitives; an `==` impl bounded on
/// `T: ConstantTimeEq` would silently fail to apply to `[u8; N]`, the
/// canonical use case. Callers that need constant-time equality on a fixed
/// array should compare slices explicitly:
///
/// ```ignore
/// use subtle::ConstantTimeEq;
/// let equal: bool = a.expose()[..].ct_eq(&b.expose()[..]).into();
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Sensitive<T: Zeroize> {
    inner: T,
}

impl<T: Zeroize> Sensitive<T> {
    #[must_use]
    pub fn new(value: T) -> Self {
        Self { inner: value }
    }

    /// Borrow the wrapped secret. Same review-visibility intent as
    /// [`SecretBytes::expose`].
    #[must_use]
    pub fn expose(&self) -> &T {
        &self.inner
    }
}

impl<T: Zeroize> fmt::Debug for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sensitive")
            .field("inner", &"<redacted>")
            .finish()
    }
}
