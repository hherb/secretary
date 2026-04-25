//! Integration tests for the `crypto::secret` module.
//!
//! Kept as a separate compilation target so they exercise the public API the
//! same way downstream code will, and so any future post-drop verification
//! (which would require `unsafe`) can live here without weakening the
//! `forbid(unsafe_code)` boundary on the main crate.

use secretary_core::crypto::secret::{SecretBytes, Sensitive, Zeroize};

#[test]
fn test_zeroize_clears_bytes() {
    let mut s = SecretBytes::new(vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
    s.zeroize();
    assert!(
        s.expose().iter().all(|&b| b == 0),
        "expected all bytes zeroed, got {:?}",
        s.expose()
    );
}

#[test]
fn test_debug_does_not_leak_bytes() {
    let s = SecretBytes::new(vec![0xAA, 0xBB, 0xCC, 0xDD]);
    let dbg = format!("{s:?}");

    // The hex / decimal forms of the secret bytes must not appear.
    for &byte in s.expose() {
        let hex = format!("{byte:x}");
        let dec = format!("{byte}");
        assert!(
            !dbg.contains(&hex),
            "debug output {dbg:?} leaked hex byte {hex}"
        );
        assert!(
            !dbg.contains(&dec),
            "debug output {dbg:?} leaked decimal byte {dec}"
        );
    }
    assert!(
        dbg.contains("len"),
        "expected the redacted debug form to mention `len`, got {dbg:?}"
    );
}

#[test]
fn test_eq_constant_time_equal_inputs() {
    let a = SecretBytes::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
    let b = SecretBytes::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(a, b);
}

#[test]
fn test_eq_constant_time_unequal_inputs() {
    let a = SecretBytes::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
    let b = SecretBytes::new(vec![1, 2, 3, 4, 5, 6, 7, 9]);
    assert_ne!(a, b);
}

#[test]
fn test_eq_different_lengths() {
    let a = SecretBytes::new(vec![1, 2, 3]);
    let b = SecretBytes::new(vec![1, 2, 3, 4]);
    // Must not panic. `subtle::ConstantTimeEq` on `&[u8]` short-circuits to
    // false on length mismatch — we just need to confirm no panic and a
    // not-equal result.
    assert_ne!(a, b);
    assert_ne!(b, a);
}

#[test]
fn test_sensitive_zeroize_array() {
    let mut s: Sensitive<[u8; 32]> = Sensitive::new([0xAB; 32]);
    s.zeroize();
    assert_eq!(s.expose(), &[0u8; 32]);
}

#[test]
fn test_sensitive_debug_does_not_leak() {
    let s: Sensitive<[u8; 16]> = Sensitive::new([0x42; 16]);
    let dbg = format!("{s:?}");
    assert!(
        !dbg.contains("42") && !dbg.contains("66"),
        "debug output {dbg:?} leaked sensitive bytes"
    );
    assert!(dbg.contains("redacted"));
}

#[test]
fn test_sensitive_constant_time_compare_via_slice() {
    use subtle::ConstantTimeEq;
    let a: Sensitive<[u8; 8]> = Sensitive::new([7; 8]);
    let b: Sensitive<[u8; 8]> = Sensitive::new([7; 8]);
    let c: Sensitive<[u8; 8]> = Sensitive::new([8; 8]);
    assert!(bool::from(a.expose()[..].ct_eq(&b.expose()[..])));
    assert!(!bool::from(a.expose()[..].ct_eq(&c.expose()[..])));
}
