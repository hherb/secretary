//! Single-fault `bundle_file` seeds (#641), planted into
//! `core/fuzz/seeds/bundle_file/golden.bin`.
//!
//! The §3 envelope (`docs/vault-format.md`) is a fixed big-endian layout read
//! by offset, so the offsets below are spelled from the field widths in
//! order. [`checked_base`] asserts each wrap length prefix the base carries is
//! the §3 value 32 before any seed is planted, so an offset that drifted onto
//! a neighbouring field fails here instead of planting a different fault.
//!
//! The `variant` column separates the shapes one token covers: seven of the
//! nine seeds name `container_malformed`, spread over five
//! `BundleFileError` variants, and Section RTS pins the Python class of each.

use std::mem::size_of;

use secretary_core::vault::manifest::RuleToken;
use secretary_core::version::FORMAT_VERSION;

use super::SeedCase;

// §3 field widths.
const U16_LEN: usize = size_of::<u16>();
const U32_LEN: usize = size_of::<u32>();
const VAULT_UUID_LEN: usize = 16;
const NONCE_LEN: usize = 24;
/// The 32-byte Identity Block Key plus its 16-byte Poly1305 tag.
const WRAP_CT_WITH_TAG_LEN: usize = 32 + 16;
/// What §3 requires each `wrap_*_ct_len` prefix to declare.
const WRAP_CT_LEN: u32 = 32;

// §3 field offsets: magic (u32), format_version (u16), file_kind (u16),
// vault_uuid, created_at_ms (u64), then three nonce || u32 length || ct
// sections (wrap_pw, wrap_rec, bundle).
const MAGIC_AT: usize = 0;
const FORMAT_VERSION_AT: usize = MAGIC_AT + U32_LEN;
const FILE_KIND_AT: usize = FORMAT_VERSION_AT + U16_LEN;
const VAULT_UUID_AT: usize = FILE_KIND_AT + U16_LEN;
const CREATED_AT_AT: usize = VAULT_UUID_AT + VAULT_UUID_LEN;
const WRAP_PW_LEN_AT: usize = CREATED_AT_AT + size_of::<u64>() + NONCE_LEN;
const WRAP_REC_LEN_AT: usize = WRAP_PW_LEN_AT + U32_LEN + WRAP_CT_WITH_TAG_LEN + NONCE_LEN;
const BUNDLE_CT_LEN_AT: usize = WRAP_REC_LEN_AT + U32_LEN + WRAP_CT_WITH_TAG_LEN + NONCE_LEN;

/// `bundle_file.rs`'s `FILE_KIND_IDENTITY_BUNDLE` is `pub(crate)`; §3 states
/// it as `0x0001`.
const FILE_KIND_IDENTITY_BUNDLE: u16 = 0x0001;
/// A byte appended past the bundle tag.
const TRAILING_BYTE: u8 = 0;

fn put_u16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + U16_LEN].copy_from_slice(&value.to_be_bytes());
}

fn put_u32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + U32_LEN].copy_from_slice(&value.to_be_bytes());
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(bytes[at..at + U32_LEN].try_into().expect("4 bytes"))
}

/// The base as a mutable copy, after checking the offsets land on the two
/// fields whose v1 value is known.
fn checked_base(base: &[u8]) -> Vec<u8> {
    for (field, at) in [("wrap_pw", WRAP_PW_LEN_AT), ("wrap_rec", WRAP_REC_LEN_AT)] {
        assert_eq!(
            u32_at(base, at),
            WRAP_CT_LEN,
            "{field}_ct_len offset {at} does not hold the §3 value: the layout drifted"
        );
    }
    base.to_vec()
}

fn bad_magic(base: &[u8]) -> Vec<u8> {
    let mut b = checked_base(base);
    b[MAGIC_AT] ^= u8::MAX;
    b
}

fn wrong_file_kind(base: &[u8]) -> Vec<u8> {
    let mut b = checked_base(base);
    put_u16(&mut b, FILE_KIND_AT, FILE_KIND_IDENTITY_BUNDLE + 1);
    b
}

fn unsupported_format_version(base: &[u8]) -> Vec<u8> {
    let mut b = checked_base(base);
    put_u16(&mut b, FORMAT_VERSION_AT, FORMAT_VERSION + 1);
    b
}

/// Ends one byte into `vault_uuid`.
fn truncated_header(base: &[u8]) -> Vec<u8> {
    checked_base(base)[..VAULT_UUID_AT + 1].to_vec()
}

fn wrap_pw_ct_len(base: &[u8]) -> Vec<u8> {
    let mut b = checked_base(base);
    put_u32(&mut b, WRAP_PW_LEN_AT, WRAP_CT_LEN + 1);
    b
}

fn wrap_rec_ct_len(base: &[u8]) -> Vec<u8> {
    let mut b = checked_base(base);
    put_u32(&mut b, WRAP_REC_LEN_AT, WRAP_CT_LEN + 1);
    b
}

/// The file stops one byte short of the bundle tag.
fn truncated_bundle_ct(base: &[u8]) -> Vec<u8> {
    let mut b = checked_base(base);
    b.pop();
    b
}

/// `bundle_ct_len` claims more than any file holds. On a 64-bit target the
/// `checked_add` in `decode` does not overflow, so this is the bounds check.
fn bundle_ct_len_exceeds_file(base: &[u8]) -> Vec<u8> {
    let mut b = checked_base(base);
    put_u32(&mut b, BUNDLE_CT_LEN_AT, u32::MAX);
    b
}

fn trailing_bytes(base: &[u8]) -> Vec<u8> {
    let mut b = checked_base(base);
    b.push(TRAILING_BYTE);
    b
}

pub fn cases() -> Vec<SeedCase> {
    let case = |token: RuleToken,
                shape: &'static str,
                variant: &'static str,
                plant: fn(&[u8]) -> Vec<u8>| SeedCase {
        target: "bundle_file",
        token,
        shape,
        variant,
        plant,
    };
    use RuleToken::{ContainerMalformed, UnsupportedVersion};
    vec![
        case(ContainerMalformed, "bad_magic", "BadMagic", bad_magic),
        case(
            ContainerMalformed,
            "wrong_file_kind",
            "UnsupportedFileKind",
            wrong_file_kind,
        ),
        case(
            ContainerMalformed,
            "truncated_header",
            "Truncated",
            truncated_header,
        ),
        case(
            ContainerMalformed,
            "wrap_pw_ct_len",
            "WrapLengthMismatch",
            wrap_pw_ct_len,
        ),
        case(
            ContainerMalformed,
            "wrap_rec_ct_len",
            "WrapLengthMismatch",
            wrap_rec_ct_len,
        ),
        case(
            ContainerMalformed,
            "truncated_bundle_ct",
            "Truncated",
            truncated_bundle_ct,
        ),
        case(
            ContainerMalformed,
            "bundle_ct_len_exceeds_file",
            "Truncated",
            bundle_ct_len_exceeds_file,
        ),
        case(
            ContainerMalformed,
            "trailing_bytes",
            "TrailingBytes",
            trailing_bytes,
        ),
        case(
            UnsupportedVersion,
            "format_version",
            "UnsupportedFormatVersion",
            unsupported_format_version,
        ),
    ]
}
