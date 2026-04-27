//! `vault.toml` cleartext metadata (`docs/vault-format.md` §2).
//!
//! This file holds non-secret bootstrap metadata for a Secretary vault: the
//! format version, suite identifier, vault UUID, creation timestamp, and the
//! Argon2id KDF parameters (including the salt). It is parsed at vault open
//! time to determine how to derive the Master KEK from the user's password.
//!
//! `decode` enforces v1's pinned values: `format_version = 1`, `suite_id = 1`,
//! `kdf.algorithm = "argon2id"`, `kdf.version = "1.3"`. Forward compatibility
//! per §2: unknown top-level keys are ignored, but unknown keys inside `[kdf]`
//! are an error (a misinterpreted KDF parameter would derive the wrong key).

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Serialize;

use crate::version::{FORMAT_VERSION, SUITE_ID};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultToml {
    pub format_version: u16,
    pub suite_id: u16,
    pub vault_uuid: [u8; 16],
    pub created_at_ms: u64,
    pub kdf: KdfSection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdfSection {
    pub algorithm: String,        // must be "argon2id"
    pub version: String,          // must be "1.3"
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt: [u8; 32],
}

#[derive(Debug, thiserror::Error)]
pub enum VaultTomlError {
    #[error("malformed TOML: {0}")]
    MalformedToml(String),
    /// A required field was absent from the parsed TOML.
    #[error("missing field: {0}")]
    MissingField(&'static str),
    /// A numeric field's value was outside the allowed range for its target type.
    #[error("field {field} value out of range")]
    FieldOutOfRange { field: &'static str },
    #[error("unknown key in [kdf] section: {0}")]
    UnknownKdfKey(String),
    #[error("unsupported format version: {0}")]
    UnsupportedFormatVersion(u16),
    #[error("unsupported suite id: {0}")]
    UnsupportedSuiteId(u16),
    #[error("unsupported KDF algorithm: {0}")]
    UnsupportedKdfAlgorithm(String),
    #[error("unsupported KDF version: {0}")]
    UnsupportedKdfVersion(String),
    #[error("invalid salt length: expected 32 bytes, got {got}")]
    InvalidSaltLength { got: usize },
    #[error("invalid UUID")]
    InvalidUuid,
    /// `created_at_ms` exceeds i64::MAX — TOML's signed 64-bit integer cannot
    /// represent the value. Practically unreachable (would require a timestamp
    /// past year 292 million) but the API accepts u64, so we surface it as a
    /// typed error rather than a panic.
    #[error("created_at_ms ({0}) exceeds i64::MAX")]
    TimestampOutOfRange(u64),
}

// Wire types used for TOML serialization only.
#[derive(Serialize)]
struct VaultTomlWire {
    format_version: u16,
    suite_id: u16,
    vault_uuid: String,
    created_at_ms: u64,
    kdf: KdfSectionWire,
}

#[derive(Serialize)]
struct KdfSectionWire {
    algorithm: String,
    version: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt_b64: String,
}

pub fn encode(v: &VaultToml) -> Result<String, VaultTomlError> {
    if v.created_at_ms > i64::MAX as u64 {
        return Err(VaultTomlError::TimestampOutOfRange(v.created_at_ms));
    }
    let wire = VaultTomlWire {
        format_version: v.format_version,
        suite_id: v.suite_id,
        vault_uuid: format_uuid_canonical(&v.vault_uuid),
        created_at_ms: v.created_at_ms,
        kdf: KdfSectionWire {
            algorithm: v.kdf.algorithm.clone(),
            version: v.kdf.version.clone(),
            memory_kib: v.kdf.memory_kib,
            iterations: v.kdf.iterations,
            parallelism: v.kdf.parallelism,
            salt_b64: STANDARD.encode(v.kdf.salt),
        },
    };
    toml::to_string(&wire).map_err(|e| VaultTomlError::MalformedToml(e.to_string()))
}

/// Format a 16-byte UUID as the RFC 4122 textual form: 8-4-4-4-12 hex groups.
fn format_uuid_canonical(bytes: &[u8; 16]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(36);
    for (i, b) in bytes.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            s.push('-');
        }
        write!(s, "{:02x}", b).expect("writing to String cannot fail");
    }
    s
}

/// Look up an integer field from a TOML table, returning `MissingField` if
/// absent or not an integer.
fn take_i64(table: &toml::value::Table, key: &'static str) -> Result<i64, VaultTomlError> {
    table
        .get(key)
        .and_then(toml::Value::as_integer)
        .ok_or(VaultTomlError::MissingField(key))
}

/// Look up a string field from a TOML table, returning `MissingField` if
/// absent or not a string.
fn take_str<'a>(table: &'a toml::value::Table, key: &'static str) -> Result<&'a str, VaultTomlError> {
    table
        .get(key)
        .and_then(toml::Value::as_str)
        .ok_or(VaultTomlError::MissingField(key))
}

pub fn decode(s: &str) -> Result<VaultToml, VaultTomlError> {
    use toml::Value;

    let value: Value = toml::from_str(s)
        .map_err(|e| VaultTomlError::MalformedToml(e.to_string()))?;
    let table = value
        .as_table()
        .ok_or_else(|| VaultTomlError::MalformedToml("expected table".into()))?;

    let format_version = table
        .get("format_version")
        .and_then(Value::as_integer)
        .ok_or(VaultTomlError::MissingField("format_version"))?;
    // Saturate to u16::MAX so the error variant carries a meaningful value even
    // when the raw integer is out of range (e.g. 99999 → 65535 clearly signals
    // "out of range" to a reader). Same pattern for suite_id below.
    let format_version = u16::try_from(format_version).unwrap_or(u16::MAX);
    if format_version != FORMAT_VERSION {
        return Err(VaultTomlError::UnsupportedFormatVersion(format_version));
    }

    let suite_id = table
        .get("suite_id")
        .and_then(Value::as_integer)
        .ok_or(VaultTomlError::MissingField("suite_id"))?;
    let suite_id = u16::try_from(suite_id).unwrap_or(u16::MAX);
    if suite_id != SUITE_ID {
        return Err(VaultTomlError::UnsupportedSuiteId(suite_id));
    }

    let vault_uuid_str = take_str(table, "vault_uuid")?;
    let vault_uuid = parse_uuid_canonical(vault_uuid_str).ok_or(VaultTomlError::InvalidUuid)?;

    let created_at_ms = take_i64(table, "created_at_ms")?;
    let created_at_ms = u64::try_from(created_at_ms)
        .map_err(|_| VaultTomlError::FieldOutOfRange { field: "created_at_ms" })?;

    // Strict [kdf] decode: every key must be known. Unknown keys are a hard
    // error here because misinterpreting KDF parameters would derive a wrong key
    // (§2 line 73).
    let kdf_table = table
        .get("kdf")
        .and_then(Value::as_table)
        .ok_or(VaultTomlError::MissingField("kdf"))?;

    const KNOWN_KDF_KEYS: &[&str] = &[
        "algorithm", "version", "memory_kib", "iterations", "parallelism", "salt_b64",
    ];
    for k in kdf_table.keys() {
        if !KNOWN_KDF_KEYS.contains(&k.as_str()) {
            return Err(VaultTomlError::UnknownKdfKey(k.clone()));
        }
    }

    let algorithm = take_str(kdf_table, "algorithm")?.to_string();
    if algorithm != "argon2id" {
        return Err(VaultTomlError::UnsupportedKdfAlgorithm(algorithm));
    }

    let version = take_str(kdf_table, "version")?.to_string();
    if version != "1.3" {
        return Err(VaultTomlError::UnsupportedKdfVersion(version));
    }

    let memory_kib = take_i64(kdf_table, "memory_kib")?;
    let memory_kib = u32::try_from(memory_kib)
        .map_err(|_| VaultTomlError::FieldOutOfRange { field: "kdf.memory_kib" })?;

    let iterations = take_i64(kdf_table, "iterations")?;
    let iterations = u32::try_from(iterations)
        .map_err(|_| VaultTomlError::FieldOutOfRange { field: "kdf.iterations" })?;

    let parallelism = take_i64(kdf_table, "parallelism")?;
    let parallelism = u32::try_from(parallelism)
        .map_err(|_| VaultTomlError::FieldOutOfRange { field: "kdf.parallelism" })?;

    let salt_b64 = take_str(kdf_table, "salt_b64")?;
    let salt_vec = STANDARD
        .decode(salt_b64)
        .map_err(|e| VaultTomlError::MalformedToml(format!("salt_b64: {e}")))?;
    let salt: [u8; 32] = salt_vec
        .as_slice()
        .try_into()
        .map_err(|_| VaultTomlError::InvalidSaltLength { got: salt_vec.len() })?;

    Ok(VaultToml {
        format_version,
        suite_id,
        vault_uuid,
        created_at_ms,
        kdf: KdfSection {
            algorithm,
            version,
            memory_kib,
            iterations,
            parallelism,
            salt,
        },
    })
}

/// Parse the RFC 4122 textual UUID form ("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx").
///
/// §2's "canonical 8-4-4-4-12 hyphenated lowercase hex" form is enforced
/// strictly: exactly 36 bytes, hyphens at indices 8/13/18/23, every other
/// byte must be a lowercase hex digit (`0-9` or `a-f`). Uppercase and
/// non-hyphenated forms are rejected to keep the canonical form symmetric
/// with the encoder, which emits lowercase via `{:02x}`.
fn parse_uuid_canonical(s: &str) -> Option<[u8; 16]> {
    let b = s.as_bytes();
    if b.len() != 36 {
        return None;
    }
    for i in [8usize, 13, 18, 23] {
        if b[i] != b'-' {
            return None;
        }
    }
    // Every non-hyphen byte must be lowercase hex (0-9, a-f).
    for (i, &c) in b.iter().enumerate() {
        if i == 8 || i == 13 || i == 18 || i == 23 {
            continue;
        }
        if !c.is_ascii_digit() && !(b'a'..=b'f').contains(&c) {
            return None;
        }
    }
    // Walk the five hex groups directly; no intermediate Vec needed.
    // Pre-validation above guarantees lengths and character validity.
    let groups: [&[u8]; 5] = [&b[0..8], &b[9..13], &b[14..18], &b[19..23], &b[24..36]];
    let mut out = [0u8; 16];
    let mut byte_idx = 0;
    for group in &groups {
        for pair in group.chunks_exact(2) {
            out[byte_idx] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
            byte_idx += 1;
        }
    }
    Some(out)
}

/// Convert a pre-validated lowercase hex byte to its nibble value.
#[inline]
fn hex_nibble(c: u8) -> u8 {
    if c.is_ascii_digit() { c - b'0' } else { c - b'a' + 10 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> VaultToml {
        VaultToml {
            format_version: 1,
            suite_id: 1,
            vault_uuid: [0xAB; 16],
            created_at_ms: 1_714_060_800_000,
            kdf: KdfSection {
                algorithm: "argon2id".to_string(),
                version: "1.3".to_string(),
                memory_kib: 262144,
                iterations: 3,
                parallelism: 1,
                salt: [0xCD; 32],
            },
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let v = sample();
        let s = encode(&v).expect("encode");
        let parsed = decode(&s).expect("decode");
        assert_eq!(parsed, v);
    }

    #[test]
    fn decode_ignores_unknown_top_level_key() {
        // Insert the unknown key before [kdf] so TOML parses it as a top-level
        // entry; appending after [kdf] would make it a kdf key (§2: unknown
        // top-level keys are ignored, unknown kdf keys are errors).
        let s = encode(&sample()).expect("encode").replacen("[kdf]\n", "future_key = \"some value\"\n[kdf]\n", 1);
        let parsed = decode(&s).expect("unknown top-level key must be ignored");
        assert_eq!(parsed, sample());
    }

    #[test]
    fn decode_rejects_unknown_kdf_key() {
        // Insert rogue key directly after [kdf] header so TOML parses it into
        // the kdf table regardless of section ordering.
        let s = encode(&sample()).expect("encode").replacen("[kdf]\n", "[kdf]\nrogue_param = 42\n", 1);
        let err = decode(&s).unwrap_err();
        assert!(matches!(err, VaultTomlError::UnknownKdfKey(ref k) if k == "rogue_param"));
    }

    #[test]
    fn decode_rejects_unsupported_format_version() {
        let s = encode(&sample()).expect("encode").replace("format_version = 1", "format_version = 2");
        let err = decode(&s).unwrap_err();
        assert!(matches!(err, VaultTomlError::UnsupportedFormatVersion(2)));
    }

    #[test]
    fn decode_rejects_unsupported_suite_id() {
        let s = encode(&sample()).expect("encode").replace("suite_id = 1", "suite_id = 2");
        let err = decode(&s).unwrap_err();
        assert!(matches!(err, VaultTomlError::UnsupportedSuiteId(2)));
    }

    #[test]
    fn decode_rejects_wrong_kdf_algorithm() {
        let s = encode(&sample()).expect("encode").replace("algorithm = \"argon2id\"", "algorithm = \"scrypt\"");
        let err = decode(&s).unwrap_err();
        assert!(matches!(err, VaultTomlError::UnsupportedKdfAlgorithm(ref s) if s == "scrypt"));
    }

    #[test]
    fn decode_rejects_wrong_kdf_version() {
        let s = encode(&sample()).expect("encode").replace("version = \"1.3\"", "version = \"1.0\"");
        let err = decode(&s).unwrap_err();
        assert!(matches!(err, VaultTomlError::UnsupportedKdfVersion(ref s) if s == "1.0"));
    }

    #[test]
    fn decode_rejects_short_salt() {
        let v = sample();
        let s = encode(&v).expect("encode");
        let short_b64 = STANDARD.encode([0u8; 16]);
        let original_b64 = STANDARD.encode([0xCDu8; 32]);
        let s = s.replace(&original_b64, &short_b64);
        let err = decode(&s).unwrap_err();
        assert!(matches!(err, VaultTomlError::InvalidSaltLength { got: 16 }));
    }

    #[test]
    fn decode_rejects_invalid_salt_b64() {
        let s = encode(&sample()).expect("encode").replace(
            &STANDARD.encode([0xCDu8; 32]),
            "not!valid!base64!!!",
        );
        let err = decode(&s).unwrap_err();
        assert!(matches!(err, VaultTomlError::MalformedToml(ref m) if m.starts_with("salt_b64:")));
    }

    #[test]
    fn decode_rejects_uppercase_uuid() {
        let s = encode(&sample()).expect("encode").replace(
            "abababab-abab-abab-abab-abababababab",
            "ABABABAB-ABAB-ABAB-ABAB-ABABABABABAB",
        );
        let err = decode(&s).unwrap_err();
        assert!(matches!(err, VaultTomlError::InvalidUuid));
    }

    #[test]
    fn decode_rejects_uuid_without_hyphens() {
        let s = encode(&sample()).expect("encode").replace(
            "abababab-abab-abab-abab-abababababab",
            "abababababababababababababababababab",
        );
        let err = decode(&s).unwrap_err();
        assert!(matches!(err, VaultTomlError::InvalidUuid));
    }

    #[test]
    fn decode_rejects_uuid_with_wrong_grouping() {
        let s = encode(&sample()).expect("encode").replace(
            "abababab-abab-abab-abab-abababababab",
            "abab-abababab-abab-abab-abababababab",
        );
        let err = decode(&s).unwrap_err();
        assert!(matches!(err, VaultTomlError::InvalidUuid));
    }

    #[test]
    fn encode_rejects_timestamp_out_of_range() {
        let mut v = sample();
        v.created_at_ms = (i64::MAX as u64) + 1;
        let err = encode(&v).unwrap_err();
        assert!(matches!(err, VaultTomlError::TimestampOutOfRange(t) if t == (i64::MAX as u64) + 1));
    }
}
