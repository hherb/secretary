//! `vault.toml` cleartext metadata (`docs/vault-format.md` §2).

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Serialize;

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

pub fn encode(v: &VaultToml) -> String {
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
    toml::to_string(&wire).expect("serializing primitive types cannot fail")
}

/// Format a 16-byte UUID as the RFC 4122 textual form: 8-4-4-4-12 hex groups.
fn format_uuid_canonical(bytes: &[u8; 16]) -> String {
    let h = bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
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
        .ok_or_else(|| VaultTomlError::MalformedToml("format_version missing".into()))?;
    // Saturate to u16::MAX so the error variant carries a meaningful value even
    // when the raw integer is out of range (e.g. 99999 → 65535 clearly signals
    // "out of range" to a reader). Same pattern for suite_id below.
    let format_version = u16::try_from(format_version).unwrap_or(u16::MAX);
    if format_version != 1 {
        return Err(VaultTomlError::UnsupportedFormatVersion(format_version));
    }

    let suite_id = table
        .get("suite_id")
        .and_then(Value::as_integer)
        .ok_or_else(|| VaultTomlError::MalformedToml("suite_id missing".into()))?;
    let suite_id = u16::try_from(suite_id).unwrap_or(u16::MAX);
    if suite_id != 1 {
        return Err(VaultTomlError::UnsupportedSuiteId(suite_id));
    }

    let vault_uuid_str = table
        .get("vault_uuid")
        .and_then(Value::as_str)
        .ok_or_else(|| VaultTomlError::MalformedToml("vault_uuid missing".into()))?;
    let vault_uuid = parse_uuid_canonical(vault_uuid_str).ok_or(VaultTomlError::InvalidUuid)?;

    let created_at_ms = table
        .get("created_at_ms")
        .and_then(Value::as_integer)
        .ok_or_else(|| VaultTomlError::MalformedToml("created_at_ms missing".into()))?
        as u64;

    // Strict [kdf] decode: every key must be known. Unknown keys are a hard
    // error here because misinterpreting KDF parameters would derive a wrong key
    // (§2 line 73).
    let kdf_table = table
        .get("kdf")
        .and_then(Value::as_table)
        .ok_or_else(|| VaultTomlError::MalformedToml("[kdf] missing".into()))?;

    const KNOWN_KDF_KEYS: &[&str] = &[
        "algorithm", "version", "memory_kib", "iterations", "parallelism", "salt_b64",
    ];
    for k in kdf_table.keys() {
        if !KNOWN_KDF_KEYS.contains(&k.as_str()) {
            return Err(VaultTomlError::UnknownKdfKey(k.clone()));
        }
    }

    let algorithm = kdf_table
        .get("algorithm")
        .and_then(Value::as_str)
        .ok_or_else(|| VaultTomlError::MalformedToml("kdf.algorithm missing".into()))?
        .to_string();
    if algorithm != "argon2id" {
        return Err(VaultTomlError::UnsupportedKdfAlgorithm(algorithm));
    }

    let version = kdf_table
        .get("version")
        .and_then(Value::as_str)
        .ok_or_else(|| VaultTomlError::MalformedToml("kdf.version missing".into()))?
        .to_string();
    if version != "1.3" {
        return Err(VaultTomlError::UnsupportedKdfVersion(version));
    }

    let memory_kib = kdf_table
        .get("memory_kib")
        .and_then(Value::as_integer)
        .ok_or_else(|| VaultTomlError::MalformedToml("kdf.memory_kib missing".into()))?
        as u32;
    let iterations = kdf_table
        .get("iterations")
        .and_then(Value::as_integer)
        .ok_or_else(|| VaultTomlError::MalformedToml("kdf.iterations missing".into()))?
        as u32;
    let parallelism = kdf_table
        .get("parallelism")
        .and_then(Value::as_integer)
        .ok_or_else(|| VaultTomlError::MalformedToml("kdf.parallelism missing".into()))?
        as u32;

    let salt_b64 = kdf_table
        .get("salt_b64")
        .and_then(Value::as_str)
        .ok_or_else(|| VaultTomlError::MalformedToml("kdf.salt_b64 missing".into()))?;
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
/// Returns `None` on any deviation from the expected 32 hex digits plus hyphens.
fn parse_uuid_canonical(s: &str) -> Option<[u8; 16]> {
    // Strip hyphens and require exactly 32 hex chars.
    let stripped: String = s.chars().filter(|c| *c != '-').collect();
    if stripped.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        let byte = u8::from_str_radix(&stripped[i * 2..i * 2 + 2], 16).ok()?;
        out[i] = byte;
    }
    Some(out)
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
        let s = encode(&v);
        let parsed = decode(&s).expect("decode");
        assert_eq!(parsed, v);
    }
}
