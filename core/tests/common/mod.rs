//! Shared helpers for integration tests — KAT loader and hex utilities.
//!
//! Each `tests/*.rs` is its own crate; this module is included via
//! `mod common;` and is *not* picked up as a separate test target by Cargo
//! (the `common/mod.rs` layout is the conventional way to share test code).
//!
//! The on-disk JSON KAT files in `tests/data/*.json` are the
//! cross-language conformance contract from `docs/crypto-design.md` §15.
//! Each KAT family has a typed `*Kat` struct here; tests load with
//! [`load_kat`].

#![allow(dead_code)] // not every test consumes every helper.

use std::fs;
use std::path::PathBuf;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer};

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

/// Decode a hex string to `Vec<u8>`. Lowercase or uppercase; rejects
/// odd-length or non-hex characters with a descriptive error.
pub fn hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err(format!("odd-length hex string ({} chars)", s.len()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        out.push((nib(chunk[0])? << 4) | nib(chunk[1])?);
    }
    Ok(out)
}

fn nib(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        other => Err(format!("non-hex character: {:#04x}", other)),
    }
}

/// Serde adapter for hex-encoded byte strings. Use as
/// `#[serde(deserialize_with = "de_hex")]` on `Vec<u8>` fields.
pub fn de_hex<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let s: String = Deserialize::deserialize(d)?;
    hex(&s).map_err(serde::de::Error::custom)
}

/// Serde adapter for hex-encoded byte strings of fixed length `N`.
pub fn de_hex_array<'de, const N: usize, D: Deserializer<'de>>(d: D) -> Result<[u8; N], D::Error> {
    let v = de_hex(d)?;
    v.try_into().map_err(|v: Vec<u8>| {
        serde::de::Error::custom(format!("expected {} bytes, got {}", N, v.len()))
    })
}

// ---------------------------------------------------------------------------
// File loading
// ---------------------------------------------------------------------------

/// Path to a file under `core/tests/data/`. Resolved relative to
/// `CARGO_MANIFEST_DIR` so the tests are reproducible regardless of which
/// directory `cargo test` is invoked from.
pub fn data_path(filename: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("data");
    p.push(filename);
    p
}

/// Load and deserialize a JSON KAT file from `tests/data/`. Panics with
/// an explicit message if the file is missing or malformed — KAT loading
/// is part of the test contract, not something a test can recover from.
pub fn load_kat<T: DeserializeOwned>(filename: &str) -> T {
    let path = data_path(filename);
    let bytes = fs::read(&path)
        .unwrap_or_else(|e| panic!("failed to read KAT file {}: {}", path.display(), e));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("failed to parse KAT file {}: {}", path.display(), e))
}
