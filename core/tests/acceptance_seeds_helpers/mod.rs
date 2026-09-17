//! Committed seeds for the value-type ACCEPTANCE divergences (#669), and the
//! one table the generator and the label-binding check both read.
//!
//! **Why these exist.** A wrong-type sweep found 16 bodies that
//! `conformance.py` ACCEPTED and the Rust decoder rejected, across
//! `contact_card`, `vault_toml` and `manifest_body`. None was reachable from
//! any committed or runtime corpus input, which is why the differential
//! replay reported full agreement the whole time. Committing one body per
//! position makes CI compare both decoders on each of them, so the class
//! cannot silently reopen.
//!
//! **How this differs from `rule_token_seeds_helpers`, deliberately, twice:**
//!
//! 1. **It binds a Rust error VARIANT and the verdict, not a rule token.**
//!    `contact_card` and `vault_toml` have no token taxonomy yet (#641), so
//!    there is no token to bind; requiring one would pin a distinction those
//!    targets cannot make. `manifest_body` does have one, but the variant is
//!    strictly finer, so binding the variant everywhere keeps one contract.
//!
//! 2. **Its two-way census is scoped to `SEED_PREFIX`.**
//!    `rule_token_seeds.rs` claims every file whose name contains `__` in its
//!    targets' directories. `core/fuzz/seeds/manifest_body/` already holds 38
//!    seeds written by three other generators (`arraysort__`, `keyorder__`,
//!    `top__`/`block__`/`trash__`, `uniq__`), none of which censuses the
//!    directory. Copying that pattern verbatim would make this generator
//!    claim all 38 and fail. Only `valuetype__*` is owned here.
//!
//! **Why three substitutions for each manifest key.** A partial fix must red.
//! A bool-only guard leaves the `text` row accepted; a type check without the
//! length or range check leaves `short` / `negative` accepted. Each of the
//! three checks is pinned independently, rather than by one row any partial
//! fix would satisfy.

use std::path::PathBuf;

use ciborium::Value;

pub const SEED_PREFIX: &str = "valuetype__";

/// One committed seed.
pub struct AcceptanceCase {
    /// The replay target whose seed directory holds this file.
    pub target: &'static str,
    /// What was planted, as a file-name-safe label unique within `target`.
    pub shape: &'static str,
    /// The Rust error VARIANT the decoder must raise, as its `Debug` name.
    ///
    /// Finer than a verdict and finer than a token: it is what distinguishes
    /// `WrongType` from `InvalidByteLength` on the same field, which is the
    /// difference between "the type check runs" and "the length check runs".
    pub variant: &'static str,
    /// Build the seed from the target's accepting base.
    pub plant: fn(&[u8]) -> Vec<u8>,
}

impl AcceptanceCase {
    pub fn file_name(&self) -> String {
        let extension = if self.target == "vault_toml" { "toml" } else { "bin" };
        format!("{SEED_PREFIX}{}.{extension}", self.shape)
    }

    pub fn path(&self) -> PathBuf {
        seed_dir(self.target).join(self.file_name())
    }

    pub fn bytes(&self) -> Vec<u8> {
        (self.plant)(&base(self.target))
    }
}

/// `core/fuzz/seeds/<target>/`.
pub fn seed_dir(target: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz/seeds")
        .join(target)
}

/// The ACCEPTING input each target's seeds are planted into.
///
/// `manifest_body`'s is BUILT rather than read: the two keys this slice is
/// about are `Option` fields absent from every committed body, and a key that
/// nothing emits is a key no corpus can reach — which is exactly why they went
/// unvalidated. It is built through `decode_manifest` → `encode_manifest` so
/// the result is canonical by construction; hand-assembling a map would risk
/// planting a key-order fault and rejecting for the wrong reason.
pub fn base(target: &str) -> Vec<u8> {
    match target {
        "contact_card" => read_seed("contact_card", "with_sigs.cbor"),
        "vault_toml" => read_seed("vault_toml", "golden.toml"),
        "manifest_body" => manifest_base_with_optional_trash_keys(),
        other => panic!("no seed base for target {other}"),
    }
}

fn read_seed(target: &str, name: &str) -> Vec<u8> {
    let path = seed_dir(target).join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read seed base {}: {e}", path.display()))
}

/// A 32-byte digest and a nonzero timestamp: values a conformant reader
/// accepts, so the base is ACCEPTED and every seed differs from it by exactly
/// one planted fault.
const BASE_FINGERPRINT: [u8; 32] = [0x11; 32];
const BASE_PURGED_AT_MS: u64 = 7;

fn manifest_base_with_optional_trash_keys() -> Vec<u8> {
    use secretary_core::vault::manifest::{decode_manifest, encode_manifest};

    let raw = read_seed("manifest_body", "uniq__control__all_distinct.bin");
    let mut manifest = decode_manifest(&raw).expect("the committed control manifest decodes");
    let entry = manifest
        .trash
        .first_mut()
        .expect("the control manifest has a trash entry");
    entry.fingerprint = Some(BASE_FINGERPRINT);
    entry.purged_at_ms = Some(BASE_PURGED_AT_MS);
    encode_manifest(&manifest)
        .expect("a manifest carrying both optional trash keys encodes")
        .expose()
        .to_vec()
}

/// One step of a path into a CBOR value.
pub enum Step {
    Key(&'static str),
    Index(usize),
}

/// `bytes` with the value at `path` replaced by `new`, re-encoded.
///
/// Only a VALUE is ever replaced, never a key, so map entry order — and with
/// it the body's canonicality — is the base's own. The generator additionally
/// asserts that the base round-trips through this function byte for byte with
/// nothing substituted, so "one planted fault" is measured rather than
/// assumed.
pub fn sub_value(bytes: &[u8], path: &[Step], new: Value) -> Vec<u8> {
    let mut value: Value = ciborium::de::from_reader(bytes).expect("a seed base parses");
    set_at(&mut value, path, new);
    let mut out = Vec::new();
    ciborium::ser::into_writer(&value, &mut out).expect("a planted seed encodes");
    out
}

fn set_at(value: &mut Value, path: &[Step], new: Value) {
    match path {
        [] => *value = new,
        [Step::Key(key), rest @ ..] => {
            let Value::Map(pairs) = value else {
                panic!("path step {key:?} expects a map")
            };
            let slot = pairs
                .iter_mut()
                .find(|(k, _)| matches!(k, Value::Text(t) if t == key))
                .map(|(_, v)| v)
                .unwrap_or_else(|| panic!("no key {key:?} in this map"));
            set_at(slot, rest, new);
        }
        [Step::Index(index), rest @ ..] => {
            let Value::Array(items) = value else {
                panic!("path step [{index}] expects an array")
            };
            let slot = items
                .get_mut(*index)
                .unwrap_or_else(|| panic!("no element [{index}] in this array"));
            set_at(slot, rest, new);
        }
    }
}

/// `text` with the TOML assignment to `key` replaced by `key = literal`.
///
/// Matches the assignment's own key rather than a substring, so a value that
/// happens to spell another key's name cannot be rewritten by accident.
pub fn sub_toml(text: &[u8], key: &str, literal: &str) -> Vec<u8> {
    let text = std::str::from_utf8(text).expect("the vault.toml base is UTF-8");
    let mut out = String::new();
    let mut replaced = false;
    for line in text.lines() {
        let names_key = !replaced
            && line
                .split_once('=')
                .is_some_and(|(lhs, _)| lhs.trim() == key);
        if names_key {
            out.push_str(&format!("{key} = {literal}"));
            replaced = true;
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    assert!(replaced, "no assignment to {key:?} in the base vault.toml");
    out.into_bytes()
}

/// How the Rust decoder rejected a seed, or `None` if it accepted.
///
/// A copy of the decode → re-encode pipeline
/// `differential_replay_helpers::rust_decoder` runs for each target. Nothing
/// ties the two together — `rust_decoder` belongs to a test target gated on
/// the `differential-replay` feature, which this target does not import — so a
/// change to one arm must be mirrored in the other by hand. The same
/// arrangement `rule_token_seeds_helpers` documents.
pub fn rust_rejection(target: &str, bytes: &[u8]) -> Option<String> {
    use secretary_core::identity::card::ContactCard;
    use secretary_core::unlock::vault_toml;
    use secretary_core::vault::manifest::{decode_manifest, encode_manifest};

    match target {
        "contact_card" => ContactCard::from_canonical_cbor(bytes)
            .and_then(|c| c.to_canonical_cbor())
            .err()
            .map(|e| variant_name(&e)),
        "vault_toml" => match std::str::from_utf8(bytes) {
            Ok(text) => vault_toml::decode(text).err().map(|e| variant_name(&e)),
            Err(_) => Some("Utf8".to_owned()),
        },
        "manifest_body" => decode_manifest(bytes)
            .and_then(|m| encode_manifest(&m))
            .err()
            .map(|e| variant_name(&e)),
        other => panic!("no Rust decoder for target {other}"),
    }
}

/// The variant name a derived `Debug` prints first: `WrongType { .. }` and
/// `CborDecode(..)` give `WrongType` and `CborDecode`.
fn variant_name(error: &impl std::fmt::Debug) -> String {
    format!("{error:?}")
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect()
}

fn card_bool(key: &'static str) -> fn(&[u8]) -> Vec<u8> {
    match key {
        "card_version" => |b| sub_value(b, &[Step::Key("card_version")], Value::Bool(true)),
        "created_at" => |b| sub_value(b, &[Step::Key("created_at")], Value::Bool(true)),
        other => panic!("no card plant for {other}"),
    }
}

/// Every case, in a stable order.
pub fn all_cases() -> Vec<AcceptanceCase> {
    let mut cases = Vec::new();

    // `contact_card` — M1, `isinstance(x, int)` with no bool exclusion.
    // `card.rs`'s `take_u8` / `take_u64` match `Value::Integer` alone.
    for key in ["card_version", "created_at"] {
        cases.push(AcceptanceCase {
            target: "contact_card",
            shape: key,
            variant: "Malformed",
            plant: card_bool(key),
        });
    }

    // `vault_toml` — M1 again, through `toml::Value::as_integer`, which
    // returns `None` for a boolean and so reports the key as MISSING.
    macro_rules! toml_bool {
        ($key:literal) => {
            cases.push(AcceptanceCase {
                target: "vault_toml",
                shape: $key,
                variant: "MissingField",
                plant: |b| sub_toml(b, $key, "true"),
            })
        };
    }
    toml_bool!("format_version");
    toml_bool!("suite_id");
    toml_bool!("created_at_ms");
    toml_bool!("memory_kib");
    toml_bool!("iterations");
    toml_bool!("parallelism");

    // `manifest_body` — M2, the two keys that were validated by NOTHING.
    // Three substitutions each, so a partial fix reds: see the module doc.
    macro_rules! trash {
        ($shape:literal, $key:literal, $variant:literal, $value:expr) => {
            cases.push(AcceptanceCase {
                target: "manifest_body",
                shape: $shape,
                variant: $variant,
                plant: |b| {
                    sub_value(
                        b,
                        &[Step::Key("trash"), Step::Index(0), Step::Key($key)],
                        $value,
                    )
                },
            })
        };
    }
    trash!("trash_fingerprint_bool", "fingerprint", "WrongType", Value::Bool(true));
    trash!("trash_fingerprint_text", "fingerprint", "WrongType", Value::Text("x".into()));
    trash!(
        "trash_fingerprint_short",
        "fingerprint",
        "InvalidByteLength",
        Value::Bytes(vec![0])
    );
    trash!("trash_purged_bool", "purged_at_ms", "WrongType", Value::Bool(true));
    trash!("trash_purged_text", "purged_at_ms", "WrongType", Value::Text("x".into()));
    trash!(
        "trash_purged_negative",
        "purged_at_ms",
        "IntegerOutOfRange",
        Value::Integer((-1i64).into())
    );

    cases
}

/// The targets whose `valuetype__*` files this table owns.
pub const SEEDED_TARGETS: &[&str] = &["contact_card", "vault_toml", "manifest_body"];
