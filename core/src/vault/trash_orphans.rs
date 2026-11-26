//! The open-time sweep of trash files no `TrashEntry` names (#790,
//! `docs/vault-format.md` §7, "Open-time unreferenced-file sweep").
//!
//! A restore keeps its `trash/<uuid>.cbor.enc.<ts>` file (§7.1 step 5) so a
//! later conflict-copy merge can read its signed header clock (crypto-design
//! §11.6), and removes the `TrashEntry` that named it. Nothing keyed on trash
//! entries ever reaches such a file again, so once the block is edited it would
//! hold an old version's ciphertext for good. The sweep removes it once `<ts>`
//! is more than [`UNREFERENCED_TRASH_WINDOW_MS`] before the manifest's signed
//! `last_mod_ms`. The suffix is unauthenticated, but deleting a file no entry
//! names cannot orphan a live block or undo a purge: a planted suffix can at
//! worst remove that one file early.
//!
//! The selection is pure; only [`remove_expired_unreferenced`] does I/O.

use std::collections::HashSet;
use std::path::Path;

use crate::unlock::vault_toml::parse_uuid_canonical;
use crate::vault::manifest::Manifest;
use crate::vault::orchestrators::{BLOCK_FILE_EXTENSION, TRASH_SUBDIR};
use crate::vault::retention::DEFAULT_RETENTION_WINDOW_MS;

/// How long an unreferenced trash file is kept. It is a fixed protocol value,
/// not the user's retention setting: no entry names the file, so it can never
/// be restored, and the window only gives every device time to merge
/// (crypto-design §11.3) before §11.6 loses the file's clock.
pub(crate) const UNREFERENCED_TRASH_WINDOW_MS: u64 = DEFAULT_RETENTION_WINDOW_MS;

/// Length of a hyphenated UUID, the first field of a trash file name.
const HYPHENATED_UUID_LEN: usize = 36;

/// The `(block_uuid, <unix-millis>)` a trash file name carries, if it follows
/// §7's grammar `<uuid-hyphenated>.cbor.enc.<unix-millis>`: a canonical
/// lowercase UUID and a canonical decimal `u64` (no sign, no leading zero,
/// as §7.1 step 1 requires). Any other name is `None`.
#[must_use]
pub(crate) fn parse_trash_file_name(name: &str) -> Option<([u8; 16], u64)> {
    let uuid = parse_uuid_canonical(name.get(..HYPHENATED_UUID_LEN)?)?;
    let suffix = name
        .get(HYPHENATED_UUID_LEN..)?
        .strip_prefix(BLOCK_FILE_EXTENSION)?
        .strip_prefix('.')?;
    let ts: u64 = suffix.parse().ok()?;
    (ts.to_string() == suffix).then_some((uuid, ts))
}

/// The names in `names` to remove: trash files in §7's grammar that no
/// `manifest.trash` entry names (same `block_uuid` and `tombstoned_at_ms`,
/// purged or not), whose `<ts>` is more than `window_ms` before `now_ms`.
/// The age uses a saturating subtraction and an exclusive boundary, exactly
/// as retention's `expired_trash_indices` does for an entry.
#[must_use]
pub(crate) fn expired_unreferenced<'a>(
    names: &'a [String],
    manifest: &Manifest,
    window_ms: u64,
    now_ms: u64,
) -> Vec<&'a str> {
    let named: HashSet<([u8; 16], u64)> = manifest
        .trash
        .iter()
        .map(|t| (t.block_uuid, t.tombstoned_at_ms))
        .collect();
    names
        .iter()
        .filter(|name| {
            parse_trash_file_name(name).is_some_and(|key| {
                !named.contains(&key) && now_ms.saturating_sub(key.1) > window_ms
            })
        })
        .map(String::as_str)
        .collect()
}

/// Remove every [`expired_unreferenced`] file under `folder`'s `trash/`.
/// Best-effort like every open-time sweep: an unreadable directory removes
/// nothing, and a failed removal is logged, never fatal. `manifest` is the one
/// just verified on disk, since a newer manifest may name a file again.
pub(crate) fn remove_expired_unreferenced(
    folder: &Path,
    manifest: &Manifest,
    window_ms: u64,
    now_ms: u64,
) {
    let trash_dir = folder.join(TRASH_SUBDIR);
    let names = trash_file_names(&trash_dir);
    for name in expired_unreferenced(&names, manifest, window_ms, now_ms) {
        if let Err(e) = std::fs::remove_file(trash_dir.join(name)) {
            tracing::warn!(
                file = %name,
                error = %e,
                "failed to remove unreferenced trash file; it stays until the next open"
            );
        }
    }
}

/// The UTF-8 file names directly under `trash_dir`; empty if it cannot be
/// read (a vault with no `trash/` yet).
fn trash_file_names(trash_dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(trash_dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::manifest::{KdfParamsRef, TrashEntry};
    use std::collections::BTreeMap;

    const UUID: [u8; 16] = [0xab; 16];
    const UUID_TEXT: &str = "abababab-abab-abab-abab-abababababab";
    const WINDOW: u64 = 100;

    fn manifest_with_trash(trash: Vec<TrashEntry>) -> Manifest {
        Manifest {
            manifest_version: 1,
            vault_uuid: [0x01; 16],
            format_version: crate::version::FORMAT_VERSION,
            suite_id: crate::version::SUITE_ID,
            owner_user_uuid: [0x02; 16],
            vector_clock: Vec::new(),
            blocks: Vec::new(),
            trash,
            kdf_params: KdfParamsRef {
                memory_kib: 262_144,
                iterations: 3,
                parallelism: 1,
                salt: [0x03; 32],
            },
            unknown: BTreeMap::new(),
        }
    }

    fn entry(tombstoned_at_ms: u64, purged_at_ms: Option<u64>) -> TrashEntry {
        TrashEntry {
            block_uuid: UUID,
            tombstoned_at_ms,
            tombstoned_by: [0x04; 16],
            fingerprint: None,
            purged_at_ms,
            unknown: BTreeMap::new(),
        }
    }

    fn name(ts: &str) -> String {
        format!("{UUID_TEXT}{BLOCK_FILE_EXTENSION}.{ts}")
    }

    #[test]
    fn a_name_in_the_grammar_parses() {
        assert_eq!(parse_trash_file_name(&name("0")), Some((UUID, 0)));
        assert_eq!(parse_trash_file_name(&name("1234")), Some((UUID, 1234)));
    }

    #[test]
    fn a_name_outside_the_grammar_does_not_parse() {
        for bad in [
            name("007"),
            name("+7"),
            name(""),
            name("18446744073709551616"),
            name("12a"),
            format!("{UUID_TEXT}{BLOCK_FILE_EXTENSION}"),
            format!("{}{BLOCK_FILE_EXTENSION}.5", UUID_TEXT.to_uppercase()),
            format!("{UUID_TEXT}.cbor.5"),
            "notes.txt".to_string(),
            String::new(),
        ] {
            assert_eq!(parse_trash_file_name(&bad), None, "{bad:?}");
        }
    }

    #[test]
    fn an_unnamed_file_past_the_window_is_selected() {
        let names = vec![name("10")];
        let m = manifest_with_trash(Vec::new());
        assert_eq!(
            expired_unreferenced(&names, &m, WINDOW, 10 + WINDOW + 1),
            [names[0].as_str()]
        );
    }

    #[test]
    fn the_window_boundary_is_exclusive() {
        let names = vec![name("10")];
        let m = manifest_with_trash(Vec::new());
        assert!(expired_unreferenced(&names, &m, WINDOW, 10 + WINDOW).is_empty());
    }

    #[test]
    fn a_future_suffix_is_never_selected() {
        let names = vec![name("500")];
        let m = manifest_with_trash(Vec::new());
        assert!(expired_unreferenced(&names, &m, WINDOW, 10).is_empty());
    }

    #[test]
    fn a_file_an_entry_names_is_never_selected_purged_or_not() {
        let names = vec![name("10")];
        for purged in [None, Some(20)] {
            let m = manifest_with_trash(vec![entry(10, purged)]);
            assert!(expired_unreferenced(&names, &m, WINDOW, u64::MAX).is_empty());
        }
    }

    #[test]
    fn an_entry_for_another_stamp_does_not_name_the_file() {
        // Trashed at 10, restored, trashed again at 50: the first file is unnamed.
        let names = vec![name("10"), name("50")];
        let m = manifest_with_trash(vec![entry(50, None)]);
        assert_eq!(
            expired_unreferenced(&names, &m, WINDOW, u64::MAX),
            [names[0].as_str()]
        );
    }
}
