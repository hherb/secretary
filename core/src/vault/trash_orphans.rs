//! The open-time sweep of trash files no `TrashEntry` names (#790,
//! `docs/vault-format.md` §7, "Open-time unreferenced-file sweep").
//!
//! A restore keeps its `trash/<uuid>.cbor.enc.<ts>` file (§7.1 step 5) so a
//! later conflict-copy merge can read its signed header clock (crypto-design
//! §11.6), and removes the `TrashEntry` that named it. Unless the block is
//! trashed again and then restored or purged, nothing removes that file, so
//! once the block is edited it holds an old version's ciphertext for good.
//!
//! The sweep removes such a file only when it is that case: the block is live
//! in the manifest, the live `vector_clock_summary` strictly dominates the
//! file's header clock (the block was edited after the version the file
//! holds), and `<ts>` is more than [`UNREFERENCED_TRASH_WINDOW_MS`] before the
//! manifest's signed `last_mod_ms`. "No entry names it" is relative to this
//! device's manifest, which may be stale: a peer's trash file can arrive
//! before the manifest that names it. That file's clock equals the live one
//! (trash does not tick it), or the block is not live here at all, so it is
//! kept. The suffix and the header are read unverified: a forged one can at
//! worst remove that one file, which the forger could delete anyway.
//!
//! The selection is pure; only [`remove_expired_unreferenced`] does I/O.

use std::collections::HashMap;
use std::path::Path;

use crate::unlock::vault_toml::parse_uuid_canonical;
use crate::vault::block::decode_block_file;
use crate::vault::conflict::{clock_relation, ClockRelation};
use crate::vault::manifest::Manifest;
use crate::vault::orchestrators::{BLOCK_FILE_EXTENSION, TRASH_SUBDIR};
use crate::vault::VectorClockEntry;

/// How long an unreferenced trash file is kept: 90 days. It is a fixed
/// protocol value, not the user's retention setting (nor its default): no
/// entry names the file, so it can never be restored, and the window only
/// gives every device time to merge (crypto-design §11.3) before §11.6 loses
/// the file's clock.
pub(crate) const UNREFERENCED_TRASH_WINDOW_MS: u64 = 90 * 24 * 60 * 60 * 1000;

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

/// The candidates in `names`, each with its block's live clock: trash files
/// in §7's grammar whose block is live in `manifest.blocks` (so no
/// `manifest.trash` entry names them, the two being disjoint) and whose
/// `<ts>` is more than `window_ms` before `now_ms`.
/// The age uses a saturating subtraction and an exclusive boundary, exactly
/// as retention's `expired_trash_indices` does for an entry. A candidate is
/// removed only if [`superseded_by_live`] also holds for its header clock.
#[must_use]
pub(crate) fn expired_unreferenced<'a>(
    names: &'a [String],
    manifest: &'a Manifest,
    window_ms: u64,
    now_ms: u64,
) -> Vec<(&'a str, &'a [VectorClockEntry])> {
    let live: HashMap<[u8; 16], &[VectorClockEntry]> = manifest
        .blocks
        .iter()
        .map(|b| (b.block_uuid, b.vector_clock_summary.as_slice()))
        .collect();
    names
        .iter()
        .filter_map(|name| {
            let (uuid, ts) = parse_trash_file_name(name)?;
            let clock = live.get(&uuid)?;
            (now_ms.saturating_sub(ts) > window_ms).then_some((name.as_str(), *clock))
        })
        .collect()
}

/// Whether the live block's clock strictly dominates the trash file's: the
/// block was edited after the version the file holds. An equal or concurrent
/// clock may be a peer's trash this device has not merged yet.
#[must_use]
pub(crate) fn superseded_by_live(
    file_clock: &[VectorClockEntry],
    live: &[VectorClockEntry],
) -> bool {
    clock_relation(file_clock, live) == ClockRelation::IncomingDominates
}

/// Remove every [`expired_unreferenced`] file under `folder`'s `trash/` whose
/// header clock is [`superseded_by_live`]. Best-effort like every open-time
/// sweep: an unreadable directory removes nothing, a file that cannot be read
/// or decoded is kept, and a failed removal is logged, never fatal. `manifest`
/// is the one just verified on disk, since a newer manifest may name a file
/// again.
pub(crate) fn remove_expired_unreferenced(
    folder: &Path,
    manifest: &Manifest,
    window_ms: u64,
    now_ms: u64,
) {
    let trash_dir = folder.join(TRASH_SUBDIR);
    let names = trash_file_names(&trash_dir);
    for (name, live) in expired_unreferenced(&names, manifest, window_ms, now_ms) {
        let path = trash_dir.join(name);
        let superseded = std::fs::read(&path)
            .ok()
            .and_then(|bytes| decode_block_file(&bytes).ok())
            .is_some_and(|file| superseded_by_live(&file.header.vector_clock, live));
        if !superseded {
            continue;
        }
        if let Err(e) = std::fs::remove_file(&path) {
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
    use crate::vault::manifest::{BlockEntry, KdfParamsRef, TrashEntry};
    use std::collections::BTreeMap;

    const UUID: [u8; 16] = [0xab; 16];
    const UUID_TEXT: &str = "abababab-abab-abab-abab-abababababab";
    const WINDOW: u64 = 100;

    fn clock(counter: u64) -> Vec<VectorClockEntry> {
        vec![VectorClockEntry {
            device_uuid: [0x05; 16],
            counter,
        }]
    }

    fn live(block_uuid: [u8; 16]) -> BlockEntry {
        BlockEntry {
            block_uuid,
            block_name: String::new(),
            fingerprint: [0u8; 32],
            recipients: Vec::new(),
            vector_clock_summary: clock(2),
            suite_id: crate::version::SUITE_ID,
            created_at_ms: 0,
            last_mod_ms: 0,
            unknown: BTreeMap::new(),
        }
    }

    fn manifest(blocks: Vec<BlockEntry>, trash: Vec<TrashEntry>) -> Manifest {
        Manifest {
            manifest_version: 1,
            vault_uuid: [0x01; 16],
            format_version: crate::version::FORMAT_VERSION,
            suite_id: crate::version::SUITE_ID,
            owner_user_uuid: [0x02; 16],
            vector_clock: Vec::new(),
            blocks,
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

    /// The vault after a restore of `UUID`: live, no entry.
    fn restored() -> Manifest {
        manifest(vec![live(UUID)], Vec::new())
    }

    fn entry(tombstoned_at_ms: u64) -> TrashEntry {
        TrashEntry {
            block_uuid: UUID,
            tombstoned_at_ms,
            tombstoned_by: [0x04; 16],
            fingerprint: None,
            purged_at_ms: None,
            unknown: BTreeMap::new(),
        }
    }

    fn name(ts: &str) -> String {
        format!("{UUID_TEXT}{BLOCK_FILE_EXTENSION}.{ts}")
    }

    fn selected<'a>(names: &'a [String], m: &'a Manifest, now_ms: u64) -> Vec<&'a str> {
        expired_unreferenced(names, m, WINDOW, now_ms)
            .into_iter()
            .map(|(n, _)| n)
            .collect()
    }

    #[test]
    fn the_window_is_ninety_days() {
        assert_eq!(UNREFERENCED_TRASH_WINDOW_MS, 7_776_000_000);
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
    fn an_unnamed_file_of_a_live_block_past_the_window_is_a_candidate() {
        let names = vec![name("10")];
        let m = restored();
        let got = expired_unreferenced(&names, &m, WINDOW, 10 + WINDOW + 1);
        assert_eq!(got, [(names[0].as_str(), clock(2).as_slice())]);
    }

    #[test]
    fn the_window_boundary_is_exclusive() {
        let names = vec![name("10")];
        assert!(selected(&names, &restored(), 10 + WINDOW).is_empty());
    }

    #[test]
    fn a_future_suffix_is_never_selected() {
        let names = vec![name("500")];
        assert!(selected(&names, &restored(), 10).is_empty());
    }

    #[test]
    fn a_file_of_a_block_not_live_here_is_never_selected() {
        // A peer's trash of a block this device has not seen, or a re-trash:
        // a manifest this device has not merged may name the file.
        let names = vec![name("10")];
        for m in [
            manifest(Vec::new(), Vec::new()),
            manifest(vec![live([0xcd; 16])], Vec::new()),
            manifest(Vec::new(), vec![entry(10)]),
            manifest(Vec::new(), vec![entry(50)]),
        ] {
            assert!(selected(&names, &m, u64::MAX).is_empty());
        }
    }

    #[test]
    fn only_a_strictly_dominated_file_clock_is_superseded() {
        let live = clock(2);
        assert!(superseded_by_live(&clock(1), &live));
        assert!(superseded_by_live(&[], &live));
        // Equal: a peer's trash not merged yet (trash does not tick the clock).
        assert!(!superseded_by_live(&clock(2), &live));
        assert!(!superseded_by_live(&clock(3), &live));
        let other_device = [VectorClockEntry {
            device_uuid: [0x06; 16],
            counter: 1,
        }];
        assert!(!superseded_by_live(&other_device, &live));
    }
}
