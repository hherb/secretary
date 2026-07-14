// Pure pre-check guards for the block-CRUD UI. The Rust commands enforce the
// same rules authoritatively (defense in depth); these let the dialog/picker
// reject bad input WITHOUT an IPC round-trip and stay open. Keep them pure.

/** True when a block name is empty or whitespace-only (a UI policy: the
 *  FFI/spec permit empty names, but the desktop UI rejects them for parity
 *  with Android/iOS and usability). */
export function isBlankName(name: string): boolean {
  return name.trim().length === 0;
}

/** True when source and target block UUIDs are the same (a same-block move is
 *  a no-op the bridge does not guard against). ASCII-case-insensitive because
 *  hex is: `"AB"` and `"ab"` decode to the same UUID. Mirrors the authoritative
 *  Rust guard in `move_record_impl`. */
export function isSameBlock(sourceBlockUuidHex: string, targetBlockUuidHex: string): boolean {
  return sourceBlockUuidHex.toLowerCase() === targetBlockUuidHex.toLowerCase();
}

/** Minimum live-block count for a record move to have a destination: the
 *  record's own block plus at least one distinct target block. */
const MIN_BLOCKS_TO_MOVE = 2;

/** True when at least one block OTHER than the record's own exists, so a move
 *  has a real destination. `blockCount` is the manifest's live-block count —
 *  the same set `MoveTargetPicker` enumerates (minus the source block). Below
 *  the threshold the Move affordance can only dead-end, so it is hidden.
 *
 *  Correctness depends on `blockCount` and `MoveTargetPicker`'s `listBlocks()`
 *  projecting the SAME set (both derive from `manifest.blocks` today). If they
 *  ever diverge, mind the direction: `blockCount` UNDER-counting real targets
 *  (fewer than `listBlocks()` returns) would wrongly HIDE Move while a valid
 *  destination exists — a lost affordance, worse than the benign over-count
 *  case where the button shows only to hit the picker's empty state. Keep the
 *  two projections identical. */
export function hasMoveTargets(blockCount: number): boolean {
  return blockCount >= MIN_BLOCKS_TO_MOVE;
}
