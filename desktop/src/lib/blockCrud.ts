// Pure pre-check guards for the block-CRUD UI. The Rust commands enforce the
// same rules authoritatively (defense in depth); these let the dialog/picker
// reject bad input WITHOUT an IPC round-trip and stay open. Keep them pure.

/** True when a block name is empty or whitespace-only (a UI policy: the
 *  FFI/spec permit empty names, but the desktop UI rejects them for parity
 *  with Android/iOS and usability). */
export function isBlankName(name: string): boolean {
  return name.trim().length === 0;
}

/** True when source and target block UUIDs are identical (a same-block move
 *  is a no-op the bridge does not guard against). */
export function isSameBlock(sourceBlockUuidHex: string, targetBlockUuidHex: string): boolean {
  return sourceBlockUuidHex === targetBlockUuidHex;
}
