// Pure block-list helpers (D.1.9). No IPC / DOM — the IPC wrapper lives in
// ipc.ts. Mirrors the lib/recipients.ts pure-helper discipline.
import type { BlockSummaryDto } from './ipc';

/**
 * Order blocks for display: by block name, case-insensitive, with ties broken
 * deterministically by `blockUuidHex` so the list is stable across reloads.
 * Pure (returns a new array; does not mutate the input).
 */
export function sortBlocks(blocks: BlockSummaryDto[]): BlockSummaryDto[] {
  return [...blocks].sort((a, b) => {
    const byName = a.blockName.localeCompare(b.blockName, undefined, { sensitivity: 'base' });
    if (byName !== 0) return byName;
    return a.blockUuidHex.localeCompare(b.blockUuidHex);
  });
}
