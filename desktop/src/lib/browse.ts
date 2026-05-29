// Browse-nav store for D.1.2's stacked-page navigation (spec §7). A
// discriminated union tracks which level the user is viewing within the
// unlocked Vault. Transition helpers are the only mutation path (mirrors
// stores.ts discipline — components never call `.set()` directly).
//
// Reset to `blocks` on vault-locked (App.svelte wires this in Task 6) so a
// revealed drill-down never survives a lock.

import { writable, type Readable } from 'svelte/store';
import type { BlockSummaryDto, RecordDto } from './ipc';

export type BrowseNav =
  | { level: 'blocks' }
  | { level: 'records'; block: BlockSummaryDto }
  | { level: 'fields'; block: BlockSummaryDto; record: RecordDto };

const store = writable<BrowseNav>({ level: 'blocks' });

export const browseNav: Readable<BrowseNav> = { subscribe: store.subscribe };

export function openBlock(block: BlockSummaryDto): void {
  store.set({ level: 'records', block });
}

export function openRecord(record: RecordDto): void {
  store.update((s) =>
    s.level === 'records' ? { level: 'fields', block: s.block, record } : s
  );
}

export function back(): void {
  store.update((s) => {
    if (s.level === 'fields') return { level: 'records', block: s.block };
    if (s.level === 'records') return { level: 'blocks' };
    return s;
  });
}

export function resetBrowse(): void {
  store.set({ level: 'blocks' });
}
