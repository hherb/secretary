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
  | { level: 'fields'; block: BlockSummaryDto; record: RecordDto }
  | { level: 'newBlock' }
  | { level: 'newRecord'; block: BlockSummaryDto }
  | { level: 'editRecord'; block: BlockSummaryDto; record: RecordDto }
  | { level: 'trash' }
  | { level: 'contacts' };

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

export function openNewBlock(): void {
  store.set({ level: 'newBlock' });
}

export function openNewRecord(block: BlockSummaryDto): void {
  store.set({ level: 'newRecord', block });
}

export function openEditRecord(block: BlockSummaryDto, record: RecordDto): void {
  store.set({ level: 'editRecord', block, record });
}

export function openTrash(): void {
  store.set({ level: 'trash' });
}

export function openContacts(): void {
  store.set({ level: 'contacts' });
}

export function back(): void {
  store.update((s) => {
    if (s.level === 'editRecord') return { level: 'fields', block: s.block, record: s.record };
    if (s.level === 'newRecord') return { level: 'records', block: s.block };
    if (s.level === 'newBlock') return { level: 'blocks' };
    if (s.level === 'fields') return { level: 'records', block: s.block };
    if (s.level === 'records') return { level: 'blocks' };
    if (s.level === 'trash') return { level: 'blocks' };
    if (s.level === 'contacts') return { level: 'blocks' };
    return s;
  });
}

export function resetBrowse(): void {
  store.set({ level: 'blocks' });
}
