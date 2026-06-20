import { describe, it, expect, beforeEach } from 'vitest';
import { get } from 'svelte/store';
import { browseNav, openBlock, openRecord, openRenameBlock, back, resetBrowse, openContacts, shouldPopOnEscape } from '../src/lib/browse';
import type { BlockSummaryDto, RecordDto } from '../src/lib/ipc';
import type { BrowseNav } from '../src/lib/browse';

const BLOCK: BlockSummaryDto = { blockUuidHex: 'ab', blockName: 'B', createdAtMs: 1, lastModifiedMs: 2 };
const RECORD: RecordDto = { recordUuidHex: 'cd', recordType: 'login', tags: [], createdAtMs: 1, lastModMs: 2, fieldCount: 0, fields: [] };

describe('browse-nav store', () => {
  beforeEach(() => resetBrowse());

  it('starts at blocks level', () => {
    expect(get(browseNav).level).toBe('blocks');
  });

  it('openBlock → records level carries the block', () => {
    openBlock(BLOCK);
    const s = get(browseNav);
    expect(s.level).toBe('records');
    if (s.level === 'records') expect(s.block.blockUuidHex).toBe('ab');
  });

  it('openRecord → fields level carries block + record', () => {
    openBlock(BLOCK);
    openRecord(RECORD);
    const s = get(browseNav);
    expect(s.level).toBe('fields');
    if (s.level === 'fields') expect(s.record.recordUuidHex).toBe('cd');
  });

  it('back pops one level: fields → records → blocks', () => {
    openBlock(BLOCK); openRecord(RECORD);
    back();
    expect(get(browseNav).level).toBe('records');
    back();
    expect(get(browseNav).level).toBe('blocks');
    back();
    expect(get(browseNav).level).toBe('blocks');
  });

  it('resetBrowse returns to blocks from any level', () => {
    openBlock(BLOCK); openRecord(RECORD);
    resetBrowse();
    expect(get(browseNav).level).toBe('blocks');
  });

  it('openContacts sets level to contacts', () => {
    openContacts();
    expect(get(browseNav).level).toBe('contacts');
  });

  it('back from contacts returns to blocks', () => {
    openContacts();
    back();
    expect(get(browseNav).level).toBe('blocks');
  });

  it('openRenameBlock sets renameBlock level and carries the block', () => {
    openRenameBlock(BLOCK);
    const s = get(browseNav);
    expect(s.level).toBe('renameBlock');
    if (s.level === 'renameBlock') expect(s.block.blockUuidHex).toBe('ab');
  });

  it('back from renameBlock returns to blocks', () => {
    openRenameBlock(BLOCK);
    back();
    expect(get(browseNav).level).toBe('blocks');
  });
});

// #164 - Esc pops one browse level, but only at the read-only browse levels
// and only when nothing else owns the Escape key. shouldPopOnEscape is the
// pure decision; Vault wires it to a window keydown. This truth table pins
// every guard so the wiring stays a thin adapter.
const LEVELS: BrowseNav['level'][] = [
  'blocks', 'records', 'fields', 'newBlock',
  'newRecord', 'editRecord', 'renameBlock', 'trash', 'contacts'
];

describe('shouldPopOnEscape', () => {
  it('pops only at records and fields when no dialog/text-field owns Esc', () => {
    for (const level of LEVELS) {
      const expected = level === 'records' || level === 'fields';
      expect(shouldPopOnEscape(level, false, false)).toBe(expected);
    }
  });

  it('never pops while a dialog is open (dialog owns Esc)', () => {
    expect(shouldPopOnEscape('records', true, false)).toBe(false);
    expect(shouldPopOnEscape('fields', true, false)).toBe(false);
  });

  it('never pops while focus is in a form control', () => {
    expect(shouldPopOnEscape('records', false, true)).toBe(false);
    expect(shouldPopOnEscape('fields', false, true)).toBe(false);
  });
});
