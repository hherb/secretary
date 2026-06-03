import { describe, it, expect, beforeEach } from 'vitest';
import { get } from 'svelte/store';
import { browseNav, openBlock, openRecord, back, resetBrowse, openContacts } from '../src/lib/browse';
import type { BlockSummaryDto, RecordDto } from '../src/lib/ipc';

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
});
