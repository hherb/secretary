import { describe, it, expect, beforeEach } from 'vitest';
import { get } from 'svelte/store';
import { browseNav, openBlock, openNewBlock, openNewRecord, openEditRecord, back, resetBrowse } from '../src/lib/browse';
import type { BlockSummaryDto, RecordDto } from '../src/lib/ipc';

const BLOCK: BlockSummaryDto = { blockUuidHex: 'ab', blockName: 'B', createdAtMs: 1, lastModifiedMs: 1 };
const REC: RecordDto = { recordUuidHex: 'cd', recordType: 'login', tags: [], createdAtMs: 1, lastModMs: 1, fieldCount: 0, fields: [] };

describe('browse edit transitions', () => {
  beforeEach(() => resetBrowse());

  it('openNewBlock from blocks', () => {
    openNewBlock();
    expect(get(browseNav)).toEqual({ level: 'newBlock' });
  });

  it('newBlock backs to blocks', () => {
    openNewBlock(); back();
    expect(get(browseNav)).toEqual({ level: 'blocks' });
  });

  it('openNewRecord carries the block; backs to records', () => {
    openBlock(BLOCK); openNewRecord(BLOCK);
    expect(get(browseNav)).toEqual({ level: 'newRecord', block: BLOCK });
    back();
    expect(get(browseNav)).toEqual({ level: 'records', block: BLOCK });
  });

  it('openEditRecord carries block + record; backs to fields', () => {
    openBlock(BLOCK); openNewRecord(BLOCK); // ensure block context
    openEditRecord(BLOCK, REC);
    expect(get(browseNav)).toEqual({ level: 'editRecord', block: BLOCK, record: REC });
    back();
    expect(get(browseNav)).toEqual({ level: 'fields', block: BLOCK, record: REC });
  });
});
