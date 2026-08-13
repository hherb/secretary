// Tests for panesFor — the pure projection from the nine-arm browseNav union
// onto the three-pane layout (#526). This file IS the design's projection
// table, executable: one assertion block per union arm.

import { describe, it, expect } from 'vitest';
import {
  panesFor,
  SELECT_BLOCK_PROMPT,
  SELECT_RECORD_PROMPT
} from '../src/lib/panes';
import type { BlockSummaryDto, RecordDto } from '../src/lib/ipc';

const BLOCK: BlockSummaryDto = {
  blockUuidHex: 'aaaa1111',
  blockName: 'Banking',
  createdAtMs: 1_700_000_000_000,
  lastModifiedMs: 1_700_000_100_000
};

const RECORD: RecordDto = {
  recordUuidHex: 'bbbb2222',
  recordType: 'login',
  title: 'alice@example.test',
  subtitle: 'url: https://bank.test',
  tags: [],
  createdAtMs: 1_700_000_000_000,
  lastModMs: 1_700_000_100_000,
  fieldCount: 2,
  fields: []
};

describe('panesFor — blocks root', () => {
  it('selects nothing, prompts for a block, leaves detail empty', () => {
    const p = panesFor({ level: 'blocks' });
    expect(p.sidebar).toEqual({ kind: 'none' });
    expect(p.list).toEqual({ kind: 'prompt', message: SELECT_BLOCK_PROMPT });
    expect(p.detail).toEqual({ kind: 'empty' });
    expect(p.modal).toEqual({ kind: 'none' });
  });
});

describe('panesFor — records', () => {
  it('selects the block, lists its records, prompts for a record', () => {
    const p = panesFor({ level: 'records', block: BLOCK });
    expect(p.sidebar).toEqual({ kind: 'block', blockUuidHex: BLOCK.blockUuidHex });
    expect(p.list).toEqual({
      kind: 'records',
      block: BLOCK,
      selectedRecordUuidHex: null,
      frozen: false
    });
    expect(p.detail).toEqual({ kind: 'prompt', message: SELECT_RECORD_PROMPT });
  });
});

describe('panesFor — fields', () => {
  it('highlights the record in the list and shows the viewer', () => {
    const p = panesFor({ level: 'fields', block: BLOCK, record: RECORD });
    expect(p.list).toEqual({
      kind: 'records',
      block: BLOCK,
      selectedRecordUuidHex: RECORD.recordUuidHex,
      frozen: false
    });
    expect(p.detail).toEqual({ kind: 'viewer', block: BLOCK, record: RECORD });
  });
});

describe('panesFor — editRecord', () => {
  it('freezes the list so a stray click cannot discard the edit', () => {
    const p = panesFor({ level: 'editRecord', block: BLOCK, record: RECORD });
    expect(p.list).toEqual({
      kind: 'records',
      block: BLOCK,
      selectedRecordUuidHex: RECORD.recordUuidHex,
      frozen: true
    });
    expect(p.detail).toEqual({ kind: 'editor', block: BLOCK, record: RECORD });
  });
});

describe('panesFor — newRecord', () => {
  it('freezes the list with no row selected and an empty editor', () => {
    const p = panesFor({ level: 'newRecord', block: BLOCK });
    expect(p.list).toEqual({
      kind: 'records',
      block: BLOCK,
      selectedRecordUuidHex: null,
      frozen: true
    });
    expect(p.detail).toEqual({ kind: 'editor', block: BLOCK, record: null });
  });
});

describe('panesFor — trash and contacts span both right-hand columns', () => {
  it('trash', () => {
    const p = panesFor({ level: 'trash' });
    expect(p.sidebar).toEqual({ kind: 'trash' });
    expect(p.list).toEqual({ kind: 'trash' });
    expect(p.detail).toEqual({ kind: 'spanned' });
  });

  it('contacts', () => {
    const p = panesFor({ level: 'contacts' });
    expect(p.sidebar).toEqual({ kind: 'contacts' });
    expect(p.list).toEqual({ kind: 'contacts' });
    expect(p.detail).toEqual({ kind: 'spanned' });
  });
});

describe('panesFor — the modal arms define their own backdrop', () => {
  it('newBlock sits over the blocks root', () => {
    const p = panesFor({ level: 'newBlock' });
    expect(p.sidebar).toEqual({ kind: 'none' });
    expect(p.list).toEqual({ kind: 'prompt', message: SELECT_BLOCK_PROMPT });
    expect(p.modal).toEqual({ kind: 'blockName', mode: { kind: 'create' } });
  });

  it('renameBlock sits over that block, already selected — so cancel is seamless', () => {
    const p = panesFor({ level: 'renameBlock', block: BLOCK });
    expect(p.sidebar).toEqual({ kind: 'block', blockUuidHex: BLOCK.blockUuidHex });
    expect(p.list).toEqual({
      kind: 'records',
      block: BLOCK,
      selectedRecordUuidHex: null,
      frozen: false
    });
    expect(p.modal).toEqual({ kind: 'blockName', mode: { kind: 'rename', block: BLOCK } });
  });
});

describe('panesFor — total coverage', () => {
  it('never returns a modal outside the two block-name arms', () => {
    const navs = [
      { level: 'blocks' },
      { level: 'records', block: BLOCK },
      { level: 'fields', block: BLOCK, record: RECORD },
      { level: 'editRecord', block: BLOCK, record: RECORD },
      { level: 'newRecord', block: BLOCK },
      { level: 'trash' },
      { level: 'contacts' }
    ] as const;
    for (const nav of navs) {
      expect(panesFor(nav).modal).toEqual({ kind: 'none' });
    }
  });
});
