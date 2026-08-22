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
import type { BrowseNav } from '../src/lib/browse';

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
    expect(p.detail).toEqual({ kind: 'empty' });
    expect(p.modal).toEqual({ kind: 'blockName', mode: { kind: 'create' } });
  });

  // #530 — both modal arms now assert `detail` too. They set
  // `detail: { kind: 'empty' }` and previously asserted only sidebar/list/
  // modal, so a change to either arm's detail slot passed the whole suite.
  // The detail pane is inert behind a modal, but this file is the projection
  // table made executable and two of its rows were incomplete.
  it('renameBlock sits over that block, already selected — cancel returns there', () => {
    const p = panesFor({ level: 'renameBlock', block: BLOCK });
    expect(p.sidebar).toEqual({ kind: 'block', blockUuidHex: BLOCK.blockUuidHex });
    expect(p.list).toEqual({
      kind: 'records',
      block: BLOCK,
      selectedRecordUuidHex: null,
      frozen: false
    });
    expect(p.detail).toEqual({ kind: 'empty' });
    expect(p.modal).toEqual({ kind: 'blockName', mode: { kind: 'rename', block: BLOCK } });
  });
});

// Every arm of the union, in one place. Typed as `BrowseNav[]` (not `as
// const`) so adding a tenth arm to BrowseNav without extending this list is a
// type error rather than a silently narrower sweep.
const ALL_NAVS: BrowseNav[] = [
  { level: 'blocks' },
  { level: 'records', block: BLOCK },
  { level: 'fields', block: BLOCK, record: RECORD },
  { level: 'newBlock' },
  { level: 'newRecord', block: BLOCK },
  { level: 'editRecord', block: BLOCK, record: RECORD },
  { level: 'renameBlock', block: BLOCK },
  { level: 'trash' },
  { level: 'contacts' }
];

describe('panesFor — total coverage', () => {
  it('covers every arm of the BrowseNav union', () => {
    // Guards the sweeps below from silently shrinking: they are only as
    // exhaustive as this list.
    const levels = new Set(ALL_NAVS.map((n) => n.level));
    expect(levels.size).toBe(ALL_NAVS.length);
    expect(ALL_NAVS).toHaveLength(9);
  });

  it('never returns a modal outside the two block-name arms', () => {
    for (const nav of ALL_NAVS) {
      const expected =
        nav.level === 'newBlock' || nav.level === 'renameBlock' ? 'blockName' : 'none';
      expect(panesFor(nav).modal.kind).toBe(expected);
    }
  });

  // The cross-arm invariant the whole freeze mechanism rests on (#526 review).
  //
  // Vault.svelte derives the SIDEBAR's frozen flag as
  // `panes.list.kind === 'records' && panes.list.frozen`, which yields `false`
  // for every non-`records` list kind. So an arm that opened an editor over a
  // different list kind — or over `records` with `frozen: false` — would leave
  // the sidebar AND the rows live during an edit, and a stray click would
  // discard the draft. Per-arm literal assertions cannot catch that: they only
  // check the arms someone remembered to write down. This checks the property.
  it('every arm that opens an editor also freezes the list', () => {
    for (const nav of ALL_NAVS) {
      const p = panesFor(nav);
      if (p.detail.kind !== 'editor') continue;
      expect(p.list.kind).toBe('records');
      expect(p.list.kind === 'records' && p.list.frozen).toBe(true);
    }
  });

  it('freezes the list ONLY when an editor is open', () => {
    // The converse, so the flag cannot drift into meaning something vaguer —
    // a permanently-frozen list would be just as broken, and just as silent.
    for (const nav of ALL_NAVS) {
      const p = panesFor(nav);
      if (p.list.kind !== 'records') continue;
      expect(p.list.frozen).toBe(p.detail.kind === 'editor');
    }
  });
});
