// Wiring tests for the D.1.4 editor routing in Vault.svelte.
// Verifies that the browse-nav levels added in D.1.4 (`newBlock`,
// `newRecord`, `editRecord`) are routed to the correct pane components,
// and that a `refreshManifest()` call after createBlock surfaces the
// new block in the blocks pane.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render } from '@testing-library/svelte';
import { get } from 'svelte/store';
import Vault from '../src/routes/Vault.svelte';
import {
  _resetSessionStateForTest,
  unlockSucceeded,
  beginUnlock,
  sessionState,
  refreshManifest
} from '../src/lib/stores';
import {
  openNewBlock,
  openNewRecord,
  openEditRecord,
  resetBrowse
} from '../src/lib/browse';
import type { ManifestDto, SettingsDto, BlockSummaryDto, RecordDto } from '../src/lib/ipc';

// Stub IPC calls so the components don't blow up with a missing Tauri bridge.
const { lockMock, setSettingsMock, readBlockMock, getManifestMock, createBlockMock,
        saveRecordMock, saveRecordEditMock, revealRecordMock } = vi.hoisted(() => ({
  lockMock: vi.fn(),
  setSettingsMock: vi.fn(),
  readBlockMock: vi.fn(),
  getManifestMock: vi.fn(),
  createBlockMock: vi.fn(),
  saveRecordMock: vi.fn(),
  saveRecordEditMock: vi.fn(),
  revealRecordMock: vi.fn()
}));
vi.mock('../src/lib/ipc', async () => {
  const real = await vi.importActual<typeof import('../src/lib/ipc')>('../src/lib/ipc');
  return {
    ...real,
    lock: lockMock,
    setSettings: setSettingsMock,
    readBlock: readBlockMock,
    getManifest: getManifestMock,
    createBlock: createBlockMock,
    saveRecord: saveRecordMock,
    saveRecordEdit: saveRecordEditMock,
    revealRecord: revealRecordMock
  };
});

const SETTINGS: SettingsDto = { autoLockTimeoutMs: 60_000 };

function blockFixture(name: string, uuidHex: string): BlockSummaryDto {
  return {
    blockUuidHex: uuidHex,
    blockName: name,
    createdAtMs: 0,
    lastModifiedMs: 0
  };
}

function recordFixture(type: string, uuidHex: string): RecordDto {
  return {
    recordUuidHex: uuidHex,
    recordType: type,
    tags: [],
    createdAtMs: 0,
    lastModMs: 0,
    fieldCount: 0,
    fields: []
  };
}

function manifestFixture(blocks: BlockSummaryDto[] = []): ManifestDto {
  return {
    vaultUuidHex: 'abcdabcdabcdabcd',
    ownerUserUuidHex: 'ef',
    blockCount: blocks.length,
    blockSummaries: blocks,
    warnings: []
  };
}

function unlock(blocks: BlockSummaryDto[] = []) {
  _resetSessionStateForTest();
  beginUnlock(0);
  unlockSucceeded(manifestFixture(blocks), SETTINGS);
}

beforeEach(() => {
  unlock();
  resetBrowse();
  readBlockMock.mockReset();
  readBlockMock.mockResolvedValue({ blockUuidHex: 'ab', blockName: 'B', records: [] });
  getManifestMock.mockReset();
  getManifestMock.mockResolvedValue(manifestFixture());
  createBlockMock.mockReset();
  saveRecordMock.mockReset();
  saveRecordEditMock.mockReset();
  revealRecordMock.mockReset();
  revealRecordMock.mockResolvedValue({ fields: [] });
});

describe('Vault editor routing', () => {
  it('renders NewBlock when browseNav is newBlock', async () => {
    openNewBlock();
    const { findByRole } = render(Vault);
    expect(await findByRole('heading', { name: /new block/i })).toBeTruthy();
  });

  it('renders RecordEditor (add) when browseNav is newRecord', async () => {
    const block = blockFixture('Work', 'bb');
    unlock([block]);
    openNewRecord(block);
    const { findByRole } = render(Vault);
    expect(await findByRole('heading', { name: /add record/i })).toBeTruthy();
  });

  it('renders RecordEditor (edit) when browseNav is editRecord', async () => {
    const block = blockFixture('Work', 'bb');
    const record = recordFixture('login', 'rr');
    unlock([block]);
    openEditRecord(block, record);
    const { findByRole } = render(Vault);
    expect(await findByRole('heading', { name: /edit record/i })).toBeTruthy();
  });
});

describe('refreshManifest', () => {
  it('updates manifest.blockSummaries in sessionState with fresh IPC data', async () => {
    const newBlock = blockFixture('New Block', 'new1');
    const updatedManifest = manifestFixture([newBlock]);
    getManifestMock.mockResolvedValueOnce(updatedManifest);

    await refreshManifest();

    const s = get(sessionState);
    expect(s.status).toBe('unlocked');
    if (s.status === 'unlocked') {
      expect(s.manifest.blockSummaries).toHaveLength(1);
      expect(s.manifest.blockSummaries[0].blockName).toBe('New Block');
    }
  });
});
