import { describe, it, expect, vi, beforeEach } from 'vitest';
const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));

import {
  readBlock,
  tombstoneRecord,
  resurrectRecord,
  trashBlock,
  restoreBlock,
  listTrashedBlocks
} from '../src/lib/ipc';

describe('trash IPC wrappers', () => {
  beforeEach(() => invokeMock.mockReset());

  it('readBlock defaults includeDeleted to false', async () => {
    invokeMock.mockResolvedValueOnce({ blockUuidHex: 'ab', blockName: 'B', records: [] });
    await readBlock('ab');
    expect(invokeMock).toHaveBeenCalledWith('read_block', { blockUuidHex: 'ab', includeDeleted: false });
  });

  it('readBlock forwards includeDeleted: true when requested', async () => {
    invokeMock.mockResolvedValueOnce({ blockUuidHex: 'ab', blockName: 'B', records: [] });
    await readBlock('ab', true);
    expect(invokeMock).toHaveBeenCalledWith('read_block', { blockUuidHex: 'ab', includeDeleted: true });
  });

  it('tombstoneRecord forwards block + record uuid', async () => {
    invokeMock.mockResolvedValueOnce({ blockUuidHex: 'ab', recordUuidHex: 'cd' });
    const ref = await tombstoneRecord('ab', 'cd');
    expect(invokeMock).toHaveBeenCalledWith('tombstone_record', { blockUuidHex: 'ab', recordUuidHex: 'cd' });
    expect(ref.recordUuidHex).toBe('cd');
  });

  it('resurrectRecord forwards block + record uuid', async () => {
    invokeMock.mockResolvedValueOnce({ blockUuidHex: 'ab', recordUuidHex: 'cd' });
    await resurrectRecord('ab', 'cd');
    expect(invokeMock).toHaveBeenCalledWith('resurrect_record', { blockUuidHex: 'ab', recordUuidHex: 'cd' });
  });

  it('trashBlock forwards blockUuidHex', async () => {
    invokeMock.mockResolvedValueOnce(undefined);
    await trashBlock('ab');
    expect(invokeMock).toHaveBeenCalledWith('trash_block', { blockUuidHex: 'ab' });
  });

  it('restoreBlock forwards blockUuidHex and returns a summary', async () => {
    invokeMock.mockResolvedValueOnce({ blockUuidHex: 'ab', blockName: 'B', createdAtMs: 1, lastModifiedMs: 2 });
    const s = await restoreBlock('ab');
    expect(invokeMock).toHaveBeenCalledWith('restore_block', { blockUuidHex: 'ab' });
    expect(s.blockUuidHex).toBe('ab');
  });

  it('listTrashedBlocks invokes with empty args', async () => {
    invokeMock.mockResolvedValueOnce([]);
    await listTrashedBlocks();
    expect(invokeMock).toHaveBeenCalledWith('list_trashed_blocks', {});
  });
});
