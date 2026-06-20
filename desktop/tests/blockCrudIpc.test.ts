import { describe, it, expect, vi, beforeEach } from 'vitest';
const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));
import { renameBlock, moveRecord } from '../src/lib/ipc';

describe('block-CRUD ipc wrappers', () => {
  beforeEach(() => invokeMock.mockReset());

  it('renameBlock invokes rename_block with camelCase args', async () => {
    invokeMock.mockResolvedValueOnce({ blockUuidHex: 'ab', blockName: 'After', createdAtMs: 1, lastModifiedMs: 2 });
    await renameBlock('ab', 'After');
    expect(invokeMock).toHaveBeenCalledWith('rename_block', { blockUuidHex: 'ab', newName: 'After' });
  });

  it('moveRecord invokes move_record with camelCase args', async () => {
    invokeMock.mockResolvedValueOnce({ blockUuidHex: 'cd', recordUuidHex: 'ef' });
    const ref = await moveRecord('ab', 'cd', 'rr');
    expect(invokeMock).toHaveBeenCalledWith('move_record', {
      sourceBlockUuidHex: 'ab', targetBlockUuidHex: 'cd', sourceRecordUuidHex: 'rr'
    });
    expect(ref.recordUuidHex).toBe('ef');
  });
});
