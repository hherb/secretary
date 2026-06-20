import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));
import RecordList from '../src/components/RecordList.svelte';

const block = { blockUuidHex: 'src', blockName: 'Source', createdAtMs: 1, lastModifiedMs: 1 };
const rec = { recordUuidHex: 'r1', recordType: 'login', tags: [], createdAtMs: 1, lastModMs: 1, fieldCount: 1, fields: [], tombstoned: false };
const targets = [block, { blockUuidHex: 'dst', blockName: 'Target', createdAtMs: 1, lastModifiedMs: 1 }];

describe('RecordList move flow', () => {
  beforeEach(() => invokeMock.mockReset());

  it('moves a record into the chosen target then reloads the source', async () => {
    invokeMock.mockImplementation((cmd: string) => {
      if (cmd === 'read_block') return Promise.resolve({ blockUuidHex: 'src', blockName: 'Source', records: [rec] });
      if (cmd === 'list_blocks') return Promise.resolve(targets);
      if (cmd === 'move_record') return Promise.resolve({ blockUuidHex: 'dst', recordUuidHex: 'r2' });
      return Promise.resolve(null);
    });
    const { getByRole, findByRole } = render(RecordList, { props: { block } });
    await waitFor(() => getByRole('button', { name: /move record/i }));
    await fireEvent.click(getByRole('button', { name: /move record/i }));
    const target = await findByRole('button', { name: /Target/ });
    await fireEvent.click(target);
    await waitFor(() => expect(invokeMock).toHaveBeenCalledWith('move_record', {
      sourceBlockUuidHex: 'src', targetBlockUuidHex: 'dst', sourceRecordUuidHex: 'r1'
    }));
    // the source block is re-read after the move so the moved record shows tombstoned
    await waitFor(() => {
      const readSrcCalls = invokeMock.mock.calls.filter(
        ([cmd, args]) => cmd === 'read_block' && args?.blockUuidHex === 'src'
      );
      expect(readSrcCalls.length).toBeGreaterThanOrEqual(2);
    });
  });
});
