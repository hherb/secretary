import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import {
  __setWriteGuardTestSeam,
  ReauthCancelled,
  resetReauthGuard
} from '../src/lib/writeGuard';
const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));
import RecordList from '../src/components/RecordList.svelte';

const block = { blockUuidHex: 'src', blockName: 'Source', createdAtMs: 1, lastModifiedMs: 1 };
const rec = { recordUuidHex: 'r1', recordType: 'login', tags: [], createdAtMs: 1, lastModMs: 1, fieldCount: 1, fields: [], tombstoned: false };
const targets = [block, { blockUuidHex: 'dst', blockName: 'Target', createdAtMs: 1, lastModifiedMs: 1 }];

describe('RecordList move flow', () => {
  beforeEach(() => invokeMock.mockReset());
  afterEach(() => resetReauthGuard());

  it('moves a record into the chosen target then reloads the source', async () => {
    invokeMock.mockImplementation((cmd: string) => {
      if (cmd === 'read_block') return Promise.resolve({ blockUuidHex: 'src', blockName: 'Source', records: [rec] });
      if (cmd === 'list_blocks') return Promise.resolve(targets);
      if (cmd === 'move_record') return Promise.resolve({ blockUuidHex: 'dst', recordUuidHex: 'r2' });
      return Promise.resolve(null);
    });
    const { getByRole, findByRole } = render(RecordList, { props: { block, blockCount: 2 } });
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

  it('cancel: guard rejects ReauthCancelled → move_record NOT called, MoveTargetPicker stays open', async () => {
    __setWriteGuardTestSeam({
      readSettings: () => ({ enabled: true, windowMs: 0 }),
      now: () => 0,
      biometricPrefEnabled: () => false,
      tryBiometric: () => Promise.resolve('unavailable' as const),
      prompt: () => Promise.reject(ReauthCancelled)
    });
    invokeMock.mockImplementation((cmd: string) => {
      if (cmd === 'read_block') return Promise.resolve({ blockUuidHex: 'src', blockName: 'Source', records: [rec] });
      if (cmd === 'list_blocks') return Promise.resolve(targets);
      return Promise.resolve(null);
    });

    const { getByRole, findByRole, container } = render(RecordList, { props: { block, blockCount: 2 } });
    await waitFor(() => getByRole('button', { name: /move record/i }));
    await fireEvent.click(getByRole('button', { name: /move record/i }));

    // MoveTargetPicker is open; click a target to trigger confirmMove
    const targetBtn = await findByRole('button', { name: /Target/ });
    await fireEvent.click(targetBtn);

    // Guard cancelled → move_record must not have been called
    await waitFor(() =>
      expect(invokeMock.mock.calls.some(([c]) => c === 'move_record')).toBe(false)
    );
    // MoveTargetPicker MUST STILL BE PRESENT — cancel keeps the picker open
    expect(container.querySelector('.move-picker')).not.toBeNull();
  });

  it('hides the Move button when the vault has no other block (blockCount 1)', async () => {
    invokeMock.mockImplementation((cmd: string) =>
      cmd === 'read_block'
        ? Promise.resolve({ blockUuidHex: 'src', blockName: 'Source', records: [rec] })
        : Promise.resolve(null)
    );
    const { findByRole, queryByRole } = render(RecordList, { props: { block, blockCount: 1 } });
    // Delete is unconditional for a live record — wait on it so the row has rendered.
    await findByRole('button', { name: /delete record/i });
    expect(queryByRole('button', { name: /move record/i })).toBeNull();
  });

  it('shows the Move button when the vault has another block (blockCount 2)', async () => {
    invokeMock.mockImplementation((cmd: string) =>
      cmd === 'read_block'
        ? Promise.resolve({ blockUuidHex: 'src', blockName: 'Source', records: [rec] })
        : Promise.resolve(null)
    );
    const { findByRole } = render(RecordList, { props: { block, blockCount: 2 } });
    await findByRole('button', { name: /move record/i });
  });
});
