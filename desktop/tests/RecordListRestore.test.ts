// Tests for the RecordList resurrect gate: a contentless tombstone
// (fieldCount 0) routes through a ConfirmDialog before resurrect_record;
// a tombstone that still has fields resurrects one-click.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));

import RecordList from '../src/components/RecordList.svelte';
import type { BlockSummaryDto } from '../src/lib/ipc';

const BLOCK: BlockSummaryDto = { blockUuidHex: 'ab', blockName: 'Personal logins', createdAtMs: 1, lastModifiedMs: 2 };

const EMPTY_TOMBSTONE = {
  recordUuidHex: 'cd', recordType: 'login', tags: [] as string[],
  fieldCount: 0, lastModMs: 5, tombstoned: true, fields: []
};
const FILLED_TOMBSTONE = {
  recordUuidHex: 'ef', recordType: 'login', tags: [] as string[],
  fieldCount: 2, lastModMs: 5, tombstoned: true, fields: []
};

function mockReadReturning(record: unknown) {
  invokeMock.mockImplementation((cmd: string) => {
    if (cmd === 'read_block') {
      return Promise.resolve({ blockUuidHex: 'ab', blockName: 'Personal logins', records: [record] });
    }
    return Promise.resolve(null); // resurrect_record + any teardown invoke
  });
}

const calledResurrect = () => invokeMock.mock.calls.some(([c]) => c === 'resurrect_record');

describe('RecordList — contentless resurrect confirm gate', () => {
  beforeEach(() => invokeMock.mockReset());

  it('opens a confirm and does NOT resurrect until confirmed', async () => {
    mockReadReturning(EMPTY_TOMBSTONE);
    const { getByLabelText, container } = render(RecordList, { props: { block: BLOCK } });

    const restoreBtn = await waitFor(() => getByLabelText('Restore record'));
    await fireEvent.click(restoreBtn);

    // ConfirmDialog mounts; resurrect must not have fired yet.
    await waitFor(() => {
      if (!container.querySelector('.confirm-dialog__button--danger')) {
        throw new Error('confirm dialog not yet mounted');
      }
    });
    expect(calledResurrect()).toBe(false);
  });

  it('confirming invokes resurrect_record and reloads', async () => {
    mockReadReturning(EMPTY_TOMBSTONE);
    const { getByLabelText, container } = render(RecordList, { props: { block: BLOCK } });

    const restoreBtn = await waitFor(() => getByLabelText('Restore record'));
    await fireEvent.click(restoreBtn);

    const confirmBtn = await waitFor(() => {
      const el = container.querySelector('.confirm-dialog__button--danger');
      if (!el) throw new Error('confirm dialog not yet mounted');
      return el as HTMLButtonElement;
    });
    await fireEvent.click(confirmBtn);

    await waitFor(() =>
      expect(invokeMock).toHaveBeenCalledWith('resurrect_record', { blockUuidHex: 'ab', recordUuidHex: 'cd' })
    );
    await waitFor(() =>
      expect(invokeMock.mock.calls.filter(([c]) => c === 'read_block').length).toBeGreaterThanOrEqual(2)
    );
  });

  it('cancelling closes the dialog without resurrecting', async () => {
    mockReadReturning(EMPTY_TOMBSTONE);
    const { getByLabelText, getByText, container } = render(RecordList, { props: { block: BLOCK } });

    const restoreBtn = await waitFor(() => getByLabelText('Restore record'));
    await fireEvent.click(restoreBtn);

    const cancelBtn = await waitFor(() => getByText('Cancel'));
    await fireEvent.click(cancelBtn);

    await waitFor(() => {
      if (container.querySelector('.confirm-dialog__button--danger')) {
        throw new Error('confirm dialog still mounted');
      }
    });
    expect(calledResurrect()).toBe(false);
  });

  it('resurrects a still-filled tombstone one-click (no confirm)', async () => {
    mockReadReturning(FILLED_TOMBSTONE);
    const { getByLabelText, container } = render(RecordList, { props: { block: BLOCK } });

    const restoreBtn = await waitFor(() => getByLabelText('Restore record'));
    await fireEvent.click(restoreBtn);

    await waitFor(() =>
      expect(invokeMock).toHaveBeenCalledWith('resurrect_record', { blockUuidHex: 'ab', recordUuidHex: 'ef' })
    );
    expect(container.querySelector('.confirm-dialog__button--danger')).toBeNull();
  });
});
