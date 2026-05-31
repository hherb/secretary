// Tests for the RecordList "Show deleted" toggle — flipping the checkbox
// re-reads the block with includeDeleted: true so tombstoned records
// become visible (for restore). Initial mount reads with
// includeDeleted: false.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));

import RecordList from '../src/components/RecordList.svelte';
import type { BlockSummaryDto } from '../src/lib/ipc';

const BLOCK: BlockSummaryDto = { blockUuidHex: 'ab', blockName: 'Personal logins', createdAtMs: 1, lastModifiedMs: 2 };

describe('RecordList — show-deleted toggle', () => {
  beforeEach(() => invokeMock.mockReset());

  it('reads the block with includeDeleted: false on mount', async () => {
    invokeMock.mockResolvedValue({ blockUuidHex: 'ab', blockName: 'Personal logins', records: [] });
    render(RecordList, { props: { block: BLOCK } });
    await waitFor(() =>
      expect(invokeMock).toHaveBeenCalledWith('read_block', { blockUuidHex: 'ab', includeDeleted: false })
    );
  });

  it('re-reads with includeDeleted: true when "Show deleted" is toggled on', async () => {
    invokeMock.mockResolvedValue({ blockUuidHex: 'ab', blockName: 'Personal logins', records: [] });
    const { getByLabelText } = render(RecordList, { props: { block: BLOCK } });
    await waitFor(() =>
      expect(invokeMock).toHaveBeenCalledWith('read_block', { blockUuidHex: 'ab', includeDeleted: false })
    );

    const toggle = getByLabelText(/show deleted/i) as HTMLInputElement;
    await fireEvent.click(toggle);

    await waitFor(() =>
      expect(invokeMock).toHaveBeenCalledWith('read_block', { blockUuidHex: 'ab', includeDeleted: true })
    );
  });
});

describe('RecordList — delete confirm → tombstoneRecord', () => {
  beforeEach(() => invokeMock.mockReset());

  const LIVE_RECORD = {
    recordUuidHex: 'cd',
    recordType: 'login',
    tags: [] as string[],
    fieldCount: 2,
    lastModMs: 5,
    tombstoned: false
  };

  it('confirming the delete dialog invokes tombstone_record and reloads', async () => {
    // read_block → one live record; tombstone_record resolves; reload read_block.
    invokeMock.mockImplementation((cmd: string) => {
      if (cmd === 'read_block') {
        return Promise.resolve({ blockUuidHex: 'ab', blockName: 'Personal logins', records: [LIVE_RECORD] });
      }
      if (cmd === 'tombstone_record') return Promise.resolve(null);
      // Tolerate any incidental/teardown invoke; the assertions below pin the
      // commands we care about.
      return Promise.resolve(null);
    });

    const { getByLabelText, container } = render(RecordList, { props: { block: BLOCK } });

    // Wait for the live row's Delete action to render.
    const deleteBtn = await waitFor(() => getByLabelText('Delete record'));
    await fireEvent.click(deleteBtn);

    // ConfirmDialog mounts; click its confirm ("Delete") button. Scope to the
    // dialog's danger button so we don't match the row's "Delete" action,
    // which shares the same text content.
    const confirmBtn = await waitFor(() => {
      const el = container.querySelector('.confirm-dialog__button--danger');
      if (!el) throw new Error('confirm dialog not yet mounted');
      return el as HTMLButtonElement;
    });
    await fireEvent.click(confirmBtn);

    await waitFor(() =>
      expect(invokeMock).toHaveBeenCalledWith('tombstone_record', { blockUuidHex: 'ab', recordUuidHex: 'cd' })
    );

    // A reload follows the tombstone: read_block invoked again (mount + reload ≥ 2).
    await waitFor(() =>
      expect(invokeMock.mock.calls.filter(([cmd]) => cmd === 'read_block').length).toBeGreaterThanOrEqual(2)
    );
  });
});
