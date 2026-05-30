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
