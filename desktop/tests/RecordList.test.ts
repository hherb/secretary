import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, waitFor } from '@testing-library/svelte';

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));

import RecordList from '../src/components/RecordList.svelte';
import type { BlockSummaryDto } from '../src/lib/ipc';

const BLOCK: BlockSummaryDto = { blockUuidHex: 'ab', blockName: 'Personal logins', createdAtMs: 1, lastModifiedMs: 2 };

describe('RecordList', () => {
  beforeEach(() => invokeMock.mockReset());

  it('fetches read_block on mount and renders a row per record', async () => {
    invokeMock.mockResolvedValueOnce({
      blockUuidHex: 'ab', blockName: 'Personal logins',
      records: [{ recordUuidHex: 'cd', recordType: 'login', tags: ['work'], createdAtMs: 1, lastModMs: 2, fieldCount: 2, fields: [] }]
    });
    const { getByText } = render(RecordList, { props: { block: BLOCK } });
    await waitFor(() => expect(getByText('login')).toBeTruthy());
    expect(invokeMock).toHaveBeenCalledWith('read_block', { blockUuidHex: 'ab' });
  });

  it('renders an empty-state when the block has no records', async () => {
    invokeMock.mockResolvedValueOnce({ blockUuidHex: 'ab', blockName: 'Personal logins', records: [] });
    const { getByText } = render(RecordList, { props: { block: BLOCK } });
    await waitFor(() => expect(getByText(/No records/i)).toBeTruthy());
  });

  it('shows the typed error message when read_block rejects', async () => {
    invokeMock.mockRejectedValueOnce({ code: 'block_not_found', block_uuid_hex: 'ab' });
    const { findByRole } = render(RecordList, { props: { block: BLOCK } });
    const alert = await findByRole('alert');
    expect(alert.textContent).toMatch(/Block not found/i);
  });
});
