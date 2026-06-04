import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, waitFor } from '@testing-library/svelte';

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));

import RecordList from '../src/components/RecordList.svelte';
import type { BlockSummaryDto } from '../src/lib/ipc';

const BLOCK: BlockSummaryDto = { blockUuidHex: 'ab', blockName: 'Personal logins', createdAtMs: 1, lastModifiedMs: 2 };

/** Answer both IPC calls that RecordList fires on mount: read_block (records)
 *  and block_recipients (banner). Tests that only care about one can pass an
 *  empty override for the other. Unknown commands resolve to null so that
 *  any cleanup-phase stale calls don't throw and pollute the next test. */
function bothCalls(
  records: unknown[],
  recipients: unknown[] = [{ uuidHex: '00', kind: 'owner', displayName: null }]
) {
  invokeMock.mockImplementation((cmd: string) => {
    if (cmd === 'read_block') return Promise.resolve({ records });
    if (cmd === 'block_recipients') return Promise.resolve(recipients);
    return Promise.resolve(null);
  });
}

describe('RecordList', () => {
  beforeEach(() => invokeMock.mockReset());

  it('fetches read_block on mount and renders a row per record', async () => {
    bothCalls([
      { recordUuidHex: 'cd', recordType: 'login', tags: ['work'], createdAtMs: 1, lastModMs: 2, fieldCount: 2, fields: [] }
    ]);
    const { getByText } = render(RecordList, { props: { block: BLOCK } });
    await waitFor(() => expect(getByText('login')).toBeTruthy());
    expect(invokeMock).toHaveBeenCalledWith('read_block', { blockUuidHex: 'ab', includeDeleted: false });
  });

  it('renders an empty-state when the block has no records', async () => {
    bothCalls([]);
    const { getByText } = render(RecordList, { props: { block: BLOCK } });
    await waitFor(() => expect(getByText(/No records/i)).toBeTruthy());
  });

  it('shows the typed error message when read_block rejects', async () => {
    // Only read_block rejects; block_recipients still resolves so its error
    // doesn't clobber the record-list error we are asserting against.
    invokeMock.mockImplementation((cmd: string) => {
      if (cmd === 'read_block')
        return Promise.reject({ code: 'block_not_found', block_uuid_hex: 'ab' });
      if (cmd === 'block_recipients')
        return Promise.resolve([{ uuidHex: '00', kind: 'owner', displayName: null }]);
      return Promise.resolve(null);
    });
    const { findByRole } = render(RecordList, { props: { block: BLOCK } });
    const alert = await findByRole('alert');
    expect(alert.textContent).toMatch(/Block not found/i);
  });

  it('mounts the Shared-with banner for the block', async () => {
    // readBlock (records) + block_recipients (banner) both fire on mount.
    invokeMock.mockImplementation((cmd: string) => {
      if (cmd === 'read_block') return Promise.resolve({ records: [] });
      if (cmd === 'block_recipients')
        return Promise.resolve([{ uuidHex: '00', kind: 'owner', displayName: null }]);
      return Promise.resolve(null);
    });
    const { getByText } = render(RecordList, {
      block: { blockUuidHex: 'deadbeef', blockName: 'Logins', lastModifiedMs: 0, createdAtMs: 0 }
    });
    await waitFor(() => expect(getByText(/Shared with:/)).toBeTruthy());
    expect(invokeMock).toHaveBeenCalledWith('block_recipients', { blockUuidHex: 'deadbeef' });
  });
});
