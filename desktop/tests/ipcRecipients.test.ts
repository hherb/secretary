// D.1.8 — listBlockRecipients passes the block uuid as a camelCase arg and
// returns the recipient DTO array verbatim.
import { describe, it, expect, vi, beforeEach } from 'vitest';

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));

import { listBlockRecipients, type RecipientDto } from '../src/lib/ipc';

describe('listBlockRecipients', () => {
  beforeEach(() => invokeMock.mockReset());

  it('invokes block_recipients with a camelCase blockUuidHex arg', async () => {
    const rows: RecipientDto[] = [
      { uuidHex: 'aa', kind: 'owner', displayName: null },
      { uuidHex: 'bb', kind: 'contact', displayName: 'Alice' }
    ];
    invokeMock.mockResolvedValueOnce(rows);
    const res = await listBlockRecipients('deadbeef');
    expect(invokeMock).toHaveBeenCalledWith('block_recipients', { blockUuidHex: 'deadbeef' });
    expect(res).toEqual(rows);
  });
});
