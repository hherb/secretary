// D.1.8 — BlockRecipients banner: loads block_recipients on mount, renders a
// collapsed summary, expands to a per-recipient list, surfaces errors.
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));

import BlockRecipients from '../src/components/BlockRecipients.svelte';

const block = { blockUuidHex: 'deadbeef', blockName: 'Logins', createdAtMs: 0, lastModifiedMs: 0 };

describe('BlockRecipients', () => {
  beforeEach(() => invokeMock.mockReset());

  it('shows a collapsed summary then expands to the full list', async () => {
    invokeMock.mockResolvedValueOnce([
      { uuidHex: '00', kind: 'owner', displayName: null },
      { uuidHex: 'a1', kind: 'contact', displayName: 'Alice' },
      { uuidHex: 'a1b2c3d4e5f6', kind: 'unknown', displayName: null }
    ]);
    const { getByRole, getByText, queryByText } = render(BlockRecipients, { block });

    // Collapsed: summary names owner + contact + unknown count.
    await waitFor(() => expect(getByText(/Shared with:/)).toBeTruthy());
    expect(getByText(/You, Alice, \+1 unknown/)).toBeTruthy();
    // List rows not shown until expanded.
    expect(queryByText('Unknown contact (a1b2c3d4…)')).toBeNull();

    await fireEvent.click(getByRole('button', { name: /shared with/i }));
    expect(getByText('Unknown contact (a1b2c3d4…)')).toBeTruthy();
    expect(invokeMock).toHaveBeenCalledWith('block_recipients', { blockUuidHex: 'deadbeef' });
  });

  it('surfaces a typed error when the call rejects', async () => {
    invokeMock.mockRejectedValueOnce({ code: 'internal' });
    const { findByRole } = render(BlockRecipients, { block });
    const alert = await findByRole('alert');
    expect(alert.textContent).toMatch(/internal error/i);
  });
});
