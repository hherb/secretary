// Tests for TrashView.svelte — the trashed-blocks list reached via the
// Vault "Trash" entry. Loads list_trashed_blocks on mount, renders a row
// per entry (newest-first), an empty-state when there are none, and a
// typed-error alert when the IPC rejects.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, waitFor } from '@testing-library/svelte';

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));

import TrashView from '../src/components/delete/TrashView.svelte';

describe('TrashView', () => {
  beforeEach(() => invokeMock.mockReset());

  it('lists trashed blocks by name', async () => {
    invokeMock.mockResolvedValueOnce([
      { blockUuidHex: 'ab', blockName: 'Bank logins', tombstonedAtMs: 2, tombstonedByHex: 'd' }
    ]);
    const { getByText } = render(TrashView);
    await waitFor(() => expect(getByText('Bank logins')).toBeTruthy());
    expect(invokeMock).toHaveBeenCalledWith('list_trashed_blocks', {});
  });

  it('renders an empty-state when there are no trashed blocks', async () => {
    invokeMock.mockResolvedValueOnce([]);
    const { getByText } = render(TrashView);
    await waitFor(() => expect(getByText(/empty/i)).toBeTruthy());
  });

  it('shows the typed error message when list_trashed_blocks rejects', async () => {
    invokeMock.mockRejectedValueOnce({ code: 'io' });
    const { findByRole } = render(TrashView);
    const alert = await findByRole('alert');
    expect(alert.textContent).toMatch(/filesystem error/i);
  });
});
