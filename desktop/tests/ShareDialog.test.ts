// Tests for ShareDialog.svelte (D.1.6) — the contact-picker + inline-import
// modal launched from a block's Share action. Native <dialog> mirroring
// ConfirmDialog; callback prop (onClose); list_contacts on mount, share_block
// on confirm. JSDOM's <dialog> showModal/close are polyfilled in tests/setup.ts.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));
vi.mock('@tauri-apps/plugin-dialog', () => ({ open: vi.fn() }));

import ShareDialog from '../src/components/share/ShareDialog.svelte';
import type { BlockSummaryDto } from '../src/lib/ipc';

const BLOCK: BlockSummaryDto = {
  blockUuidHex: 'blk',
  blockName: 'Logins',
  createdAtMs: 1,
  lastModifiedMs: 2
};

describe('ShareDialog.svelte', () => {
  beforeEach(() => invokeMock.mockReset());

  it('shows the empty state with an import affordance when no contacts', async () => {
    invokeMock.mockResolvedValueOnce({ contacts: [], unreadableCount: 0 }); // list_contacts
    const { getByText } = render(ShareDialog, { props: { block: BLOCK, onClose: vi.fn() } });
    await waitFor(() => expect(getByText(/Import a contact/i)).toBeTruthy());
  });

  it('lists contacts and shares the selected one', async () => {
    invokeMock.mockResolvedValueOnce({
      contacts: [{ contactUuidHex: 'rcp', displayName: 'Alice' }],
      unreadableCount: 0
    });
    const onClose = vi.fn();
    const { getByText, getByRole } = render(ShareDialog, { props: { block: BLOCK, onClose } });
    await waitFor(() => expect(getByText('Alice')).toBeTruthy());
    await fireEvent.click(getByText('Alice'));
    invokeMock.mockResolvedValueOnce(undefined); // share_block
    await fireEvent.click(getByRole('button', { name: /^Share$/ }));
    await waitFor(() =>
      expect(invokeMock).toHaveBeenCalledWith('share_block', {
        blockUuidHex: 'blk',
        recipientUuidHex: 'rcp'
      })
    );
  });

  it('warns when some cards are unreadable', async () => {
    invokeMock.mockResolvedValueOnce({ contacts: [], unreadableCount: 2 });
    const { getByText } = render(ShareDialog, { props: { block: BLOCK, onClose: vi.fn() } });
    await waitFor(() => expect(getByText(/2 .*unreadable/i)).toBeTruthy());
  });
});
