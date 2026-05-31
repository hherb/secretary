// Tests for ShareDialog.svelte (D.1.6) — the contact-picker + inline-import
// modal launched from a block's Share action. Native <dialog> mirroring
// ConfirmDialog; callback prop (onClose); list_contacts on mount, share_block
// on confirm. JSDOM's <dialog> showModal/close are polyfilled in tests/setup.ts.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';

const { invokeMock, openMock } = vi.hoisted(() => ({ invokeMock: vi.fn(), openMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));
vi.mock('@tauri-apps/plugin-dialog', () => ({ open: openMock }));

import ShareDialog from '../src/components/share/ShareDialog.svelte';
import type { BlockSummaryDto } from '../src/lib/ipc';

const BLOCK: BlockSummaryDto = {
  blockUuidHex: 'blk',
  blockName: 'Logins',
  createdAtMs: 1,
  lastModifiedMs: 2
};

describe('ShareDialog.svelte', () => {
  beforeEach(() => {
    invokeMock.mockReset();
    openMock.mockReset();
  });

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

  it('imports a picked card and re-lists so the new contact appears', async () => {
    // Mount: empty list. Import: dialog returns a path → import_contact →
    // refresh re-pulls list_contacts, now containing the imported peer.
    invokeMock.mockResolvedValueOnce({ contacts: [], unreadableCount: 0 }); // mount list_contacts
    const { getByText, getByRole } = render(ShareDialog, {
      props: { block: BLOCK, onClose: vi.fn() }
    });
    await waitFor(() => expect(getByText(/Import a contact/i)).toBeTruthy());

    openMock.mockResolvedValueOnce('/tmp/carol.card'); // file picker
    invokeMock.mockResolvedValueOnce({ contactUuidHex: 'rcp', displayName: 'Carol' }); // import_contact
    invokeMock.mockResolvedValueOnce({
      contacts: [{ contactUuidHex: 'rcp', displayName: 'Carol' }],
      unreadableCount: 0
    }); // refresh list_contacts

    await fireEvent.click(getByRole('button', { name: /Import a contact/i }));

    await waitFor(() =>
      expect(invokeMock).toHaveBeenCalledWith('import_contact', { cardPath: '/tmp/carol.card' })
    );
    await waitFor(() => expect(getByText('Carol')).toBeTruthy());
  });

  it('renders a typed error message when sharing fails', async () => {
    invokeMock.mockResolvedValueOnce({
      contacts: [{ contactUuidHex: 'rcp', displayName: 'Alice' }],
      unreadableCount: 0
    });
    const onClose = vi.fn();
    const { getByText, getByRole } = render(ShareDialog, { props: { block: BLOCK, onClose } });
    await waitFor(() => expect(getByText('Alice')).toBeTruthy());
    await fireEvent.click(getByText('Alice'));
    // share_block rejects with a known typed AppError code.
    invokeMock.mockRejectedValueOnce({ code: 'recipient_already_present' });
    await fireEvent.click(getByRole('button', { name: /^Share$/ }));
    await waitFor(() => expect(getByText(/already shared/i)).toBeTruthy());
    // The dialog stays open on error (onClose only fires on success).
    expect(onClose).not.toHaveBeenCalled();
  });
});
