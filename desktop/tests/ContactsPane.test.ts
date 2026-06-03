// Tests for ContactsPane.svelte (D.1.7) — the contacts management pane
// reached from the Vault "👤 Contacts" entry. Loads list_contacts on
// mount, renders contact rows (name + block count), handles the warn-but-
// allow delete flow (ConfirmDialog → deleteContactCard), and offers an
// "Export my card" PathPicker.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';

const { invokeMock, openMock } = vi.hoisted(() => ({
  invokeMock: vi.fn(),
  openMock: vi.fn()
}));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));
vi.mock('@tauri-apps/plugin-dialog', () => ({ open: openMock }));

import ContactsPane from '../src/components/contacts/ContactsPane.svelte';

describe('ContactsPane', () => {
  beforeEach(() => {
    invokeMock.mockReset();
    openMock.mockReset();
  });

  it('lists contacts with their shared-block counts', async () => {
    invokeMock.mockResolvedValueOnce({
      contacts: [
        { contactUuidHex: 'aa', displayName: 'Alice', sharedBlockCount: 2 },
        { contactUuidHex: 'bb', displayName: 'Bob', sharedBlockCount: 0 }
      ],
      unreadableCount: 0
    });
    const { getByText } = render(ContactsPane);
    await waitFor(() => expect(getByText('Alice')).toBeTruthy());
    expect(getByText('receives 2 blocks')).toBeTruthy();
    expect(getByText('Bob')).toBeTruthy();
    expect(invokeMock).toHaveBeenCalledWith('list_contacts', {});
  });

  it('renders empty state when there are no contacts', async () => {
    invokeMock.mockResolvedValueOnce({ contacts: [], unreadableCount: 0 });
    const { getByText } = render(ContactsPane);
    await waitFor(() => expect(getByText(/No contacts imported yet/i)).toBeTruthy());
  });

  it('shows a typed error when list_contacts rejects', async () => {
    invokeMock.mockRejectedValueOnce({ code: 'io' });
    const { findByRole } = render(ContactsPane);
    const alert = await findByRole('alert');
    expect(alert.textContent).toMatch(/filesystem error/i);
  });

  it('warns when some cards are unreadable', async () => {
    invokeMock.mockResolvedValueOnce({
      contacts: [],
      unreadableCount: 3
    });
    const { findByRole } = render(ContactsPane);
    const alert = await findByRole('alert');
    expect(alert.textContent).toMatch(/3 contact file/i);
  });

  it('deleting a contact with N>0 routes through a confirm then deleteContactCard', async () => {
    invokeMock.mockResolvedValueOnce({
      contacts: [{ contactUuidHex: 'aa', displayName: 'Alice', sharedBlockCount: 2 }],
      unreadableCount: 0
    });
    const { getByText, findByText } = render(ContactsPane);
    await waitFor(() => expect(getByText('Alice')).toBeTruthy());

    // Click the Delete button on Alice's row
    await fireEvent.click(getByText('Delete'));

    // A confirm dialog should appear with the warn-but-allow label
    const confirmBtn = await findByText('Delete anyway');
    expect(confirmBtn).toBeTruthy();

    // Set up mock for deleteContactCard + reload
    invokeMock.mockResolvedValueOnce(undefined); // delete_contact_card
    invokeMock.mockResolvedValueOnce({ contacts: [], unreadableCount: 0 }); // reload list_contacts

    await fireEvent.click(confirmBtn);

    await waitFor(() =>
      expect(invokeMock).toHaveBeenCalledWith('delete_contact_card', {
        contactUuidHex: 'aa'
      })
    );
  });

  it('deleting a contact with 0 blocks shows plain "Delete" label on confirm', async () => {
    invokeMock.mockResolvedValueOnce({
      contacts: [{ contactUuidHex: 'bb', displayName: 'Bob', sharedBlockCount: 0 }],
      unreadableCount: 0
    });
    const { getAllByText, findByText } = render(ContactsPane);
    await waitFor(() => expect(getAllByText('Delete').length).toBeGreaterThan(0));

    // Click the row's Delete button (the first one in the DOM is the row button)
    const deleteButtons = getAllByText('Delete');
    await fireEvent.click(deleteButtons[0]);

    // Confirm dialog should have "Delete" (not "Delete anyway")
    const confirmLabel = await findByText((text, element) => {
      return (
        element?.tagName === 'BUTTON' &&
        element.classList.contains('confirm-dialog__button--danger') &&
        text === 'Delete'
      );
    });
    expect(confirmLabel).toBeTruthy();
  });

  it('export: exportContactCard is called after PathPicker folder selection', async () => {
    invokeMock.mockResolvedValueOnce({ contacts: [], unreadableCount: 0 });
    const { getByRole } = render(ContactsPane);
    await waitFor(() => invokeMock.mock.calls.length >= 1);

    // Simulate the PathPicker folder dialog returning a path
    openMock.mockResolvedValueOnce('/tmp/exports');
    invokeMock.mockResolvedValueOnce({ path: '/tmp/exports/mycard.vcf' }); // export_contact_card

    // Click the "Export…" button inside the PathPicker
    const exportBtn = getByRole('button', { name: 'Export…' });
    await fireEvent.click(exportBtn);

    await waitFor(() =>
      expect(invokeMock).toHaveBeenCalledWith('export_contact_card', { destDir: '/tmp/exports' })
    );
  });
});
