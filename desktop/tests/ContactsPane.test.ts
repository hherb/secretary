// Tests for ContactsPane.svelte (D.1.7) — the contacts management pane
// reached from the Vault "👤 Contacts" entry. Loads list_contacts on
// mount, renders contact rows (name + block count), handles the warn-but-
// allow delete flow (ConfirmDialog → deleteContactCard), and offers an
// "Export my card" PathPicker.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import {
  __setWriteGuardTestSeam,
  ReauthCancelled,
  resetReauthGuard
} from '../src/lib/writeGuard';

// PathPicker now invokes `pick_export_dir` directly via `@tauri-apps/api/core`
// (#353) instead of the retired `@tauri-apps/plugin-dialog`, so the same
// `invokeMock` used for `list_contacts` / `export_contact_card` etc. also
// answers the picker call — ordering is FIFO across all invoke() calls.
const { invokeMock } = vi.hoisted(() => ({
  invokeMock: vi.fn()
}));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));

import ContactsPane from '../src/components/contacts/ContactsPane.svelte';

describe('ContactsPane', () => {
  beforeEach(() => {
    invokeMock.mockReset();
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

  it('self-heals when a delete fails with contact_not_found (reload + benign notice, no error)', async () => {
    invokeMock.mockResolvedValueOnce({
      contacts: [{ contactUuidHex: 'aa', displayName: 'Alice', sharedBlockCount: 0 }],
      unreadableCount: 0
    });
    const { getAllByText, findByText, findByRole, queryByRole } = render(ContactsPane);
    await waitFor(() => expect(getAllByText('Alice').length).toBeGreaterThan(0));

    // Open the confirm (N==0 → plain "Delete" danger button).
    await fireEvent.click(getAllByText('Delete')[0]);
    const confirmBtn = await findByText(
      (text, element) =>
        element?.tagName === 'BUTTON' &&
        element.classList.contains('confirm-dialog__button--danger') &&
        text === 'Delete'
    );

    // The delete rejects because the card already vanished on disk; the
    // component should re-fetch the list so the dead row doesn't linger and
    // show a benign notice (not an error — the user's intent is met).
    invokeMock.mockRejectedValueOnce({ code: 'contact_not_found', contact_uuid_hex: 'aa' });
    invokeMock.mockResolvedValueOnce({ contacts: [], unreadableCount: 0 }); // reload

    await fireEvent.click(confirmBtn);

    // list_contacts called twice total (initial mount + self-heal reload).
    await waitFor(() =>
      expect(invokeMock.mock.calls.filter((c) => c[0] === 'list_contacts').length).toBe(2)
    );
    const status = await findByRole('status');
    expect(status.textContent).toMatch(/already removed/i);
    expect(queryByRole('alert')).toBeNull();
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

    // Simulate the backend pick_export_dir command returning a path
    invokeMock.mockResolvedValueOnce('/tmp/exports');
    // Real exports are always `<uuid>.card` (owner_card_export); keep the
    // fixture in that shape so it doesn't imply a vCard/.vcf path.
    invokeMock.mockResolvedValueOnce({
      path: '/tmp/exports/00112233-4455-6677-8899-aabbccddeeff.card'
    }); // export_contact_card

    // Click the "Export…" button inside the PathPicker
    const exportBtn = getByRole('button', { name: 'Export…' });
    await fireEvent.click(exportBtn);

    await waitFor(() =>
      expect(invokeMock).toHaveBeenCalledWith('export_contact_card', { destDir: '/tmp/exports' })
    );
  });
});

describe('ContactsPane — delete write-reauth gate', () => {
  beforeEach(() => {
    invokeMock.mockReset();
  });
  afterEach(() => resetReauthGuard());

  it('cancel: guard rejects ReauthCancelled → delete_contact_card NOT called, ConfirmDialog stays open', async () => {
    __setWriteGuardTestSeam({
      readSettings: () => ({ enabled: true, windowMs: 0 }),
      now: () => 0,
      prompt: () => Promise.reject(ReauthCancelled)
    });

    invokeMock.mockResolvedValueOnce({
      contacts: [{ contactUuidHex: 'aa', displayName: 'Alice', sharedBlockCount: 0 }],
      unreadableCount: 0
    }); // list_contacts

    const { getAllByText, findByText, container } = render(ContactsPane);
    await waitFor(() => expect(getAllByText('Alice').length).toBeGreaterThan(0));

    // Click Delete on Alice's row
    await fireEvent.click(getAllByText('Delete')[0]);

    // ConfirmDialog appears — click the danger button
    const confirmBtn = await findByText(
      (text, element) =>
        element?.tagName === 'BUTTON' &&
        element.classList.contains('confirm-dialog__button--danger') &&
        text === 'Delete'
    );
    await fireEvent.click(confirmBtn);

    // Guard cancelled → delete_contact_card must NOT have been called; dialog stays open.
    await new Promise((r) => setTimeout(r, 50));
    expect(invokeMock.mock.calls.some(([c]) => c === 'delete_contact_card')).toBe(false);
    // ConfirmDialog must still be present
    expect(container.querySelector('.confirm-dialog__button--danger')).not.toBeNull();
  });

  it('happy: guard resolves → delete_contact_card called once', async () => {
    __setWriteGuardTestSeam({
      readSettings: () => ({ enabled: true, windowMs: 0 }),
      now: () => 0,
      prompt: () => Promise.resolve()
    });

    invokeMock.mockResolvedValueOnce({
      contacts: [{ contactUuidHex: 'aa', displayName: 'Alice', sharedBlockCount: 0 }],
      unreadableCount: 0
    }); // list_contacts

    const { getAllByText, findByText } = render(ContactsPane);
    await waitFor(() => expect(getAllByText('Alice').length).toBeGreaterThan(0));

    await fireEvent.click(getAllByText('Delete')[0]);

    const confirmBtn = await findByText(
      (text, element) =>
        element?.tagName === 'BUTTON' &&
        element.classList.contains('confirm-dialog__button--danger') &&
        text === 'Delete'
    );

    invokeMock.mockResolvedValueOnce(undefined); // delete_contact_card
    invokeMock.mockResolvedValueOnce({ contacts: [], unreadableCount: 0 }); // reload list_contacts

    await fireEvent.click(confirmBtn);

    await waitFor(() =>
      expect(invokeMock).toHaveBeenCalledWith('delete_contact_card', { contactUuidHex: 'aa' })
    );
  });
});
