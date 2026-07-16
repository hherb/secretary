// D.1.9 — ContactRow inline reverse map: lazy-fetch the contact's blocks on
// first expand, render them sorted, click a block to open it. Mocks ipc invoke
// and the browse store's openBlock seam.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import {
  __setWriteGuardTestSeam,
  ReauthCancelled,
  resetReauthGuard
} from '../src/lib/writeGuard';

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));

const { openBlockMock } = vi.hoisted(() => ({ openBlockMock: vi.fn() }));
vi.mock('../src/lib/browse', () => ({ openBlock: openBlockMock }));

import ContactRow from '../src/components/contacts/ContactRow.svelte';

const contact = { contactUuidHex: 'abcd', displayName: 'Alice', sharedBlockCount: 2 };
const noDelete = () => {};
const noRevoke = () => {};

describe('ContactRow reverse map', () => {
  beforeEach(() => {
    invokeMock.mockReset();
    openBlockMock.mockReset();
  });

  it('lazily fetches and lists blocks (sorted) on first expand', async () => {
    invokeMock.mockResolvedValueOnce([
      { blockUuidHex: 'b2', blockName: 'Logins', createdAtMs: 0, lastModifiedMs: 0 },
      { blockUuidHex: 'b1', blockName: 'Cards', createdAtMs: 0, lastModifiedMs: 0 }
    ]);
    const { getByRole, getByText, queryByText } = render(ContactRow, {
      contact,
      onDelete: noDelete,
      onRevoked: noRevoke
    });

    // Not fetched until expanded.
    expect(invokeMock).not.toHaveBeenCalled();
    expect(queryByText('Logins')).toBeNull();

    await fireEvent.click(getByRole('button', { name: /Alice/ }));

    await waitFor(() => expect(getByText('Cards')).toBeTruthy());
    expect(invokeMock).toHaveBeenCalledWith('list_contact_blocks', { contactUuidHex: 'abcd' });
    // Sorted: Cards before Logins.
    const items = getByRole('list').textContent ?? '';
    expect(items.indexOf('Cards')).toBeLessThan(items.indexOf('Logins'));
  });

  it('fetches once across collapse/re-expand', async () => {
    invokeMock.mockResolvedValueOnce([
      { blockUuidHex: 'b1', blockName: 'Cards', createdAtMs: 0, lastModifiedMs: 0 }
    ]);
    const { getByRole, getByText } = render(ContactRow, {
      contact,
      onDelete: noDelete,
      onRevoked: noRevoke
    });
    const toggle = getByRole('button', { name: /Alice/ });

    await fireEvent.click(toggle); // expand → fetch
    await waitFor(() => expect(getByText('Cards')).toBeTruthy());
    await fireEvent.click(toggle); // collapse
    await fireEvent.click(toggle); // re-expand → no refetch

    expect(invokeMock).toHaveBeenCalledTimes(1);
  });

  it('clicking a block calls openBlock with that block', async () => {
    const block = { blockUuidHex: 'b1', blockName: 'Cards', createdAtMs: 0, lastModifiedMs: 0 };
    invokeMock.mockResolvedValueOnce([block]);
    const { getByRole, getByText } = render(ContactRow, {
      contact,
      onDelete: noDelete,
      onRevoked: noRevoke
    });

    await fireEvent.click(getByRole('button', { name: /Alice/ }));
    await waitFor(() => expect(getByText('Cards')).toBeTruthy());
    await fireEvent.click(getByText('Cards'));

    expect(openBlockMock).toHaveBeenCalledWith(block);
  });

  it('shows an empty state when the contact receives no blocks', async () => {
    invokeMock.mockResolvedValueOnce([]);
    const { getByRole, getByText } = render(ContactRow, {
      contact: { contactUuidHex: 'ee', displayName: 'Eve', sharedBlockCount: 0 },
      onDelete: noDelete,
      onRevoked: noRevoke
    });
    await fireEvent.click(getByRole('button', { name: /Eve/ }));
    await waitFor(() => expect(getByText(/No shared blocks/i)).toBeTruthy());
  });

  it('surfaces an error when the fetch rejects', async () => {
    invokeMock.mockRejectedValueOnce({ code: 'internal' });
    const { getByRole, findByRole } = render(ContactRow, {
      contact,
      onDelete: noDelete,
      onRevoked: noRevoke
    });
    await fireEvent.click(getByRole('button', { name: /Alice/ }));
    const alert = await findByRole('alert');
    expect(alert.textContent).toMatch(/internal error/i);
  });

  it('retries the fetch after an error on next expand', async () => {
    invokeMock
      .mockRejectedValueOnce({ code: 'internal' })
      .mockResolvedValueOnce([
        { blockUuidHex: 'b1', blockName: 'Cards', createdAtMs: 0, lastModifiedMs: 0 }
      ]);
    const { getByRole, findByRole, findByText } = render(ContactRow, {
      contact,
      onDelete: noDelete,
      onRevoked: noRevoke
    });
    const toggle = getByRole('button', { name: /Alice/ });
    await fireEvent.click(toggle); // expand → error
    await findByRole('alert');
    await fireEvent.click(toggle); // collapse
    await fireEvent.click(toggle); // re-expand → retry
    await findByText('Cards');
    expect(invokeMock).toHaveBeenCalledTimes(2);
  });

  it('#180 — toggle aria-controls equals the expanded region id (uuid-derived)', async () => {
    invokeMock.mockResolvedValueOnce([
      { blockUuidHex: 'b1', blockName: 'Cards', createdAtMs: 0, lastModifiedMs: 0 }
    ]);
    const { container, getByRole } = render(ContactRow, {
      contact,
      onDelete: noDelete,
      onRevoked: noRevoke
    });
    const toggle = getByRole('button', { name: /Alice/ });
    expect(toggle.getAttribute('aria-controls')).toBe(`contact-blocks-${contact.contactUuidHex}`);
    await fireEvent.click(toggle);
    await waitFor(() =>
      expect(container.querySelector(`#contact-blocks-${contact.contactUuidHex}`)).not.toBeNull()
    );
  });

  it('the delete button does not toggle expand', async () => {
    const onDelete = vi.fn();
    const { getByRole, queryByRole } = render(ContactRow, {
      contact,
      onDelete,
      onRevoked: noRevoke
    });
    await fireEvent.click(getByRole('button', { name: /^Delete$/ }));
    expect(onDelete).toHaveBeenCalledWith(contact);
    expect(invokeMock).not.toHaveBeenCalled(); // expand did not trigger a fetch
    expect(queryByRole('list')).toBeNull();
  });

  it('revokes a block from the contact, reloads, and notifies the parent', async () => {
    const onRevoked = vi.fn();
    invokeMock
      .mockResolvedValueOnce([
        { blockUuidHex: 'b1', blockName: 'Logins', createdAtMs: 0, lastModifiedMs: 0 }
      ]) // ensureLoaded: contact's blocks
      .mockResolvedValueOnce(undefined) // revoke_block_from
      .mockResolvedValueOnce([]); // reload after revoke (now empty)

    const contact = { contactUuidHex: 'c1', displayName: 'Alice', sharedBlockCount: 1 };
    const { getByRole, getByText } = render(ContactRow, {
      contact,
      onDelete: vi.fn(),
      onRevoked
    });

    await fireEvent.click(getByRole('button', { name: /receives 1 block/i })); // expand
    await waitFor(() => expect(getByText('Logins')).toBeTruthy());

    await fireEvent.click(getByRole('button', { name: /Stop sharing .*Logins.* with Alice/i }));
    await fireEvent.click(getByRole('button', { name: 'Revoke' })); // confirm

    await waitFor(() =>
      expect(invokeMock).toHaveBeenCalledWith('revoke_block_from', {
        blockUuidHex: 'b1',
        recipientUuidHex: 'c1'
      })
    );
    await waitFor(() => expect(onRevoked).toHaveBeenCalled());
  });

  it('surfaces a typed error when a revoke rejects, without notifying the parent', async () => {
    const onRevoked = vi.fn();
    invokeMock
      .mockResolvedValueOnce([
        { blockUuidHex: 'b1', blockName: 'Logins', createdAtMs: 0, lastModifiedMs: 0 }
      ]) // ensureLoaded: contact's blocks
      .mockRejectedValueOnce({ code: 'recipient_not_present' }); // revoke_block_from fails

    const contact = { contactUuidHex: 'c1', displayName: 'Alice', sharedBlockCount: 1 };
    const { getByRole, getByText, findByRole } = render(ContactRow, {
      contact,
      onDelete: vi.fn(),
      onRevoked
    });

    await fireEvent.click(getByRole('button', { name: /receives 1 block/i })); // expand
    await waitFor(() => expect(getByText('Logins')).toBeTruthy());
    await fireEvent.click(getByRole('button', { name: /Stop sharing .*Logins.* with Alice/i }));
    await fireEvent.click(getByRole('button', { name: 'Revoke' })); // confirm

    // The typed error is surfaced; the parent badge is NOT refreshed on failure.
    const alert = await findByRole('alert');
    expect(alert.textContent).toMatch(/no longer a recipient/i);
    expect(onRevoked).not.toHaveBeenCalled();
  });
});

describe('ContactRow — revoke write-reauth gate', () => {
  beforeEach(() => {
    invokeMock.mockReset();
    openBlockMock.mockReset();
  });
  afterEach(() => resetReauthGuard());

  it('cancel: guard rejects ReauthCancelled → revoke_block_from NOT called, ConfirmDialog stays open', async () => {
    const onRevoked = vi.fn();
    __setWriteGuardTestSeam({
      readSettings: () => ({ enabled: true, windowMs: 0 }),
      now: () => 0,
      biometricPrefEnabled: () => false,
      tryBiometric: () => Promise.resolve('unavailable' as const),
      prompt: () => Promise.reject(ReauthCancelled)
    });

    invokeMock.mockResolvedValueOnce([
      { blockUuidHex: 'b1', blockName: 'Logins', createdAtMs: 0, lastModifiedMs: 0 }
    ]); // list_contact_blocks

    const testContact = { contactUuidHex: 'c1', displayName: 'Alice', sharedBlockCount: 1 };
    const { getByRole, getByText, container } = render(ContactRow, {
      contact: testContact,
      onDelete: vi.fn(),
      onRevoked
    });

    await fireEvent.click(getByRole('button', { name: /receives 1 block/i })); // expand
    await waitFor(() => expect(getByText('Logins')).toBeTruthy());
    await fireEvent.click(getByRole('button', { name: /Stop sharing .*Logins.* with Alice/i })); // ✕
    await fireEvent.click(getByRole('button', { name: 'Revoke' })); // confirm

    // Guard cancelled → revoke_block_from must NOT have been called; dialog stays open.
    await new Promise((r) => setTimeout(r, 50));
    expect(invokeMock.mock.calls.some(([c]) => c === 'revoke_block_from')).toBe(false);
    expect(onRevoked).not.toHaveBeenCalled();
    // ConfirmDialog must still be present
    expect(container.querySelector('.confirm-dialog__button--danger')).not.toBeNull();
  });

  it('happy: guard resolves → revoke_block_from called once', async () => {
    __setWriteGuardTestSeam({
      readSettings: () => ({ enabled: true, windowMs: 0 }),
      now: () => 0,
      biometricPrefEnabled: () => false,
      tryBiometric: () => Promise.resolve('unavailable' as const),
      prompt: () => Promise.resolve()
    });

    invokeMock
      .mockResolvedValueOnce([
        { blockUuidHex: 'b1', blockName: 'Logins', createdAtMs: 0, lastModifiedMs: 0 }
      ]) // list_contact_blocks
      .mockResolvedValueOnce(undefined) // revoke_block_from
      .mockResolvedValueOnce([]); // list_contact_blocks reload

    const testContact = { contactUuidHex: 'c1', displayName: 'Alice', sharedBlockCount: 1 };
    const { getByRole, getByText } = render(ContactRow, {
      contact: testContact,
      onDelete: vi.fn(),
      onRevoked: vi.fn()
    });

    await fireEvent.click(getByRole('button', { name: /receives 1 block/i })); // expand
    await waitFor(() => expect(getByText('Logins')).toBeTruthy());
    await fireEvent.click(getByRole('button', { name: /Stop sharing .*Logins.* with Alice/i })); // ✕
    await fireEvent.click(getByRole('button', { name: 'Revoke' })); // confirm

    await waitFor(() =>
      expect(invokeMock).toHaveBeenCalledWith('revoke_block_from', {
        blockUuidHex: 'b1',
        recipientUuidHex: 'c1'
      })
    );
  });
});
