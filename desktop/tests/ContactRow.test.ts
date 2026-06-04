// D.1.9 — ContactRow inline reverse map: lazy-fetch the contact's blocks on
// first expand, render them sorted, click a block to open it. Mocks ipc invoke
// and the browse store's openBlock seam.
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));

const { openBlockMock } = vi.hoisted(() => ({ openBlockMock: vi.fn() }));
vi.mock('../src/lib/browse', () => ({ openBlock: openBlockMock }));

import ContactRow from '../src/components/contacts/ContactRow.svelte';

const contact = { contactUuidHex: 'abcd', displayName: 'Alice', sharedBlockCount: 2 };
const noDelete = () => {};

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
    const { getByRole, getByText, queryByText } = render(ContactRow, { contact, onDelete: noDelete });

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
    const { getByRole, getByText } = render(ContactRow, { contact, onDelete: noDelete });
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
    const { getByRole, getByText } = render(ContactRow, { contact, onDelete: noDelete });

    await fireEvent.click(getByRole('button', { name: /Alice/ }));
    await waitFor(() => expect(getByText('Cards')).toBeTruthy());
    await fireEvent.click(getByText('Cards'));

    expect(openBlockMock).toHaveBeenCalledWith(block);
  });

  it('shows an empty state when the contact receives no blocks', async () => {
    invokeMock.mockResolvedValueOnce([]);
    const { getByRole, getByText } = render(ContactRow, {
      contact: { contactUuidHex: 'ee', displayName: 'Eve', sharedBlockCount: 0 },
      onDelete: noDelete
    });
    await fireEvent.click(getByRole('button', { name: /Eve/ }));
    await waitFor(() => expect(getByText(/No shared blocks/i)).toBeTruthy());
  });

  it('surfaces an error when the fetch rejects', async () => {
    invokeMock.mockRejectedValueOnce({ code: 'internal' });
    const { getByRole, findByRole } = render(ContactRow, { contact, onDelete: noDelete });
    await fireEvent.click(getByRole('button', { name: /Alice/ }));
    const alert = await findByRole('alert');
    expect(alert.textContent).toMatch(/internal error/i);
  });

  it('the delete button does not toggle expand', async () => {
    const onDelete = vi.fn();
    const { getByRole, queryByRole } = render(ContactRow, { contact, onDelete });
    await fireEvent.click(getByRole('button', { name: /^Delete$/ }));
    expect(onDelete).toHaveBeenCalledWith(contact);
    expect(invokeMock).not.toHaveBeenCalled(); // expand did not trigger a fetch
    expect(queryByRole('list')).toBeNull();
  });
});
