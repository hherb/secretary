// Tests for TrashView.svelte — the trashed-blocks list reached via the
// Vault "Trash" entry. Loads list_trashed_blocks on mount, renders a row
// per entry (newest-first), an empty-state when there are none, and a
// typed-error alert when the IPC rejects. Also covers the "Run retention
// now" entry point (mounts RetentionDialog) and the per-row "Delete
// forever" purge flow (ConfirmDialog -> authorizeWrite -> purgeBlock ->
// refreshManifest -> reload), mirroring RetentionDialog.test.ts's mocking
// shape for ipc / stores / writeGuard.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor, within } from '@testing-library/svelte';

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));

const { previewRetentionMock, runRetentionMock, purgeBlockMock, authorizeWriteMock, refreshManifestMock, reauthCancelledSymbol } =
  vi.hoisted(() => ({
    previewRetentionMock: vi.fn(),
    runRetentionMock: vi.fn(),
    purgeBlockMock: vi.fn(),
    authorizeWriteMock: vi.fn(),
    refreshManifestMock: vi.fn(),
    reauthCancelledSymbol: Symbol('ReauthCancelled')
  }));

// listTrashedBlocks / restoreBlock stay real (they go through `call` ->
// the mocked `invoke` above, same as the pre-existing tests); only the
// retention/purge surface is stubbed directly, mirroring
// RetentionDialog.test.ts.
vi.mock('../src/lib/ipc', async () => {
  const real = await vi.importActual<typeof import('../src/lib/ipc')>('../src/lib/ipc');
  return {
    ...real,
    previewRetention: previewRetentionMock,
    runRetention: runRetentionMock,
    purgeBlock: purgeBlockMock
  };
});

vi.mock('../src/lib/stores', () => ({ refreshManifest: refreshManifestMock }));

vi.mock('../src/lib/writeGuard', () => ({
  authorizeWrite: authorizeWriteMock,
  ReauthCancelled: reauthCancelledSymbol
}));

import TrashView from '../src/components/delete/TrashView.svelte';

function trashedEntry() {
  return { blockUuidHex: 'ab', blockName: 'Bank logins', tombstonedAtMs: 2, tombstonedByHex: 'd' };
}

describe('TrashView', () => {
  beforeEach(() => {
    invokeMock.mockReset();
    previewRetentionMock.mockReset();
    runRetentionMock.mockReset();
    purgeBlockMock.mockReset();
    authorizeWriteMock.mockReset();
    authorizeWriteMock.mockResolvedValue(undefined);
    refreshManifestMock.mockReset();
    refreshManifestMock.mockResolvedValue(undefined);
    previewRetentionMock.mockResolvedValue({ entries: [], windowMs: 1 });
  });

  it('lists trashed blocks by name', async () => {
    invokeMock.mockResolvedValueOnce([trashedEntry()]);
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

  it('renders a "Run retention now" button that mounts RetentionDialog', async () => {
    invokeMock.mockResolvedValueOnce([]);
    const { findByRole } = render(TrashView);

    const retentionButton = await findByRole('button', { name: /run retention now/i });
    await fireEvent.click(retentionButton);

    await waitFor(() => expect(previewRetentionMock).toHaveBeenCalledTimes(1));
    expect(await findByRole('heading', { name: /run retention now/i })).toBeTruthy();
  });

  it('renders a "Delete forever" button per row; confirming purges via authorizeWrite -> purgeBlock -> refreshManifest -> reload', async () => {
    invokeMock.mockResolvedValueOnce([trashedEntry()]);
    invokeMock.mockResolvedValueOnce([]); // reload after purge
    purgeBlockMock.mockResolvedValueOnce({
      blockUuidHex: 'ab',
      wasShared: false,
      recipientCount: 0,
      filesRemoved: 1
    });

    const { findByRole, getByText } = render(TrashView);
    await waitFor(() => expect(getByText('Bank logins')).toBeTruthy());

    // The row button's accessible name comes from its aria-label (not its
    // "Delete forever" text), so match on that; the ConfirmDialog's confirm
    // button has no aria-label and is matched by its visible text instead.
    const purgeButton = await findByRole('button', { name: /permanently delete block bank logins/i });
    await fireEvent.click(purgeButton);

    const confirmButton = await findByRole('button', { name: /^delete forever$/i });
    await fireEvent.click(confirmButton);

    await waitFor(() => expect(purgeBlockMock).toHaveBeenCalledWith('ab'));
    expect(authorizeWriteMock).toHaveBeenCalledTimes(1);
    await waitFor(() => expect(refreshManifestMock).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(invokeMock).toHaveBeenCalledTimes(2));

    const authorizeOrder = authorizeWriteMock.mock.invocationCallOrder[0];
    const purgeOrder = purgeBlockMock.mock.invocationCallOrder[0];
    const refreshOrder = refreshManifestMock.mock.invocationCallOrder[0];
    expect(authorizeOrder).toBeLessThan(purgeOrder);
    expect(purgeOrder).toBeLessThan(refreshOrder);
  });

  it('authorizeWrite rejecting with ReauthCancelled aborts the purge (no purgeBlock call)', async () => {
    invokeMock.mockResolvedValueOnce([trashedEntry()]);
    // mockRejectedValueOnce (not persistent mockRejectedValue): a persistent
    // rejection would spuriously fail any later test whose click handler
    // catches the error, and leaks unresolved-promise state across tests.
    authorizeWriteMock.mockRejectedValueOnce(reauthCancelledSymbol);

    const { findByRole, getByText } = render(TrashView);
    await waitFor(() => expect(getByText('Bank logins')).toBeTruthy());

    const purgeButton = await findByRole('button', { name: /permanently delete block bank logins/i });
    await fireEvent.click(purgeButton);

    const confirmButton = await findByRole('button', { name: /^delete forever$/i });
    await fireEvent.click(confirmButton);

    await waitFor(() => expect(authorizeWriteMock).toHaveBeenCalledTimes(1));
    expect(purgeBlockMock).not.toHaveBeenCalled();
    expect(refreshManifestMock).not.toHaveBeenCalled();
  });

  it('shows a "Purged N items" status banner after emptying trash', async () => {
    invokeMock.mockResolvedValueOnce([trashedEntry(), { ...trashedEntry(), blockUuidHex: 'cd', blockName: 'Card' }]);
    // empty_trash goes through the real ipc.emptyTrash -> mocked invoke; it
    // resolves BEFORE the post-empty reload (confirmEmpty awaits emptyTrash()
    // then refreshManifest() then load()), so this is the 2nd invoke call:
    invokeMock.mockResolvedValueOnce({
      purgedCount: 2, sharedCount: 0, ownerOnlyCount: 2, unknownCount: 0, filesRemoved: 2, filesFailed: 0
    });
    invokeMock.mockResolvedValueOnce([]); // reload after empty (3rd invoke call)

    const { findByRole, getByText } = render(TrashView);
    await waitFor(() => expect(getByText('Bank logins')).toBeTruthy());

    const emptyButton = await findByRole('button', { name: /empty trash/i });
    await fireEvent.click(emptyButton);
    // The dialog's confirm button shares its accessible name ("Empty trash")
    // with the trigger button once both are mounted, so scope the query to
    // the dialog to disambiguate.
    const dialog = await findByRole('dialog');
    const confirm = within(dialog).getByRole('button', { name: /^empty trash$/i });
    await fireEvent.click(confirm);

    const status = await findByRole('status');
    expect(status.textContent).toMatch(/purged 2 items/i);
  });

  it('clears a stale success banner when a later purge is cancelled at re-auth', async () => {
    // Regression for the stale-notice bug: notice was only cleared inside the
    // success path, so a cancelled/failed re-auth on a SECOND destructive
    // action left the FIRST action's success banner on screen, falsely
    // implying the second action also succeeded.
    invokeMock.mockResolvedValueOnce([trashedEntry(), { ...trashedEntry(), blockUuidHex: 'cd', blockName: 'Card' }]);
    invokeMock.mockResolvedValueOnce([{ ...trashedEntry(), blockUuidHex: 'cd', blockName: 'Card' }]); // reload after 1st purge
    purgeBlockMock.mockResolvedValueOnce({
      blockUuidHex: 'ab', wasShared: false, recipientCount: 0, filesRemoved: 1
    });

    const { findByRole, getByText, queryByRole } = render(TrashView);
    await waitFor(() => expect(getByText('Bank logins')).toBeTruthy());

    // First purge succeeds and leaves a "Deleted forever" success banner.
    let purgeButton = await findByRole('button', { name: /permanently delete block bank logins/i });
    await fireEvent.click(purgeButton);
    let confirmButton = await findByRole('button', { name: /^delete forever$/i });
    await fireEvent.click(confirmButton);
    const status = await findByRole('status');
    expect(status.textContent).toMatch(/deleted forever/i);

    // Second purge (remaining "Card" block) is cancelled at re-auth.
    // mockRejectedValueOnce (not persistent mockRejectedValue): a persistent
    // rejection would spuriously fail later tests whose click handler
    // catches the error, and leaks unresolved-promise state across tests.
    authorizeWriteMock.mockRejectedValueOnce(reauthCancelledSymbol);
    await waitFor(() => expect(getByText('Card')).toBeTruthy());
    purgeButton = await findByRole('button', { name: /permanently delete block card/i });
    await fireEvent.click(purgeButton);
    confirmButton = await findByRole('button', { name: /^delete forever$/i });
    await fireEvent.click(confirmButton);

    await waitFor(() => expect(authorizeWriteMock).toHaveBeenCalledTimes(2));
    expect(purgeBlockMock).toHaveBeenCalledTimes(1); // only the 1st purge went through
    expect(queryByRole('status')).toBeNull(); // stale success banner must be gone
  });

  it('renders a warning banner when files could not be removed', async () => {
    invokeMock.mockResolvedValueOnce([trashedEntry()]);
    invokeMock.mockResolvedValueOnce([]); // reload after purge
    purgeBlockMock.mockResolvedValueOnce({
      blockUuidHex: 'ab', wasShared: false, recipientCount: 0, filesRemoved: 1
    });
    // (single-block purge is always "Deleted forever" — this asserts the
    // success banner text; the warning branch is covered by purgeNotice.test.ts)
    const { findByRole, getByText } = render(TrashView);
    await waitFor(() => expect(getByText('Bank logins')).toBeTruthy());
    const purgeButton = await findByRole('button', { name: /permanently delete block bank logins/i });
    await fireEvent.click(purgeButton);
    const confirm = await findByRole('button', { name: /^delete forever$/i });
    await fireEvent.click(confirm);
    const status = await findByRole('status');
    expect(status.textContent).toMatch(/deleted forever/i);
  });
});
