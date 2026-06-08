import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import SyncPasswordDialog from '../src/components/SyncPasswordDialog.svelte';
import * as ipc from '../src/lib/ipc';

vi.mock('../src/lib/ipc', async (orig) => ({
  ...(await orig<typeof ipc>()),
  syncNow: vi.fn()
}));
const mockSyncNow = vi.mocked(ipc.syncNow);

function renderDialog(overrides: Record<string, unknown> = {}) {
  const onSynced = vi.fn();
  const onConflicts = vi.fn();
  const onCancel = vi.fn();
  const utils = render(SyncPasswordDialog, {
    props: { onSynced, onConflicts, onCancel, ...overrides }
  });
  return { ...utils, onSynced, onConflicts, onCancel };
}

describe('SyncPasswordDialog.svelte', () => {
  beforeEach(() => mockSyncNow.mockReset());

  it('opens a modal with a password field and a Sync button', async () => {
    const { container, getByLabelText, getByRole } = renderDialog();
    await waitFor(() => {
      const dialog = container.querySelector('dialog') as HTMLDialogElement;
      expect(dialog.hasAttribute('open')).toBe(true);
    });
    expect(getByLabelText(/password/i)).toBeTruthy();
    expect(getByRole('button', { name: /sync/i })).toBeTruthy();
  });

  it('calls syncNow with the typed password and onSynced with the outcome', async () => {
    mockSyncNow.mockResolvedValue({ kind: 'nothingToDo' });
    const { getByLabelText, getByRole, onSynced } = renderDialog();
    await fireEvent.input(getByLabelText(/password/i), { target: { value: 'hunter2' } });
    await fireEvent.click(getByRole('button', { name: /^sync$/i }));
    await waitFor(() => expect(mockSyncNow).toHaveBeenCalledWith('hunter2'));
    expect(onSynced).toHaveBeenCalledWith({ kind: 'nothingToDo' });
  });

  it('renders the typed error inline and stays open on failure', async () => {
    // `...Once` (not the persistent `mockRejectedValue`) avoids a Vitest
    // unhandled-rejection that fails this test even though it is caught.
    mockSyncNow.mockRejectedValueOnce({ code: 'wrong_password' });
    const { getByLabelText, getByRole, findByRole, onSynced } = renderDialog();
    await fireEvent.input(getByLabelText(/password/i), { target: { value: 'bad' } });
    await fireEvent.click(getByRole('button', { name: /^sync$/i }));
    const alert = await findByRole('alert');
    expect(alert.textContent).toMatch(/wrong password/i);
    expect(onSynced).not.toHaveBeenCalled();
  });

  it('routes a conflictsPending outcome to onConflicts with the password', async () => {
    const outcome = {
      kind: 'conflictsPending' as const,
      vetoes: [
        {
          recordUuidHex: 'aa',
          recordType: 'login',
          tags: [],
          fieldNames: ['password'],
          localLastModMs: 1,
          peerTombstonedAtMs: 2,
          peerDeviceHex: 'beef'
        }
      ],
      collisions: [],
      manifestHash: [1]
    };
    mockSyncNow.mockResolvedValueOnce(outcome);
    const { getByLabelText, getByRole, onConflicts, onSynced } = renderDialog();
    await fireEvent.input(getByLabelText(/password/i), { target: { value: 'thepassword' } });
    await fireEvent.click(getByRole('button', { name: /^sync$/i }));
    await waitFor(() => expect(onConflicts).toHaveBeenCalledWith(outcome, 'thepassword'));
    expect(onSynced).not.toHaveBeenCalled();
  });

  it('fires onCancel when Cancel is clicked, without syncing', async () => {
    const { getByRole, onCancel } = renderDialog();
    await fireEvent.click(getByRole('button', { name: /cancel/i }));
    expect(onCancel).toHaveBeenCalledTimes(1);
    expect(mockSyncNow).not.toHaveBeenCalled();
  });
});
