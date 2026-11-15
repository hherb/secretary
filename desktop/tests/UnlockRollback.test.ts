// #746: the "This vault looks older than expected" confirmation on the Unlock
// route. An unlock refused with `rollback_detected` must show the shared copy
// with an explicit "Reset and open" / "Cancel" pair. Nothing happens without
// the user's click: Cancel calls no command, and only Reset and open invokes
// `resetSyncStateAndUnlock` with the password the user just typed.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import { get } from 'svelte/store';
import Unlock from '../src/routes/Unlock.svelte';
import { sessionState, _resetSessionStateForTest } from '../src/lib/stores';
import type { ManifestDto, SettingsDto } from '../src/lib/ipc';

const MANIFEST: ManifestDto = {
  vaultUuidHex: 'aa',
  ownerUserUuidHex: 'bb',
  blockCount: 0,
  blockSummaries: [],
  warnings: []
};
const SETTINGS: SettingsDto = {
  autoLockTimeoutMs: 600_000,
  requirePasswordBeforeEdits: false,
  reauthGraceWindowMs: 120_000,
  retentionWindowMs: 7_776_000_000
};
const FOLDER = '/home/alice/vault';
const PASSWORD = 'hunter2';
const TITLE = 'This vault looks older than expected';
const BODY =
  'This device last saw a newer version of this vault. That can happen after restoring a backup, but it can also mean your storage provider is serving an old copy. Only continue if you restored this vault from a backup or are sure this copy is current.';

const { unlockMock, resetMock, settingsMock, invokeMock, recentMock } = vi.hoisted(() => ({
  unlockMock: vi.fn(),
  resetMock: vi.fn(),
  settingsMock: vi.fn(),
  invokeMock: vi.fn(),
  recentMock: vi.fn()
}));
vi.mock('../src/lib/ipc', async (importActual) => {
  const actual = await importActual<typeof import('../src/lib/ipc')>();
  return {
    ...actual,
    unlockWithPassword: unlockMock,
    resetSyncStateAndUnlock: resetMock,
    getSettings: settingsMock,
    useRecentVault: recentMock
  };
});
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));

beforeEach(() => {
  _resetSessionStateForTest();
  unlockMock.mockReset();
  resetMock.mockReset();
  settingsMock.mockReset();
  invokeMock.mockReset();
  recentMock.mockReset();
  recentMock.mockResolvedValue(null);
});

/** Render Unlock, pick FOLDER, type PASSWORD and submit an unlock that fails
 *  with `rollback_detected`. */
async function renderRefusedUnlock() {
  unlockMock.mockRejectedValueOnce({ code: 'rollback_detected' });
  invokeMock.mockResolvedValueOnce(FOLDER);
  const view = render(Unlock);
  await fireEvent.click(view.getByRole('button', { name: /choose/i }));
  await waitFor(() => expect(invokeMock).toHaveBeenCalled());
  await fireEvent.input(view.getByLabelText(/password/i), { target: { value: PASSWORD } });
  await fireEvent.click(view.getByRole('button', { name: /^unlock$/i }));
  await waitFor(() => expect(get(sessionState).status).toBe('locked'));
  return view;
}

describe('Unlock — #746 rollback_detected confirmation', () => {
  it('shows the shared copy with Reset and open + Cancel, and calls nothing yet', async () => {
    const { findByRole, getByRole, getByText, getByLabelText } = await renderRefusedUnlock();

    expect(await findByRole('button', { name: 'Reset and open' })).toBeTruthy();
    expect(getByRole('button', { name: 'Cancel' })).toBeTruthy();
    expect(getByText(TITLE)).toBeTruthy();
    expect(getByText(BODY)).toBeTruthy();
    expect(resetMock).not.toHaveBeenCalled();
    // The confirmation reuses the typed password, so it stays bound.
    expect((getByLabelText(/password/i) as HTMLInputElement).value).toBe(PASSWORD);
  });

  it('Cancel invokes no command, hides the confirmation and clears the password', async () => {
    const { findByRole, getByLabelText, queryByRole } = await renderRefusedUnlock();

    await findByRole('button', { name: 'Cancel' });
    const invokesBefore = invokeMock.mock.calls.length;
    await fireEvent.click(await findByRole('button', { name: 'Cancel' }));

    expect(resetMock).not.toHaveBeenCalled();
    expect(unlockMock).toHaveBeenCalledTimes(1);
    expect(invokeMock.mock.calls.length).toBe(invokesBefore);
    expect(queryByRole('button', { name: 'Reset and open' })).toBeNull();
    expect((getByLabelText(/password/i) as HTMLInputElement).value).toBe('');
    expect(get(sessionState).status).toBe('locked');
  });

  it('choosing another folder withdraws the confirmation', async () => {
    const { findByRole, getByRole, queryByRole } = await renderRefusedUnlock();
    await findByRole('button', { name: 'Reset and open' });

    invokeMock.mockResolvedValueOnce('/home/alice/other-vault');
    await fireEvent.click(getByRole('button', { name: /choose/i }));

    await waitFor(() => expect(queryByRole('button', { name: 'Reset and open' })).toBeNull());
    expect(resetMock).not.toHaveBeenCalled();
  });

  it('Reset and open invokes the reset command with the typed password and unlocks', async () => {
    resetMock.mockResolvedValueOnce(MANIFEST);
    settingsMock.mockResolvedValueOnce(SETTINGS);
    const { findByRole } = await renderRefusedUnlock();

    await fireEvent.click(await findByRole('button', { name: 'Reset and open' }));

    await waitFor(() => expect(get(sessionState).status).toBe('unlocked'));
    expect(resetMock).toHaveBeenCalledTimes(1);
    expect(resetMock).toHaveBeenCalledWith(FOLDER, PASSWORD);
    expect(unlockMock).toHaveBeenCalledTimes(1);
  });

  it('a failed reset returns to locked with its own error and no confirmation', async () => {
    resetMock.mockRejectedValueOnce({ code: 'wrong_password' });
    const { findByRole, queryByRole, getByLabelText } = await renderRefusedUnlock();

    await fireEvent.click(await findByRole('button', { name: 'Reset and open' }));

    await waitFor(() => {
      const s = get(sessionState);
      expect(s.status === 'locked' && s.lastError?.code).toBe('wrong_password');
    });
    expect(queryByRole('button', { name: 'Reset and open' })).toBeNull();
    expect((getByLabelText(/password/i) as HTMLInputElement).value).toBe('');
  });

  it('other unlock errors show no confirmation', async () => {
    unlockMock.mockRejectedValueOnce({ code: 'wrong_password' });
    invokeMock.mockResolvedValueOnce(FOLDER);
    const { getByRole, getByLabelText, queryByRole } = render(Unlock);
    await fireEvent.click(getByRole('button', { name: /choose/i }));
    await waitFor(() => expect(invokeMock).toHaveBeenCalled());
    await fireEvent.input(getByLabelText(/password/i), { target: { value: PASSWORD } });
    await fireEvent.click(getByRole('button', { name: /^unlock$/i }));
    await waitFor(() => expect(get(sessionState).status).toBe('locked'));

    expect(queryByRole('button', { name: 'Reset and open' })).toBeNull();
  });
});
