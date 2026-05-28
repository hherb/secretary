// Component-level tests for Unlock.svelte — the first user-visible
// route. Exercises the form-submission lifecycle:
//
//   1. submit disabled until folderPath + password both have content
//   2. happy path: unlockWithPassword → getSettings → unlocked state
//   3. wrong-password path: lastError set, locked state, password cleared
//   4. inline error renders userMessageFor(err).title
//   5. submit ignored while already submitting (no double-fire)

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import { get } from 'svelte/store';
import Unlock from '../src/routes/Unlock.svelte';
import {
  sessionState,
  _resetSessionStateForTest
} from '../src/lib/stores';
import type { ManifestDto, SettingsDto } from '../src/lib/ipc';

const MANIFEST: ManifestDto = {
  vaultUuidHex: 'aa',
  ownerUserUuidHex: 'bb',
  blockCount: 0,
  blockSummaries: [],
  warnings: []
};
const SETTINGS: SettingsDto = { autoLockTimeoutMs: 600_000 };

// Mock the IPC layer + dialog plugin (both used by the form). `vi.hoisted`
// returns the mocks before the `vi.mock` factories run.
const { unlockMock, settingsMock, openDialogMock } = vi.hoisted(() => ({
  unlockMock: vi.fn(),
  settingsMock: vi.fn(),
  openDialogMock: vi.fn()
}));
vi.mock('../src/lib/ipc', async (importActual) => {
  // Keep the real types + APP_ERROR_CODES export shape; override the
  // command wrappers used by Unlock.svelte.
  const actual = await importActual<typeof import('../src/lib/ipc')>();
  return {
    ...actual,
    unlockWithPassword: unlockMock,
    getSettings: settingsMock
  };
});
vi.mock('@tauri-apps/plugin-dialog', () => ({ open: openDialogMock }));

beforeEach(() => {
  _resetSessionStateForTest();
  unlockMock.mockReset();
  settingsMock.mockReset();
  openDialogMock.mockReset();
});

describe('Unlock — initial render', () => {
  it('renders the form heading + password field + submit button', () => {
    const { getByRole, getByLabelText } = render(Unlock);
    expect(getByRole('heading', { name: /secretary/i })).toBeTruthy();
    expect(getByLabelText(/password/i)).toBeTruthy();
    expect(getByRole('button', { name: /unlock/i })).toBeTruthy();
  });

  it('submit button is disabled until both folderPath and password are set', async () => {
    const { getByRole, getByLabelText } = render(Unlock);
    const submitBtn = getByRole('button', { name: /unlock/i }) as HTMLButtonElement;
    expect(submitBtn.disabled).toBe(true);

    // Fill password only — still disabled (no folder).
    const passwordInput = getByLabelText(/password/i) as HTMLInputElement;
    await fireEvent.input(passwordInput, { target: { value: 'hunter2' } });
    expect(submitBtn.disabled).toBe(true);
  });

  it('enables submit when both folder + password are present (via PathPicker)', async () => {
    openDialogMock.mockResolvedValueOnce('/home/alice/vault');
    const { getByRole, getByLabelText } = render(Unlock);

    // Pick folder.
    await fireEvent.click(getByRole('button', { name: /choose/i }));
    await waitFor(() => expect(openDialogMock).toHaveBeenCalled());
    // Fill password.
    const passwordInput = getByLabelText(/password/i) as HTMLInputElement;
    await fireEvent.input(passwordInput, { target: { value: 'hunter2' } });

    const submitBtn = getByRole('button', { name: /unlock/i }) as HTMLButtonElement;
    await waitFor(() => expect(submitBtn.disabled).toBe(false));
  });
});

describe('Unlock — happy path', () => {
  it('submitting calls unlockWithPassword(folder, password) then getSettings, transitions to unlocked', async () => {
    unlockMock.mockResolvedValueOnce(MANIFEST);
    settingsMock.mockResolvedValueOnce(SETTINGS);
    openDialogMock.mockResolvedValueOnce('/home/alice/vault');

    const { getByRole, getByLabelText } = render(Unlock);
    await fireEvent.click(getByRole('button', { name: /choose/i }));
    await waitFor(() => expect(openDialogMock).toHaveBeenCalled());
    await fireEvent.input(getByLabelText(/password/i), { target: { value: 'hunter2' } });
    await fireEvent.click(getByRole('button', { name: /unlock/i }));

    // `waitFor` polls until the assertion passes; this is robust against
    // future IPC-chain link additions in `submit()`, where the previous
    // `await Promise.resolve()` triplet would have silently asserted
    // against a half-resolved state.
    await waitFor(() => expect(get(sessionState).status).toBe('unlocked'));

    expect(unlockMock).toHaveBeenCalledTimes(1);
    expect(unlockMock).toHaveBeenCalledWith('/home/alice/vault', 'hunter2');
    expect(settingsMock).toHaveBeenCalledTimes(1);

    const s = get(sessionState);
    if (s.status === 'unlocked') {
      expect(s.manifest).toEqual(MANIFEST);
      expect(s.settings).toEqual(SETTINGS);
    }
  });

  it('clears the password field after successful unlock (do not retain in DOM)', async () => {
    unlockMock.mockResolvedValueOnce(MANIFEST);
    settingsMock.mockResolvedValueOnce(SETTINGS);
    openDialogMock.mockResolvedValueOnce('/v');

    const { getByRole, getByLabelText } = render(Unlock);
    await fireEvent.click(getByRole('button', { name: /choose/i }));
    await waitFor(() => expect(openDialogMock).toHaveBeenCalled());
    const passwordInput = getByLabelText(/password/i) as HTMLInputElement;
    await fireEvent.input(passwordInput, { target: { value: 'hunter2' } });
    await fireEvent.click(getByRole('button', { name: /unlock/i }));
    await waitFor(() => expect(passwordInput.value).toBe(''));
  });
});

describe('Unlock — error path', () => {
  it('wrong_password transitions to locked, sets lastError, surfaces userMessageFor.title', async () => {
    unlockMock.mockRejectedValueOnce({ code: 'wrong_password' });
    openDialogMock.mockResolvedValueOnce('/v');

    const { getByRole, getByLabelText, findByText } = render(Unlock);
    await fireEvent.click(getByRole('button', { name: /choose/i }));
    await waitFor(() => expect(openDialogMock).toHaveBeenCalled());
    await fireEvent.input(getByLabelText(/password/i), { target: { value: 'bad' } });
    await fireEvent.click(getByRole('button', { name: /unlock/i }));
    await waitFor(() => expect(get(sessionState).status).toBe('locked'));

    const s = get(sessionState);
    if (s.status === 'locked') {
      expect(s.lastError).toEqual({ code: 'wrong_password' });
    }
    // Inline error shows "Wrong password" — the title from
    // userMessageFor({ code: 'wrong_password' }).
    expect(await findByText(/wrong password/i)).toBeTruthy();
    expect(settingsMock).not.toHaveBeenCalled();
  });

  it('clears the password field on unlock failure (do not retain in DOM across retry)', async () => {
    // Security pin: the password string must not linger in the DOM
    // binding after a failed attempt. JS strings are immutable so we
    // can't truly zeroize, but unbinding minimises the live-reference
    // window the GC has to chase.
    unlockMock.mockRejectedValueOnce({ code: 'wrong_password' });
    openDialogMock.mockResolvedValueOnce('/v');

    const { getByRole, getByLabelText } = render(Unlock);
    await fireEvent.click(getByRole('button', { name: /choose/i }));
    await waitFor(() => expect(openDialogMock).toHaveBeenCalled());
    const passwordInput = getByLabelText(/password/i) as HTMLInputElement;
    await fireEvent.input(passwordInput, { target: { value: 'bad' } });
    await fireEvent.click(getByRole('button', { name: /unlock/i }));
    await waitFor(() => expect(passwordInput.value).toBe(''));
  });

  it('vault_path_not_found surfaces the path in the inline detail', async () => {
    const path = '/no/such/vault';
    unlockMock.mockRejectedValueOnce({ code: 'vault_path_not_found', path });
    openDialogMock.mockResolvedValueOnce(path);

    const { getByRole, getByLabelText, findByText } = render(Unlock);
    await fireEvent.click(getByRole('button', { name: /choose/i }));
    await waitFor(() => expect(openDialogMock).toHaveBeenCalled());
    await fireEvent.input(getByLabelText(/password/i), { target: { value: 'x' } });
    await fireEvent.click(getByRole('button', { name: /unlock/i }));
    await waitFor(() => expect(get(sessionState).status).toBe('locked'));

    expect(await findByText(new RegExp(path))).toBeTruthy();
  });
});

describe('Unlock — submit guards', () => {
  it('submit is a no-op when form is invalid (empty fields)', async () => {
    const { getByRole } = render(Unlock);
    // Force-click via dispatching submit on the form. The button is
    // disabled — click is ignored — but the keyboard "Enter" path
    // would dispatch on the form. Use the form directly to simulate.
    const form = getByRole('button', { name: /unlock/i }).closest('form');
    expect(form).toBeTruthy();
    if (form) {
      await fireEvent.submit(form);
    }
    expect(unlockMock).not.toHaveBeenCalled();
  });
});
