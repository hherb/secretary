// Tests for App.svelte's router + vault-locked event listener.
//
// Closes issue #149: between Task 5 (backend auto-lock emits the
// `vault-locked` event from two call sites) and Task 6 (frontend pure
// modules shipped), no consumer wired up the listener — so the Rust
// auto-lock would fire server-side but the UI would keep showing
// "unlocked" until the next IPC surfaced `AppError::NotUnlocked`.
//
// This file pins both halves of the contract:
//
//   - the listener is installed at mount, detached at unmount;
//   - `reason: 'auto'`     → autoLockNotice.reason === 'idle';
//   - `reason: 'explicit'` → autoLockNotice.reason === 'manual';
//   - sessionState transitions to `locked` regardless of the reason or
//     the prior state;
//   - the router renders `<Unlock />` when locked, the post-unlock
//     placeholder when unlocked.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, waitFor } from '@testing-library/svelte';
import { get } from 'svelte/store';
import App from '../src/App.svelte';
import {
  sessionState,
  autoLockNotice,
  beginUnlock,
  unlockSucceeded,
  beginLock,
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

// `listen()` returns a `Promise<() => void>` — the resolved value is
// the unlisten function. Capture both the handler (so tests can drive
// it directly) and the unlisten spy (so unmount detachment can be
// asserted).
type EventHandler = (event: { payload: { reason: 'explicit' | 'auto' } }) => void;
const { listenMock, capturedHandlers, unlistenMock, openDialogMock } = vi.hoisted(() => {
  const handlers: EventHandler[] = [];
  return {
    listenMock: vi.fn(),
    capturedHandlers: handlers,
    unlistenMock: vi.fn(),
    openDialogMock: vi.fn()
  };
});
vi.mock('@tauri-apps/api/event', () => ({
  listen: (event: string, handler: EventHandler) => {
    listenMock(event, handler);
    capturedHandlers.push(handler);
    return Promise.resolve(unlistenMock);
  }
}));
vi.mock('@tauri-apps/plugin-dialog', () => ({ open: openDialogMock }));

beforeEach(() => {
  _resetSessionStateForTest();
  listenMock.mockClear();
  unlistenMock.mockClear();
  capturedHandlers.length = 0;
});

describe('App.svelte — router', () => {
  it('renders the Unlock route when sessionState is locked (initial)', () => {
    const { getByRole } = render(App);
    expect(getByRole('heading', { name: /secretary/i })).toBeTruthy();
    expect(getByRole('button', { name: /unlock/i })).toBeTruthy();
  });

  it('renders the Vault route when sessionState is unlocked', () => {
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    const { getByText, getByRole } = render(App);
    // Vault renders TopBar (Lock button) and a block-count label. Both
    // are unique to Vault; the Unlock route renders neither.
    expect(getByRole('button', { name: /lock/i })).toBeTruthy();
    expect(getByText(/0 blocks/i)).toBeTruthy();
  });

  it('renders the Locking… splash when sessionState is locking', () => {
    // App.svelte explicitly handles the brief `locking` transition with
    // its own splash so the UI doesn't flash back to Unlock with stale
    // BlockList data still visible. The backend's `vault-locked` event
    // resolves the state to `locked` within milliseconds.
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    beginLock(0);
    const { getByText } = render(App);
    expect(getByText(/locking…/i)).toBeTruthy();
  });
});

describe('App.svelte — vault-locked event listener (#149)', () => {
  it('subscribes to the vault-locked event at mount', async () => {
    render(App);
    await waitFor(() => expect(listenMock).toHaveBeenCalledTimes(1));
    expect(listenMock).toHaveBeenCalledWith('vault-locked', expect.any(Function));
  });

  it('reason="auto" maps to autoLockNotice.reason="idle" and transitions to locked', async () => {
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    render(App);
    // Wait until the listener has been installed before driving it.
    await waitFor(() => expect(capturedHandlers.length).toBeGreaterThan(0));
    capturedHandlers[0]({ payload: { reason: 'auto' } });

    expect(get(sessionState).status).toBe('locked');
    const notice = get(autoLockNotice);
    expect(notice).not.toBeNull();
    if (notice) {
      expect(notice.reason).toBe('idle');
      expect(typeof notice.at).toBe('number');
    }
  });

  it('reason="explicit" maps to autoLockNotice.reason="manual" and transitions to locked', async () => {
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    render(App);
    await waitFor(() => expect(capturedHandlers.length).toBeGreaterThan(0));
    capturedHandlers[0]({ payload: { reason: 'explicit' } });

    expect(get(sessionState).status).toBe('locked');
    const notice = get(autoLockNotice);
    expect(notice).not.toBeNull();
    if (notice) {
      expect(notice.reason).toBe('manual');
    }
  });

  it('also locks correctly when the event fires from `unlocking` (mid-flight race)', async () => {
    beginUnlock(0);
    render(App);
    await waitFor(() => expect(capturedHandlers.length).toBeGreaterThan(0));
    capturedHandlers[0]({ payload: { reason: 'auto' } });
    // Authoritative `vaultLocked` accepts from any state, including
    // `unlocking` — the backend has decided to lock, frontend follows.
    expect(get(sessionState).status).toBe('locked');
  });

  it('detaches the listener on unmount', async () => {
    const { unmount } = render(App);
    // Wait for the `.then` resolution that stashes `unlisten` so the
    // unmount cleanup takes the synchronous detach branch.
    await waitFor(() => expect(listenMock).toHaveBeenCalled());
    expect(unlistenMock).not.toHaveBeenCalled();
    unmount();
    await waitFor(() => expect(unlistenMock).toHaveBeenCalledTimes(1));
  });
});
