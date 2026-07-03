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
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import { get } from 'svelte/store';
import App from '../src/App.svelte';
import {
  sessionState,
  autoLockNotice,
  beginUnlock,
  unlockSucceeded,
  settingsUpdated,
  beginLock,
  vaultLocked,
  _resetSessionStateForTest
} from '../src/lib/stores';
import { browseNav, openBlock, resetBrowse } from '../src/lib/browse';
import type { ManifestDto, SettingsDto } from '../src/lib/ipc';
import type { AutoLockNotice } from '../src/lib/stores';

const MANIFEST: ManifestDto = {
  vaultUuidHex: 'aa',
  ownerUserUuidHex: 'bb',
  blockCount: 0,
  blockSummaries: [],
  warnings: []
};
const SETTINGS: SettingsDto = { autoLockTimeoutMs: 600_000, requirePasswordBeforeEdits: false, reauthGraceWindowMs: 120_000 };

// `listen()` returns a `Promise<() => void>` — the resolved value is
// the unlisten function. Capture both the handler (so tests can drive
// it directly) and the unlisten spy (so unmount detachment can be
// asserted).
type EventHandler = (event: { payload: { reason: 'explicit' | 'auto' } }) => void;
const {
  listenMock,
  capturedHandlers,
  unlistenMock,
  invokeMock,
  startActivityTrackingMock,
  stopActivityTrackingMock
} = vi.hoisted(() => {
  const handlers: EventHandler[] = [];
  return {
    listenMock: vi.fn(),
    capturedHandlers: handlers,
    unlistenMock: vi.fn(),
    invokeMock: vi.fn(),
    // `startActivityTracking()` returns a cleanup fn — capture both so
    // tests can assert lifecycle (call counts on each).
    startActivityTrackingMock: vi.fn(),
    stopActivityTrackingMock: vi.fn()
  };
});
vi.mock('@tauri-apps/api/event', () => ({
  listen: (event: string, handler: EventHandler) => {
    listenMock(event, handler);
    capturedHandlers.push(handler);
    return Promise.resolve(unlistenMock);
  }
}));
// App.svelte's Unlock route renders PathPicker, which invokes backend
// pick_* commands directly via `@tauri-apps/api/core` (#353).
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));
// Mock `lib/auto_lock` so App's $effect-driven start/stop lifecycle can
// be asserted without installing real document-level listeners. The
// returned cleanup fn is the spy the test inspects to confirm App
// invoked it on the way out of `unlocked`.
vi.mock('../src/lib/auto_lock', () => ({
  startActivityTracking: () => {
    startActivityTrackingMock();
    return stopActivityTrackingMock;
  }
}));

beforeEach(() => {
  _resetSessionStateForTest();
  resetBrowse();
  listenMock.mockClear();
  unlistenMock.mockClear();
  capturedHandlers.length = 0;
  startActivityTrackingMock.mockClear();
  stopActivityTrackingMock.mockClear();
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
    const { getByText, container } = render(App);
    // Vault renders TopBar (Lock button) and a block-count label. Both
    // are unique to Vault; the Unlock route renders neither.
    // Use the class selector to distinguish the LockButton from the
    // "+ New block" button added in D.1.4 (both match /lock/i).
    expect(container.querySelector('.lock-button')).toBeTruthy();
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

  it('reason="explicit" transitions to locked and does NOT raise autoLockNotice', async () => {
    // The producer-side filter in stores.ts::vaultLocked drops the
    // notice write for 'manual' (the mapped frontend reason for an
    // explicit user-lock). State still transitions to locked; the
    // toast surface stays silent — the user clicked Lock themselves
    // and doesn't need a confirmation banner. See the AutoLockNotice
    // union doc-comment in stores.ts for the altitude argument.
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    render(App);
    await waitFor(() => expect(capturedHandlers.length).toBeGreaterThan(0));
    capturedHandlers[0]({ payload: { reason: 'explicit' } });

    expect(get(sessionState).status).toBe('locked');
    expect(get(autoLockNotice)).toBeNull();
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

  it('vault-locked resets browseNav to blocks (lock-clears-browse, Task 6)', async () => {
    // Security contract: a revealed FieldViewer/FieldRow must not survive
    // a vault lock. App.svelte calls resetBrowse() in the vault-locked
    // listener BEFORE vaultLocked(notice), so FieldViewer/FieldRow unmount
    // and their reveal/clipboard timers are cancelled.
    //
    // Drive the contract at the App mount level (strongest form): render
    // App, drill into a block so browseNav.level === 'records', then fire
    // the captured vault-locked handler and assert the level resets.
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    render(App);
    await waitFor(() => expect(capturedHandlers.length).toBeGreaterThan(0));

    // Simulate having navigated into a block (records level).
    openBlock({ blockUuidHex: 'ab', blockName: 'B', createdAtMs: 1, lastModifiedMs: 2 });
    expect(get(browseNav).level).toBe('records');

    // Fire the backend vault-locked event (auto-lock path).
    capturedHandlers[0]({ payload: { reason: 'auto' } });

    // browseNav must have reset to `blocks` so no revealed field survives.
    expect(get(browseNav).level).toBe('blocks');
    // Session must also have transitioned to locked.
    expect(get(sessionState).status).toBe('locked');
  });
});

describe('App.svelte — activity-tracking lifecycle (Task 10)', () => {
  // Activity tracking (document-level mousemove + keydown listeners,
  // debounced into `notifyActivity` IPC) must be active iff the session
  // is `unlocked`. Starting it on `locked` would attach listeners we
  // never use; leaving it running after a lock would keep the page
  // touching the IPC mutex while the backend is already locked.

  it('does not start activity tracking while the session is locked', () => {
    render(App);
    // Initial state is `locked` — App must not start tracking.
    expect(startActivityTrackingMock).not.toHaveBeenCalled();
  });

  it('starts activity tracking when the session enters `unlocked`', async () => {
    render(App);
    expect(startActivityTrackingMock).not.toHaveBeenCalled();

    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);

    await waitFor(() => expect(startActivityTrackingMock).toHaveBeenCalledTimes(1));
  });

  it('mounting App while already unlocked starts activity tracking exactly once', async () => {
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    render(App);
    await waitFor(() => expect(startActivityTrackingMock).toHaveBeenCalledTimes(1));
    expect(stopActivityTrackingMock).not.toHaveBeenCalled();
  });

  it('stops activity tracking when the session leaves `unlocked`', async () => {
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    render(App);
    await waitFor(() => expect(startActivityTrackingMock).toHaveBeenCalledTimes(1));

    // Backend-driven lock — drive the captured event handler.
    capturedHandlers[0]({ payload: { reason: 'auto' } });

    await waitFor(() => expect(stopActivityTrackingMock).toHaveBeenCalledTimes(1));
  });

  it('does not double-start activity tracking on settings update (unlocked → unlocked)', async () => {
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    render(App);
    await waitFor(() => expect(startActivityTrackingMock).toHaveBeenCalledTimes(1));

    // settingsUpdated transitions unlocked → unlocked. The status didn't
    // change, so the activity-tracking lifecycle must not restart —
    // otherwise the dialog's Save flow would tear down + re-install
    // document listeners on every settings change.
    settingsUpdated({ autoLockTimeoutMs: 300_000, requirePasswordBeforeEdits: false, reauthGraceWindowMs: 120_000 });

    // Give any racy $effect a tick to settle before asserting.
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(startActivityTrackingMock).toHaveBeenCalledTimes(1);
    expect(stopActivityTrackingMock).not.toHaveBeenCalled();
  });

  it('stops activity tracking on unmount when unlocked', async () => {
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    const { unmount } = render(App);
    await waitFor(() => expect(startActivityTrackingMock).toHaveBeenCalledTimes(1));
    expect(stopActivityTrackingMock).not.toHaveBeenCalled();

    unmount();
    // $effect cleanup runs on unmount; tracking stops so document
    // listeners don't outlive the component tree.
    await waitFor(() => expect(stopActivityTrackingMock).toHaveBeenCalledTimes(1));
  });
});

describe('App.svelte — Toast rendering (Task 10)', () => {
  // The Toast component is mounted under `{#if $autoLockNotice}` so the
  // backend `vault-locked` event (idle) surfaces the spec §12 notice.
  // `manual` is filtered out — user clicked Lock themselves; no toast.
  // `keep_alive_failing` (raised by lib/auto_lock.ts) gets a toast.

  it('does not render Toast when autoLockNotice is null', () => {
    const { queryByRole } = render(App);
    expect(get(autoLockNotice)).toBeNull();
    // Toast uses role="status"; the only other status role in App is
    // the Locking… splash (queried with aria-live="polite" too). Use a
    // text match to disambiguate.
    expect(queryByRole('button', { name: /dismiss/i })).toBeNull();
  });

  it('renders Toast with idle copy after an auto-lock event', async () => {
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    const { findByText } = render(App);
    await waitFor(() => expect(capturedHandlers.length).toBeGreaterThan(0));

    capturedHandlers[0]({ payload: { reason: 'auto' } });

    expect(await findByText(/auto-locked due to inactivity/i)).toBeTruthy();
  });

  it('does NOT render Toast after an explicit-lock event (notice never raised)', async () => {
    // Producer-side filter: vaultLocked('manual') leaves autoLockNotice
    // untouched, so no Toast mounts. Pinned at the rendering layer to
    // complement the stores.test.ts "does NOT raise" assertion — the
    // contract spans store + UI, and a regression at either site needs
    // to surface in a test that runs against the full mount.
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    const { queryByText } = render(App);
    await waitFor(() => expect(capturedHandlers.length).toBeGreaterThan(0));

    capturedHandlers[0]({ payload: { reason: 'explicit' } });

    expect(get(autoLockNotice)).toBeNull();
    // Microtask drain so any pending Toast mount could appear.
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(queryByText(/auto-locked due to inactivity/i)).toBeNull();
    expect(queryByText(/activity tracking is failing/i)).toBeNull();
  });

  it('renders Toast with keep_alive_failing copy when that notice is set directly', async () => {
    // `lib/auto_lock.ts` raises this notice independently of the
    // backend event — it's a frontend-driven heads-up that the
    // IPC keep-alive is failing repeatedly.
    const notice: AutoLockNotice = { reason: 'keep_alive_failing', at: 1_000 };
    autoLockNotice.set(notice);

    const { findByText } = render(App);
    expect(await findByText(/activity tracking is failing/i)).toBeTruthy();
  });

  it('clicking × on the toast clears the notice and unmounts the toast', async () => {
    const notice: AutoLockNotice = { reason: 'idle', at: 1_000 };
    autoLockNotice.set(notice);

    const { findByRole, queryByRole } = render(App);
    const dismiss = await findByRole('button', { name: /dismiss/i });

    await fireEvent.click(dismiss);

    expect(get(autoLockNotice)).toBeNull();
    // After the store clears, the {#if} branch unmounts the toast.
    await waitFor(() => expect(queryByRole('button', { name: /dismiss/i })).toBeNull());
  });

  it('autonomous vaultLocked(idle) (no Tauri event) also surfaces the toast', async () => {
    // Defence in depth: any path that lands in `idle` via vaultLocked
    // (e.g. a future direct-call site) should still show the toast,
    // because the surface is store-driven, not event-driven.
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    const { findByText } = render(App);

    vaultLocked('idle', 1_000);

    expect(await findByText(/auto-locked due to inactivity/i)).toBeTruthy();
  });
});
