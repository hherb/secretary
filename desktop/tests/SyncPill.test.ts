import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import SyncPill from '../src/components/SyncPill.svelte';
import * as ipc from '../src/lib/ipc';
import * as stores from '../src/lib/stores';
import {
  __setWriteGuardTestSeam,
  ReauthCancelled,
  resetReauthGuard
} from '../src/lib/writeGuard';

vi.mock('../src/lib/ipc', async (orig) => ({
  ...(await orig<typeof ipc>()),
  syncStatus: vi.fn(),
  syncNow: vi.fn(),
  syncCommitDecisions: vi.fn()
}));
vi.mock('../src/lib/stores', async (orig) => ({
  ...(await orig<typeof stores>()),
  refreshManifest: vi.fn()
}));
const mockStatus = vi.mocked(ipc.syncStatus);
const mockSyncNow = vi.mocked(ipc.syncNow);
const mockCommit = vi.mocked(ipc.syncCommitDecisions);
const mockRefresh = vi.mocked(stores.refreshManifest);

const PASS_THROUGH_SEAM = {
  readSettings: () => ({ enabled: false, windowMs: 0 }),
  now: () => 0,
  biometricPrefEnabled: () => false,
  tryBiometric: () => Promise.resolve('unavailable' as const),
  prompt: () => Promise.resolve()
};
const CANCELLING_SEAM = {
  ...PASS_THROUGH_SEAM,
  readSettings: () => ({ enabled: true, windowMs: 0 }),
  prompt: () => Promise.reject(ReauthCancelled)
};

// Drain the microtask queue plus one macrotask turn, so an async click handler
// that awaited a rejected promise has run to completion.
const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

describe('SyncPill.svelte', () => {
  beforeEach(() => {
    mockStatus.mockReset();
    mockSyncNow.mockReset();
    mockCommit.mockReset();
    mockRefresh.mockReset();
    __setWriteGuardTestSeam(PASS_THROUGH_SEAM);
  });
  afterEach(() => resetReauthGuard());

  it('reads status on mount and renders the last-synced label', async () => {
    mockStatus.mockResolvedValue({ hasState: false, lastStateWriteMs: null });
    const { findByRole } = render(SyncPill);
    const btn = await findByRole('button', { name: /sync/i });
    await waitFor(() => expect(btn.textContent).toMatch(/never synced/i));
    expect(mockStatus).toHaveBeenCalledTimes(1);
  });

  it('syncs nothing when the re-auth prompt is cancelled', async () => {
    const prompt = vi.fn(() => Promise.reject(ReauthCancelled));
    __setWriteGuardTestSeam({ ...CANCELLING_SEAM, prompt });
    mockStatus.mockResolvedValue({ hasState: true, lastStateWriteMs: null });
    const { findByRole, queryByRole } = render(SyncPill);
    await fireEvent.click(await findByRole('button', { name: /sync/i }));
    await waitFor(() => expect(prompt).toHaveBeenCalledTimes(1));
    await settle(); // let the rejected prompt run through syncClicked to its end
    expect(mockSyncNow).not.toHaveBeenCalled();
    expect(queryByRole('alert')).toBeNull();
  });

  it('shows a failed re-auth (not a cancel) as an error and syncs nothing', async () => {
    __setWriteGuardTestSeam({ ...CANCELLING_SEAM, prompt: () => Promise.reject({ code: 'internal' }) });
    mockStatus.mockResolvedValue({ hasState: true, lastStateWriteMs: null });
    const { findByRole } = render(SyncPill);
    await fireEvent.click(await findByRole('button', { name: /sync/i }));
    expect((await findByRole('alert')).textContent).not.toBe('');
    expect(mockSyncNow).not.toHaveBeenCalled();
  });

  it('syncs after the re-auth prompt is accepted', async () => {
    const prompt = vi.fn(() => Promise.resolve());
    __setWriteGuardTestSeam({ ...CANCELLING_SEAM, prompt });
    mockStatus.mockResolvedValue({ hasState: true, lastStateWriteMs: null });
    mockSyncNow.mockResolvedValue({ kind: 'nothingToDo' });
    const { findByRole } = render(SyncPill);
    await fireEvent.click(await findByRole('button', { name: /sync/i }));
    await waitFor(() => expect(mockSyncNow).toHaveBeenCalledTimes(1));
    expect(prompt).toHaveBeenCalledTimes(1);
    expect(prompt.mock.invocationCallOrder[0]).toBeLessThan(mockSyncNow.mock.invocationCallOrder[0]);
  });

  it('keeps an error notice up past the success dismiss delay', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: false });
    try {
      mockStatus.mockResolvedValue({ hasState: true, lastStateWriteMs: null });
      mockSyncNow.mockRejectedValueOnce({ code: 'vault_changed_on_disk' });
      const { findByRole, queryByRole } = render(SyncPill);
      await fireEvent.click(await findByRole('button', { name: /sync/i }));
      await vi.advanceTimersByTimeAsync(0);
      expect(queryByRole('alert')).not.toBeNull();
      await vi.advanceTimersByTimeAsync(60_000);
      expect(queryByRole('alert')).not.toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });

  it('reports a failed records reload after a committed sync as that, not as a failed sync', async () => {
    mockStatus.mockResolvedValue({ hasState: true, lastStateWriteMs: null });
    mockSyncNow.mockResolvedValue({ kind: 'silentMerge' });
    mockRefresh.mockRejectedValueOnce({ code: 'internal' });
    const { findByRole } = render(SyncPill);
    await fireEvent.click(await findByRole('button', { name: /sync/i }));
    expect((await findByRole('alert')).textContent).toMatch(/^Synced, but the records could not reload/);
  });

  it('shows a sync failure as an error notice', async () => {
    mockStatus.mockResolvedValue({ hasState: true, lastStateWriteMs: null });
    mockSyncNow.mockRejectedValueOnce({ code: 'vault_changed_on_disk' });
    const { findByRole } = render(SyncPill);
    await fireEvent.click(await findByRole('button', { name: /sync/i }));
    expect((await findByRole('alert')).textContent).not.toBe('');
  });

  it('after a data-changing sync: toasts success, refreshes status + manifest', async () => {
    mockStatus
      .mockResolvedValueOnce({ hasState: true, lastStateWriteMs: null })   // mount
      .mockResolvedValueOnce({ hasState: true, lastStateWriteMs: Date.now() }); // post-sync
    mockSyncNow.mockResolvedValue({ kind: 'appliedAutomatically' });
    const { findByRole, findByText } = render(SyncPill);

    await fireEvent.click(await findByRole('button', { name: /sync/i }));

    expect(await findByText(/your vault is up to date/i)).toBeTruthy();
    await waitFor(() => expect(mockRefresh).toHaveBeenCalledTimes(1));
    expect(mockStatus).toHaveBeenCalledTimes(2);
    expect(mockSyncNow).toHaveBeenCalledTimes(1);
    expect(mockSyncNow).toHaveBeenCalledWith();
  });

  it('does NOT refresh the manifest when the outcome changed nothing', async () => {
    mockStatus.mockResolvedValue({ hasState: true, lastStateWriteMs: null });
    mockSyncNow.mockResolvedValue({ kind: 'nothingToDo' });
    const { findByRole, findByText } = render(SyncPill);
    await fireEvent.click(await findByRole('button', { name: /sync/i }));
    expect(await findByText(/already up to date/i)).toBeTruthy();
    expect(mockRefresh).not.toHaveBeenCalled();
    expect(mockSyncNow).toHaveBeenCalledTimes(1);
    expect(mockSyncNow).toHaveBeenCalledWith();
  });

  it('on conflictsPending: opens the resolution dialog; onResolved toasts + reloads', async () => {
    mockStatus
      .mockResolvedValueOnce({ hasState: true, lastStateWriteMs: null })          // mount
      .mockResolvedValueOnce({ hasState: true, lastStateWriteMs: Date.now() });    // post-resolve
    mockSyncNow.mockResolvedValue({
      kind: 'conflictsPending',
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
    });
    mockCommit.mockResolvedValue({ kind: 'mergedClean' });
    const { findByRole, findByText } = render(SyncPill);

    // Sync → conflictsPending.
    await fireEvent.click(await findByRole('button', { name: /sync/i }));

    // The resolution dialog renders.
    expect(await findByText(/resolve sync conflicts/i)).toBeTruthy();

    // Apply the (default Keep-mine) decisions → mergedClean.
    await fireEvent.click(await findByRole('button', { name: /apply & finish sync/i }));

    // Synced notice + status reload + manifest refresh (mergedClean changes data).
    expect(await findByText(/your vault is up to date/i)).toBeTruthy();
    await waitFor(() => expect(mockRefresh).toHaveBeenCalledTimes(1));
    expect(mockStatus).toHaveBeenCalledTimes(2);
    expect(mockCommit).toHaveBeenCalledTimes(1);
    expect(mockCommit).toHaveBeenCalledWith([{ recordUuidHex: 'aa', keepLocal: true }], [1]);
  });

  it('auto-dismisses the notice after SYNC_NOTICE_DISMISS_MS', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: false });
    try {
      mockStatus.mockResolvedValue({ hasState: true, lastStateWriteMs: null });
      mockSyncNow.mockResolvedValue({ kind: 'nothingToDo' });
      const { findByRole, queryByText } = render(SyncPill);

      // Trigger a sync so a notice appears.
      await fireEvent.click(await findByRole('button', { name: /sync/i }));

      // Drain only microtasks (Promise resolutions) without advancing timers,
      // so the notice lands in the DOM but the dismiss timer has not fired yet.
      await vi.advanceTimersByTimeAsync(0);

      expect(queryByText(/already up to date/i)).not.toBeNull();

      // Advance past the dismiss delay (5 000 ms) — the $effect timer fires.
      await vi.advanceTimersByTimeAsync(5_000);

      expect(queryByText(/already up to date/i)).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });
});
