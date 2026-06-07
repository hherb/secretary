import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import SyncPill from '../src/components/SyncPill.svelte';
import * as ipc from '../src/lib/ipc';
import * as stores from '../src/lib/stores';

vi.mock('../src/lib/ipc', async (orig) => ({
  ...(await orig<typeof ipc>()),
  syncStatus: vi.fn(),
  syncNow: vi.fn()
}));
vi.mock('../src/lib/stores', async (orig) => ({
  ...(await orig<typeof stores>()),
  refreshManifest: vi.fn()
}));
const mockStatus = vi.mocked(ipc.syncStatus);
const mockSyncNow = vi.mocked(ipc.syncNow);
const mockRefresh = vi.mocked(stores.refreshManifest);

describe('SyncPill.svelte', () => {
  beforeEach(() => {
    mockStatus.mockReset();
    mockSyncNow.mockReset();
    mockRefresh.mockReset();
  });

  it('reads status on mount and renders the last-synced label', async () => {
    mockStatus.mockResolvedValue({ hasState: false, lastStateWriteMs: null });
    const { findByRole } = render(SyncPill);
    const btn = await findByRole('button', { name: /sync/i });
    await waitFor(() => expect(btn.textContent).toMatch(/never synced/i));
    expect(mockStatus).toHaveBeenCalledTimes(1);
  });

  it('opens the password dialog on click', async () => {
    mockStatus.mockResolvedValue({ hasState: true, lastStateWriteMs: null });
    const { findByRole, container } = render(SyncPill);
    await fireEvent.click(await findByRole('button', { name: /sync/i }));
    await waitFor(() => expect(container.querySelector('dialog')).not.toBeNull());
  });

  it('after a data-changing sync: toasts success, refreshes status + manifest', async () => {
    mockStatus
      .mockResolvedValueOnce({ hasState: true, lastStateWriteMs: null })   // mount
      .mockResolvedValueOnce({ hasState: true, lastStateWriteMs: Date.now() }); // post-sync
    mockSyncNow.mockResolvedValue({ kind: 'appliedAutomatically' });
    const { findByRole, getByLabelText, findByText } = render(SyncPill);

    await fireEvent.click(await findByRole('button', { name: /sync/i }));
    await fireEvent.input(getByLabelText(/password/i), { target: { value: 'pw' } });
    await fireEvent.click(await findByRole('button', { name: /^sync$/i }));

    expect(await findByText(/your vault is up to date/i)).toBeTruthy();
    await waitFor(() => expect(mockRefresh).toHaveBeenCalledTimes(1));
    expect(mockStatus).toHaveBeenCalledTimes(2);
    expect(mockSyncNow).toHaveBeenCalledTimes(1);
    expect(mockSyncNow).toHaveBeenCalledWith('pw');
  });

  it('does NOT refresh the manifest when the outcome changed nothing', async () => {
    mockStatus.mockResolvedValue({ hasState: true, lastStateWriteMs: null });
    mockSyncNow.mockResolvedValue({ kind: 'nothingToDo' });
    const { findByRole, getByLabelText, findByText } = render(SyncPill);
    await fireEvent.click(await findByRole('button', { name: /sync/i }));
    await fireEvent.input(getByLabelText(/password/i), { target: { value: 'pw' } });
    await fireEvent.click(await findByRole('button', { name: /^sync$/i }));
    expect(await findByText(/already up to date/i)).toBeTruthy();
    expect(mockRefresh).not.toHaveBeenCalled();
    expect(mockSyncNow).toHaveBeenCalledTimes(1);
    expect(mockSyncNow).toHaveBeenCalledWith('pw');
  });

  it('auto-dismisses the notice after SYNC_NOTICE_DISMISS_MS', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: false });
    try {
      mockStatus.mockResolvedValue({ hasState: true, lastStateWriteMs: null });
      mockSyncNow.mockResolvedValue({ kind: 'nothingToDo' });
      const { findByRole, getByLabelText, queryByText } = render(SyncPill);

      // Trigger a sync so a notice appears.
      await fireEvent.click(await findByRole('button', { name: /sync/i }));
      await fireEvent.input(getByLabelText(/password/i), { target: { value: 'pw' } });
      await fireEvent.click(await findByRole('button', { name: /^sync$/i }));

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
