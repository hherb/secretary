// Tests for Toast.svelte — the auto-lock notice surface.
//
// Behaviour contract (spec §12 + the discriminated-union AutoLockNotice
// in lib/stores.ts):
//
//   - Renders an aria-live="polite", role="status" banner so screen
//     readers announce the auto-lock without stealing focus.
//   - Reason-specific copy: `idle` → "Vault auto-locked due to
//     inactivity"; `keep_alive_failing` → "Activity tracking is
//     failing — the vault may lock unexpectedly". The
//     `AutoLockNotice` union has only these two variants — `manual`
//     is filtered at the producer (stores.ts::vaultLocked) so the
//     component never sees it; the switch in messageFor() is
//     exhaustive at compile time.
//   - Auto-dismiss: after TOAST_AUTO_DISMISS_MS the toast clears the
//     `autoLockNotice` store (which unmounts itself via App's `{#if}`).
//   - Manual dismiss: clicking the × button clears the notice
//     immediately.
//   - The dismiss button has type="button" (never a form submit).
//   - If the prop changes mid-lifetime (e.g. a second auto-lock fires
//     while a stale toast is still on screen), the timer resets so the
//     fresh notice gets the full TOAST_AUTO_DISMISS_MS window — never
//     a partial-window dismiss.
//   - On unmount, any pending dismiss timer is cleared (no late
//     `autoLockNotice.set(null)` call after the component is gone).

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import { get } from 'svelte/store';
import Toast from '../src/components/Toast.svelte';
import {
  autoLockNotice,
  type AutoLockNotice,
  _resetSessionStateForTest
} from '../src/lib/stores';

const IDLE_NOTICE: AutoLockNotice = { reason: 'idle', at: 1_000 };
const KEEP_ALIVE_NOTICE: AutoLockNotice = { reason: 'keep_alive_failing', at: 1_000 };

// Local mirror of the auto-dismiss timeout. Must match the constant in
// Toast.svelte — a drift here would silently weaken the timer tests.
const TOAST_AUTO_DISMISS_MS = 5_000;

beforeEach(() => {
  _resetSessionStateForTest();
  // Pre-set the notice so the test can assert clearing behaviour. The
  // actual production wiring is "App sets the notice via vaultLocked, then
  // mounts Toast under an {#if}"; the tests skip that flow and seed
  // directly so each test exercises a single concern.
  autoLockNotice.set(IDLE_NOTICE);
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe('Toast.svelte — rendering', () => {
  it('uses role="status" and aria-live="polite" for non-intrusive announcement', () => {
    const { getByRole } = render(Toast, { props: { notice: IDLE_NOTICE } });
    const banner = getByRole('status');
    expect(banner).toBeTruthy();
    expect(banner.getAttribute('aria-live')).toBe('polite');
  });

  it('renders the auto-lock-due-to-inactivity copy for reason="idle"', () => {
    const { getByText } = render(Toast, { props: { notice: IDLE_NOTICE } });
    expect(getByText(/auto-locked due to inactivity/i)).toBeTruthy();
  });

  it('renders the keep-alive-failing copy for reason="keep_alive_failing"', () => {
    const { getByText } = render(Toast, { props: { notice: KEEP_ALIVE_NOTICE } });
    // Per the AutoLockNotice union's intent (auto_lock.ts threshold),
    // the user needs a heads-up that the vault may lock unexpectedly.
    expect(getByText(/activity tracking is failing/i)).toBeTruthy();
  });

  it('renders a × dismiss button with type="button" and aria-label="Dismiss"', () => {
    const { getByRole } = render(Toast, { props: { notice: IDLE_NOTICE } });
    const dismiss = getByRole('button', { name: /dismiss/i });
    expect(dismiss).toBeTruthy();
    expect(dismiss.getAttribute('type')).toBe('button');
  });
});

describe('Toast.svelte — manual dismiss', () => {
  it('clicking the × button clears the autoLockNotice store', async () => {
    const { getByRole } = render(Toast, { props: { notice: IDLE_NOTICE } });
    expect(get(autoLockNotice)).not.toBeNull();

    await fireEvent.click(getByRole('button', { name: /dismiss/i }));

    expect(get(autoLockNotice)).toBeNull();
  });
});

describe('Toast.svelte — auto-dismiss', () => {
  it('clears the autoLockNotice after TOAST_AUTO_DISMISS_MS', () => {
    render(Toast, { props: { notice: IDLE_NOTICE } });
    expect(get(autoLockNotice)).not.toBeNull();

    // Just-before-the-deadline tick: notice still live.
    vi.advanceTimersByTime(TOAST_AUTO_DISMISS_MS - 1);
    expect(get(autoLockNotice)).not.toBeNull();

    // Crossing the deadline triggers the timeout callback.
    vi.advanceTimersByTime(1);
    expect(get(autoLockNotice)).toBeNull();
  });

  it('a fresh notice (prop change) resets the dismiss timer so the new notice gets the full window', async () => {
    // Render with the initial idle notice + advance halfway through the
    // dismiss window. Then simulate a fresh notice arriving (e.g. user
    // re-unlocked + auto-locked again). The timer must reset, otherwise
    // the fresh notice would dismiss after only the remaining window.
    const { rerender } = render(Toast, { props: { notice: IDLE_NOTICE } });
    vi.advanceTimersByTime(TOAST_AUTO_DISMISS_MS / 2);

    const freshNotice: AutoLockNotice = { reason: 'idle', at: IDLE_NOTICE.at + 10_000 };
    autoLockNotice.set(freshNotice);
    await rerender({ notice: freshNotice });

    // After the old half-window plus another half-window, the OLD timer
    // would have fired — but the reset means the notice is still live.
    vi.advanceTimersByTime(TOAST_AUTO_DISMISS_MS / 2);
    expect(get(autoLockNotice)).not.toBeNull();

    // After the FULL fresh window elapses from the prop change, it clears.
    vi.advanceTimersByTime(TOAST_AUTO_DISMISS_MS / 2);
    expect(get(autoLockNotice)).toBeNull();
  });

  it('on unmount, no late dismiss fires (timer is cleared)', () => {
    const { unmount } = render(Toast, { props: { notice: IDLE_NOTICE } });

    // Pre-populate the store with a *different* notice after unmount so
    // we can detect any late `autoLockNotice.set(null)` call: if the
    // timer leaks across unmount, the post-unmount notice would be
    // wiped. If the unmount-cleanup ran correctly, the post-unmount
    // notice survives the (would-have-been) firing tick.
    unmount();
    const survivor: AutoLockNotice = { reason: 'idle', at: 99_999 };
    autoLockNotice.set(survivor);

    vi.advanceTimersByTime(TOAST_AUTO_DISMISS_MS + 1);
    expect(get(autoLockNotice)).toEqual(survivor);
  });
});

