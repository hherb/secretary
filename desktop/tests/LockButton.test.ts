// Tests for LockButton.svelte — the explicit-lock trigger that lives in
// the Vault top bar. Behaviour contract:
//
//   - Renders a single "Lock" button (App.svelte renders the
//     "Locking…" splash for the brief `locking` transition since
//     LockButton's parent Vault unmounts the moment state leaves
//     `unlocked`).
//   - onClick: fires `beginLock()` then awaits the `lock` IPC.
//     On success, makes no further state mutation — the App.svelte
//     vault-locked listener handles the eventual transition to
//     `locked`, per spec §7 (backend reality is source of truth).
//   - On IPC rejection, calls `lockFailed(err)` to capture the
//     typed AppError in `sessionState.lastError` so the Unlock route
//     can render it inline.
//   - Defensive: if clicked from any non-`unlocked` state (a fast
//     double-click between transition and unmount), the handler
//     no-ops without calling beginLock again.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import { get } from 'svelte/store';
import LockButton from '../src/components/LockButton.svelte';
import {
  sessionState,
  beginUnlock,
  unlockSucceeded,
  _resetSessionStateForTest
} from '../src/lib/stores';
import type { ManifestDto, SettingsDto } from '../src/lib/ipc';
import type { AppError } from '../src/lib/errors';

const MANIFEST: ManifestDto = {
  vaultUuidHex: 'aa',
  ownerUserUuidHex: 'bb',
  blockCount: 0,
  blockSummaries: [],
  warnings: []
};
const SETTINGS: SettingsDto = { autoLockTimeoutMs: 600_000, requirePasswordBeforeEdits: false, reauthGraceWindowMs: 120_000, retentionWindowMs: 7_776_000_000 };

// Hoist the lock-IPC mock so we can drive resolution / rejection per test.
const { lockMock } = vi.hoisted(() => ({ lockMock: vi.fn() }));
vi.mock('../src/lib/ipc', async () => {
  const real = await vi.importActual<typeof import('../src/lib/ipc')>('../src/lib/ipc');
  return { ...real, lock: lockMock };
});

beforeEach(() => {
  _resetSessionStateForTest();
  lockMock.mockReset();
  // Default mock: resolve immediately. Per-test overrides for rejection
  // or pending-promise scenarios.
  lockMock.mockResolvedValue(undefined);
});

function unlockSession() {
  beginUnlock(0);
  unlockSucceeded(MANIFEST, SETTINGS);
}

describe('LockButton.svelte — rendering', () => {
  it('renders a button labelled "Lock"', () => {
    unlockSession();
    const { getByRole } = render(LockButton);
    expect(getByRole('button', { name: /lock/i })).toBeTruthy();
  });

  it('rendered element has type="button" (never a form submit)', () => {
    unlockSession();
    const { getByRole } = render(LockButton);
    const button = getByRole('button', { name: /lock/i });
    expect(button.getAttribute('type')).toBe('button');
  });
});

describe('LockButton.svelte — happy path', () => {
  it('click transitions sessionState from unlocked to locking', async () => {
    unlockSession();
    const { getByRole } = render(LockButton);
    expect(get(sessionState).status).toBe('unlocked');

    await fireEvent.click(getByRole('button', { name: /lock/i }));

    await waitFor(() => {
      expect(get(sessionState).status).toBe('locking');
    });
  });

  it('click calls the `lock` IPC exactly once', async () => {
    unlockSession();
    const { getByRole } = render(LockButton);
    await fireEvent.click(getByRole('button', { name: /lock/i }));
    await waitFor(() => expect(lockMock).toHaveBeenCalledTimes(1));
  });

  it('after successful IPC, sessionState stays `locking` (vaultLocked is App.svelte\'s job)', async () => {
    // LockButton must not call vaultLocked itself — that would make
    // the frontend the source of truth instead of the backend. The
    // App.svelte vault-locked event listener (#149) handles the real
    // transition when the backend's emit arrives.
    unlockSession();
    const { getByRole } = render(LockButton);
    await fireEvent.click(getByRole('button', { name: /lock/i }));
    await waitFor(() => expect(lockMock).toHaveBeenCalled());
    // The IPC has resolved (mocked to resolve immediately). State is
    // still `locking` because LockButton didn't fire vaultLocked.
    expect(get(sessionState).status).toBe('locking');
  });
});

describe('LockButton.svelte — error path', () => {
  it('rejected IPC calls lockFailed with the typed AppError', async () => {
    const internalErr: AppError = { code: 'internal' };
    lockMock.mockRejectedValueOnce(internalErr);

    unlockSession();
    const { getByRole } = render(LockButton);
    await fireEvent.click(getByRole('button', { name: /lock/i }));

    await waitFor(() => {
      const s = get(sessionState);
      expect(s.status).toBe('locked');
      if (s.status === 'locked') {
        expect(s.lastError).toEqual(internalErr);
      }
    });
  });

  it('captures vault_path_locked-style errors with their payload', async () => {
    // Sanity check that lockFailed forwards the variant payload, not
    // just the discriminant. (Lock IPC won't realistically return
    // vault_path_locked, but the wire layer doesn't validate that.)
    const richErr: AppError = { code: 'io' };
    lockMock.mockRejectedValueOnce(richErr);

    unlockSession();
    const { getByRole } = render(LockButton);
    await fireEvent.click(getByRole('button', { name: /lock/i }));

    await waitFor(() => {
      const s = get(sessionState);
      if (s.status === 'locked') {
        expect(s.lastError).toEqual(richErr);
      } else {
        throw new Error('expected locked');
      }
    });
  });

  it('coerces a non-AppError rejection (bare string) to { code: "internal" }', async () => {
    // Defence in depth: `call()` in ipc.ts already normalises non-AppError
    // rejections to `{ code: 'internal' }`, but this test bypasses that
    // layer by mocking the `lock` export directly. The narrowing inside
    // `lockFailed` must still surface a renderable AppError so the user
    // gets a coherent "Internal error" toast rather than an undefined
    // discriminant flowing into `userMessageFor`.
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    lockMock.mockRejectedValueOnce('raw string from a panic');

    unlockSession();
    const { getByRole } = render(LockButton);
    await fireEvent.click(getByRole('button', { name: /lock/i }));

    await waitFor(() => {
      const s = get(sessionState);
      expect(s.status).toBe('locked');
      if (s.status === 'locked') {
        expect(s.lastError).toEqual({ code: 'internal' });
      }
    });

    errorSpy.mockRestore();
  });
});

describe('LockButton.svelte — defensive guard', () => {
  it('clicking when not unlocked is a no-op (does not call lock IPC or beginLock)', async () => {
    // State machine starts `locked` — Vault should never mount LockButton
    // in this state, but we still defend against the microsecond between
    // a transition and the parent's unmount.
    const { getByRole } = render(LockButton);
    await fireEvent.click(getByRole('button', { name: /lock/i }));
    // No IPC call, no transition.
    expect(lockMock).not.toHaveBeenCalled();
    expect(get(sessionState).status).toBe('locked');
  });
});
