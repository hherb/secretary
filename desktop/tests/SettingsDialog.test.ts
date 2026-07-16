// Tests for SettingsDialog.svelte — the native <dialog> overlay that
// edits app settings (currently just auto_lock_timeout_ms, but the
// component is structured for future fields). Behaviour contract:
//
//   - Renders a <dialog> with an integer-minutes input (user-visible
//     unit) plus Save / Cancel buttons.
//   - Initial value derived from `sessionState.settings.autoLockTimeoutMs`
//     converted to minutes (rounded). Falls back to AUTO_LOCK_DEFAULT_MS
//     when the store is not in `unlocked` (defensive — dialog should
//     only be opened from Vault, which only mounts when unlocked).
//   - Client-side validation: integer, [AUTO_LOCK_MIN_MS / 60000,
//     AUTO_LOCK_MAX_MS / 60000] minutes. Out-of-range surfaces the
//     SAME typed `settings_out_of_range` AppError the backend would
//     return — consistent UX whether the gate fires client-side or
//     server-side.
//   - Save flow: validate → setSettings IPC (ms) → settingsUpdated
//     store helper → onClose. IPC rejection narrows non-AppError
//     shapes to `{ code: 'internal' }` (defence in depth — `call()`
//     in ipc.ts already coerces, but local narrowing means the
//     component contract holds independently).
//   - Cancel flow: revert input to current store value, then onClose.
//
// JSDOM 25 supports <dialog>.showModal() / .close() / the `open`
// attribute, so the `open` bindable prop drives real native dialog
// state — no polyfill needed.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import { get } from 'svelte/store';
import SettingsDialog from '../src/components/SettingsDialog.svelte';
import {
  sessionState,
  beginUnlock,
  unlockSucceeded,
  _resetSessionStateForTest,
  presencePref,
  setPresencePref,
  resetPresencePref
} from '../src/lib/stores';
import {
  MS_PER_MINUTE,
  MS_PER_DAY,
  AUTO_LOCK_MIN_MS,
  AUTO_LOCK_MAX_MS,
  AUTO_LOCK_DEFAULT_MS,
  REAUTH_WINDOW_MIN_MS,
  REAUTH_WINDOW_MAX_MS,
  REAUTH_WINDOW_DEFAULT_MS,
  REQUIRE_PASSWORD_DEFAULT,
  RETENTION_WINDOW_MIN_MS,
  RETENTION_WINDOW_MAX_MS,
  RETENTION_WINDOW_DEFAULT_MS
} from '../src/lib/constants';
import {
  __setWriteGuardTestSeam,
  ReauthCancelled,
  resetReauthGuard
} from '../src/lib/writeGuard';
import type { ManifestDto, SettingsDto } from '../src/lib/ipc';
import type { AppError } from '../src/lib/errors';

// Default: a pass-through guard so the bulk of the suite (which doesn't seed
// the reauth clock) never opens the real prompt. The gate-specific tests below
// install their own seam.
const PASS_THROUGH_SEAM = {
  readSettings: () => ({ enabled: false, windowMs: 0 }),
  now: () => 0,
  biometricPrefEnabled: () => false,
  tryBiometric: () => Promise.resolve('unavailable' as const),
  prompt: () => Promise.resolve()
};

const MANIFEST: ManifestDto = {
  vaultUuidHex: 'aa',
  ownerUserUuidHex: 'bb',
  blockCount: 0,
  blockSummaries: [],
  warnings: []
};
const INITIAL_SETTINGS: SettingsDto = { autoLockTimeoutMs: 900_000, requirePasswordBeforeEdits: false, reauthGraceWindowMs: 120_000, retentionWindowMs: RETENTION_WINDOW_DEFAULT_MS }; // 15 minutes

// Hoist the setSettings / writePresencePref IPC mocks so individual tests can
// drive resolve / reject as needed.
const { setSettingsMock, lockMock, writePresencePrefMock } = vi.hoisted(() => ({
  setSettingsMock: vi.fn(),
  lockMock: vi.fn(),
  writePresencePrefMock: vi.fn()
}));
vi.mock('../src/lib/ipc', async () => {
  const real = await vi.importActual<typeof import('../src/lib/ipc')>('../src/lib/ipc');
  return {
    ...real,
    setSettings: setSettingsMock,
    lock: lockMock,
    writePresencePref: writePresencePrefMock
  };
});

beforeEach(() => {
  _resetSessionStateForTest();
  resetPresencePref();
  setSettingsMock.mockReset();
  setSettingsMock.mockResolvedValue(undefined);
  lockMock.mockReset();
  lockMock.mockResolvedValue(undefined);
  writePresencePrefMock.mockReset();
  writePresencePrefMock.mockResolvedValue(undefined);
  __setWriteGuardTestSeam(PASS_THROUGH_SEAM);
});

afterEach(() => resetReauthGuard());

function unlockWith(settings: SettingsDto = INITIAL_SETTINGS) {
  beginUnlock(0);
  unlockSucceeded(MANIFEST, settings);
}

function renderClosed() {
  return render(SettingsDialog, { props: { open: false, onClose: vi.fn() } });
}

function renderOpen(onClose: () => void = vi.fn()) {
  return render(SettingsDialog, { props: { open: true, onClose } });
}

describe('SettingsDialog.svelte — open / closed state', () => {
  it('renders a <dialog> element', () => {
    unlockWith();
    const { container } = renderClosed();
    expect(container.querySelector('dialog')).not.toBeNull();
  });

  it('when open=false the dialog is not in the open state', () => {
    unlockWith();
    const { container } = renderClosed();
    const dialog = container.querySelector('dialog') as HTMLDialogElement;
    // showModal() sets the `open` attribute; we never called it so the
    // dialog is closed.
    expect(dialog.hasAttribute('open')).toBe(false);
  });

  it('when open=true the dialog enters the open state (showModal)', async () => {
    unlockWith();
    const { container } = renderOpen();
    await waitFor(() => {
      const dialog = container.querySelector('dialog') as HTMLDialogElement;
      expect(dialog.hasAttribute('open')).toBe(true);
    });
  });
});

describe('SettingsDialog.svelte — initial value', () => {
  it('pre-populates the input from sessionState.settings (rounded to minutes)', async () => {
    unlockWith({ autoLockTimeoutMs: 900_000, requirePasswordBeforeEdits: false, reauthGraceWindowMs: 120_000, retentionWindowMs: RETENTION_WINDOW_DEFAULT_MS }); // 15 min
    const { container } = renderOpen();
    await waitFor(() => {
      const input = container.querySelector('input[type="number"]') as HTMLInputElement;
      expect(input.value).toBe('15');
    });
  });

  it('falls back to AUTO_LOCK_DEFAULT_MS in minutes when sessionState is not unlocked', async () => {
    // Defensive: SettingsDialog should never be opened from a non-
    // unlocked state (Vault only mounts when unlocked), but if it is,
    // the input still has a usable initial value rather than NaN.
    const { container } = renderOpen();
    await waitFor(() => {
      const input = container.querySelector('input[type="number"]') as HTMLInputElement;
      expect(input.value).toBe(String(AUTO_LOCK_DEFAULT_MS / MS_PER_MINUTE));
    });
  });

  it('renders the input with min / max attributes matching the bounds (in minutes)', () => {
    unlockWith();
    const { container } = renderOpen();
    const input = container.querySelector('input[type="number"]') as HTMLInputElement;
    expect(input.getAttribute('min')).toBe(String(AUTO_LOCK_MIN_MS / MS_PER_MINUTE));
    expect(input.getAttribute('max')).toBe(String(AUTO_LOCK_MAX_MS / MS_PER_MINUTE));
    expect(input.getAttribute('step')).toBe('1');
  });
});

describe('SettingsDialog.svelte — Save happy path', () => {
  it('Save with a valid value calls setSettings IPC with the value in milliseconds', async () => {
    unlockWith();
    const { container, getByRole } = renderOpen();
    const input = container.querySelector('input[type="number"]') as HTMLInputElement;
    await fireEvent.input(input, { target: { value: '5' } });
    await fireEvent.click(getByRole('button', { name: /save/i }));

    await waitFor(() => {
      expect(setSettingsMock).toHaveBeenCalledTimes(1);
      expect(setSettingsMock).toHaveBeenCalledWith(expect.objectContaining({ autoLockTimeoutMs: 5 * MS_PER_MINUTE }));
    });
  });

  it('Save updates sessionState.settings via settingsUpdated after IPC resolves', async () => {
    unlockWith();
    const { container, getByRole } = renderOpen();
    const input = container.querySelector('input[type="number"]') as HTMLInputElement;
    await fireEvent.input(input, { target: { value: '5' } });
    await fireEvent.click(getByRole('button', { name: /save/i }));

    await waitFor(() => {
      const s = get(sessionState);
      if (s.status === 'unlocked') {
        expect(s.settings.autoLockTimeoutMs).toBe(5 * MS_PER_MINUTE);
      } else {
        throw new Error('expected unlocked');
      }
    });
  });

  it('Save calls onClose after a successful IPC', async () => {
    unlockWith();
    const onClose = vi.fn();
    const { container, getByRole } = renderOpen(onClose);
    const input = container.querySelector('input[type="number"]') as HTMLInputElement;
    await fireEvent.input(input, { target: { value: '5' } });
    await fireEvent.click(getByRole('button', { name: /save/i }));

    await waitFor(() => expect(onClose).toHaveBeenCalledTimes(1));
  });

  it('parent-driven close after Save does not re-trigger cancel via the native close event', async () => {
    // In production Vault.svelte binds `open` and sets it false from its
    // own onClose handler. That flip propagates back to the dialog,
    // making the $effect call dialogEl.close(), which fires the native
    // `close` event. The onclose handler must NOT re-run cancel — cancel
    // calls onClose, so without the `if (open) cancel()` guard the
    // parent would be notified twice per save. Simulate the parent's
    // flip with rerender({ open: false }) and assert onClose stays at 1.
    unlockWith();
    const onClose = vi.fn();
    const { container, getByRole, rerender } = render(SettingsDialog, {
      props: { open: true, onClose }
    });
    const input = container.querySelector('input[type="number"]') as HTMLInputElement;
    await fireEvent.input(input, { target: { value: '5' } });
    await fireEvent.click(getByRole('button', { name: /save/i }));
    await waitFor(() => expect(onClose).toHaveBeenCalledTimes(1));

    await rerender({ open: false, onClose });
    await waitFor(() => {
      const dialog = container.querySelector('dialog') as HTMLDialogElement;
      expect(dialog.hasAttribute('open')).toBe(false);
    });
    // The native close event fired (polyfill dispatches it when the
    // dialog was open at the time of close()), but onNativeClose saw
    // open=false and skipped cancel — onClose stays at 1, not 2.
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('Save when the session has raced to locked mid-IPC skips settingsUpdated and still closes', async () => {
    // Race-guard test: a vault-locked event lands between the IPC firing
    // and resolving (e.g. auto-lock at the boundary). The backend has
    // already accepted the new settings; the in-memory `settingsUpdated`
    // call would throw via the illegal-transition guard from a non-
    // unlocked state. Save() peeks the status and skips the store update
    // — backend is the source of truth, the next unlock observes the
    // persisted value. The dialog still calls onClose; no error toast.
    unlockWith();
    const onClose = vi.fn();
    // Resolve the IPC after we've moved the store to `locking`, mimicking
    // an auto-lock firing while the save IPC is in flight.
    setSettingsMock.mockImplementationOnce(async () => {
      _resetSessionStateForTest(); // back to `locked` synchronously
    });

    const { container, getByRole } = renderOpen(onClose);
    const input = container.querySelector('input[type="number"]') as HTMLInputElement;
    await fireEvent.input(input, { target: { value: '5' } });
    await fireEvent.click(getByRole('button', { name: /save/i }));

    await waitFor(() => expect(setSettingsMock).toHaveBeenCalledTimes(1));
    // onClose still fires — the dialog is about to unmount anyway in
    // production (Vault unmounts on leaving `unlocked`), so the parent
    // ack is idempotent / harmless.
    await waitFor(() => expect(onClose).toHaveBeenCalledTimes(1));
    // sessionState was reset by the racing event; settingsUpdated was
    // skipped, so the store stays in its post-race state (locked).
    expect(get(sessionState).status).toBe('locked');
  });
});

describe('SettingsDialog.svelte — Cancel flow', () => {
  it('Cancel calls onClose without calling setSettings', async () => {
    unlockWith();
    const onClose = vi.fn();
    const { container, getByRole } = renderOpen(onClose);
    const input = container.querySelector('input[type="number"]') as HTMLInputElement;
    await fireEvent.input(input, { target: { value: '7' } });
    await fireEvent.click(getByRole('button', { name: /cancel/i }));

    expect(setSettingsMock).not.toHaveBeenCalled();
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});

describe('SettingsDialog.svelte — client-side validation', () => {
  it('Save with a value below AUTO_LOCK_MIN_MS surfaces settings_out_of_range, no IPC call', async () => {
    // Mirror of backend bounds — the inline error uses the same typed
    // AppError code so userMessageFor renders identical copy for both
    // client-side and server-side rejection.
    unlockWith();
    const onClose = vi.fn();
    const { container, getByRole, findByText } = renderOpen(onClose);
    const input = container.querySelector('input[type="number"]') as HTMLInputElement;
    await fireEvent.input(input, { target: { value: '0' } });
    await fireEvent.click(getByRole('button', { name: /save/i }));

    // userMessageFor(settings_out_of_range) → title "Value out of range"
    expect(await findByText(/value out of range/i)).toBeTruthy();
    expect(setSettingsMock).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
  });

  it('Save with a value above AUTO_LOCK_MAX_MS surfaces settings_out_of_range, no IPC call', async () => {
    unlockWith();
    const onClose = vi.fn();
    const { container, getByRole, findByText } = renderOpen(onClose);
    const input = container.querySelector('input[type="number"]') as HTMLInputElement;
    // Max bound is 24 hours = 1440 minutes; 9999 is comfortably above.
    await fireEvent.input(input, { target: { value: '9999' } });
    await fireEvent.click(getByRole('button', { name: /save/i }));

    expect(await findByText(/value out of range/i)).toBeTruthy();
    expect(setSettingsMock).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
  });

  it('Save with a non-integer value rejects without calling IPC', async () => {
    // The input is type="number" with step="1" so the browser would
    // normally coerce to an integer, but we still defend against
    // fractional inputs reaching the save flow (the spinner can be
    // bypassed via paste or programmatic value setting).
    unlockWith();
    const { container, getByRole, findByText } = renderOpen();
    const input = container.querySelector('input[type="number"]') as HTMLInputElement;
    await fireEvent.input(input, { target: { value: '5.5' } });
    await fireEvent.click(getByRole('button', { name: /save/i }));

    expect(await findByText(/value out of range/i)).toBeTruthy();
    expect(setSettingsMock).not.toHaveBeenCalled();
  });
});

describe('SettingsDialog.svelte — IPC error path', () => {
  it('rejected IPC renders the typed error via userMessageFor', async () => {
    const oorErr: AppError = {
      code: 'settings_out_of_range',
      min: AUTO_LOCK_MIN_MS,
      max: AUTO_LOCK_MAX_MS
    };
    setSettingsMock.mockRejectedValueOnce(oorErr);

    unlockWith();
    const onClose = vi.fn();
    const { container, getByRole, findByText } = renderOpen(onClose);
    const input = container.querySelector('input[type="number"]') as HTMLInputElement;
    await fireEvent.input(input, { target: { value: '5' } });
    await fireEvent.click(getByRole('button', { name: /save/i }));

    expect(await findByText(/value out of range/i)).toBeTruthy();
    expect(onClose).not.toHaveBeenCalled();
  });

  it('rejected IPC with a non-AppError shape coerces to internal error', async () => {
    // Defence in depth: `call()` in ipc.ts already normalises non-AppError
    // rejections, but if a future refactor moves error mapping or a Tauri
    // upgrade changes rejection semantics, the dialog should still render
    // a coherent error rather than a blank or undefined-titled toast.
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    setSettingsMock.mockRejectedValueOnce('panic from runtime');

    unlockWith();
    const { container, getByRole, findByText } = renderOpen();
    const input = container.querySelector('input[type="number"]') as HTMLInputElement;
    await fireEvent.input(input, { target: { value: '5' } });
    await fireEvent.click(getByRole('button', { name: /save/i }));

    // userMessageFor(internal) → title "Internal error"
    expect(await findByText(/internal error/i)).toBeTruthy();
    errorSpy.mockRestore();
  });
});

describe('SettingsDialog.svelte — reauth controls', () => {
  it('saves the reauth toggle and window', async () => {
    unlockWith({ autoLockTimeoutMs: 600_000, requirePasswordBeforeEdits: true, reauthGraceWindowMs: 120_000, retentionWindowMs: RETENTION_WINDOW_DEFAULT_MS });
    setSettingsMock.mockResolvedValueOnce(undefined);
    const { getByLabelText, getByText } = renderOpen();

    // Toggle the checkbox off (currently true → false).
    await fireEvent.click(getByLabelText(/require password before edits/i));
    // Set the window to 1 minute.
    await fireEvent.input(getByLabelText(/re-?auth.*grace|grace.*window|grace.*minutes/i), {
      target: { value: '1' }
    });
    await fireEvent.click(getByText('Save'));

    await waitFor(() => {
      expect(setSettingsMock).toHaveBeenCalledWith(
        expect.objectContaining({ requirePasswordBeforeEdits: false, reauthGraceWindowMs: 60_000 })
      );
    });
  });

  it('Save with a window minutes value above REAUTH_WINDOW_MAX_MS surfaces settings_out_of_range', async () => {
    // REAUTH_WINDOW_MIN_MS is 0 (0 min is valid); there is no sub-zero
    // integer we can enter in a min=0 number field — the browser/JSDOM
    // clamps. Test a value above MAX instead.
    unlockWith({ autoLockTimeoutMs: 600_000, requirePasswordBeforeEdits: true, reauthGraceWindowMs: 120_000, retentionWindowMs: RETENTION_WINDOW_DEFAULT_MS });
    const { container, getByLabelText, getByRole, findByText } = renderOpen();
    // Sanity: the auto-lock input must not be affected by an out-of-range
    // window value — only the window field triggers the error.
    const autoLockInput = container.querySelector('input[type="number"]') as HTMLInputElement;
    await fireEvent.input(autoLockInput, { target: { value: '10' } }); // valid
    const windowInput = getByLabelText(/re-?auth.*grace|grace.*window|grace.*minutes/i);
    // REAUTH_WINDOW_MAX_MS = 3_600_000 ms = 60 minutes; 999 > 60.
    await fireEvent.input(windowInput, { target: { value: '999' } });
    await fireEvent.click(getByRole('button', { name: /save/i }));

    expect(await findByText(/value out of range/i)).toBeTruthy();
    expect(setSettingsMock).not.toHaveBeenCalled();
  });

  it('window input has min=0 and max=REAUTH_WINDOW_MAX_MS/60000 attributes', () => {
    unlockWith();
    const { getByLabelText } = renderOpen();
    const windowInput = getByLabelText(/re-?auth.*grace|grace.*window|grace.*minutes/i) as HTMLInputElement;
    expect(windowInput.getAttribute('min')).toBe(String(REAUTH_WINDOW_MIN_MS / MS_PER_MINUTE));
    expect(windowInput.getAttribute('max')).toBe(String(REAUTH_WINDOW_MAX_MS / MS_PER_MINUTE));
  });

  it('pre-populates the window input from sessionState.settings.reauthGraceWindowMs', async () => {
    unlockWith({ autoLockTimeoutMs: 600_000, requirePasswordBeforeEdits: true, reauthGraceWindowMs: 180_000, retentionWindowMs: RETENTION_WINDOW_DEFAULT_MS }); // 3 min
    const { getByLabelText } = renderOpen();
    await waitFor(() => {
      const windowInput = getByLabelText(/re-?auth.*grace|grace.*window|grace.*minutes/i) as HTMLInputElement;
      expect(windowInput.value).toBe('3');
    });
  });

  it('fallback requirePasswordBeforeEdits uses REQUIRE_PASSWORD_DEFAULT (true) when not unlocked', async () => {
    // Dialog opened without unlocking first — defensive. The checkbox
    // should reflect the secure-by-default value (true), not hardcoded false.
    const { getByLabelText } = renderOpen();
    await waitFor(() => {
      const checkbox = getByLabelText(/require password before edits/i) as HTMLInputElement;
      expect(checkbox.checked).toBe(REQUIRE_PASSWORD_DEFAULT);
    });
  });

  it('fallback reauthGraceWindowMs uses REAUTH_WINDOW_DEFAULT_MS when not unlocked', async () => {
    const { getByLabelText } = renderOpen();
    await waitFor(() => {
      const windowInput = getByLabelText(/re-?auth.*grace|grace.*window|grace.*minutes/i) as HTMLInputElement;
      expect(windowInput.value).toBe(String(REAUTH_WINDOW_DEFAULT_MS / MS_PER_MINUTE));
    });
  });
});

describe('SettingsDialog.svelte — retention window', () => {
  it('pre-populates the retention input from sessionState.settings.retentionWindowMs (in days)', async () => {
    unlockWith({
      autoLockTimeoutMs: 600_000,
      requirePasswordBeforeEdits: true,
      reauthGraceWindowMs: 120_000,
      retentionWindowMs: 30 * MS_PER_DAY
    });
    const { getByLabelText } = renderOpen();
    await waitFor(() => {
      const input = getByLabelText(/retention window/i) as HTMLInputElement;
      expect(input.value).toBe('30');
    });
  });

  it('Save includes retentionWindowMs (input days × MS_PER_DAY) in the setSettings payload', async () => {
    unlockWith();
    const { getByLabelText, getByRole } = renderOpen();
    const input = getByLabelText(/retention window/i);
    await fireEvent.input(input, { target: { value: '45' } });
    await fireEvent.click(getByRole('button', { name: /save/i }));

    await waitFor(() => {
      expect(setSettingsMock).toHaveBeenCalledWith(
        expect.objectContaining({ retentionWindowMs: 45 * MS_PER_DAY })
      );
    });
  });

  it('Save with a retention value of 0 days surfaces settings_out_of_range, no IPC call', async () => {
    unlockWith();
    const onClose = vi.fn();
    const { getByLabelText, getByRole, findByText } = renderOpen(onClose);
    const input = getByLabelText(/retention window/i);
    await fireEvent.input(input, { target: { value: '0' } });
    await fireEvent.click(getByRole('button', { name: /save/i }));

    expect(await findByText(/value out of range/i)).toBeTruthy();
    expect(setSettingsMock).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
  });

  it('retention input has min/max attributes matching the bounds (in days)', () => {
    unlockWith();
    const { getByLabelText } = renderOpen();
    const input = getByLabelText(/retention window/i) as HTMLInputElement;
    expect(input.getAttribute('min')).toBe(String(RETENTION_WINDOW_MIN_MS / MS_PER_DAY));
    expect(input.getAttribute('max')).toBe(String(RETENTION_WINDOW_MAX_MS / MS_PER_DAY));
    expect(input.getAttribute('step')).toBe('1');
  });

  it('fallback retentionWindowMs uses RETENTION_WINDOW_DEFAULT_MS when not unlocked', async () => {
    const { getByLabelText } = renderOpen();
    await waitFor(() => {
      const input = getByLabelText(/retention window/i) as HTMLInputElement;
      expect(input.value).toBe(String(RETENTION_WINDOW_DEFAULT_MS / MS_PER_DAY));
    });
  });

  it('does not gate retention widening behind write re-auth', async () => {
    // Retention widening only delays discarding ciphertext — it is not a
    // security REDUCTION, unlike widening auto-lock or the reauth window.
    const prompt = vi.fn(() => Promise.resolve());
    __setWriteGuardTestSeam({
      readSettings: () => ({ enabled: true, windowMs: 0 }),
      now: () => 0,
      biometricPrefEnabled: () => false,
      tryBiometric: () => Promise.resolve('unavailable' as const),
      prompt
    });
    unlockWith({
      autoLockTimeoutMs: 600_000,
      requirePasswordBeforeEdits: true,
      reauthGraceWindowMs: 120_000,
      retentionWindowMs: 30 * MS_PER_DAY
    });
    const { getByLabelText, getByRole } = renderOpen();

    await fireEvent.input(getByLabelText(/retention window/i), {
      target: { value: '365' } // widen 30 -> 365 days
    });
    await fireEvent.click(getByRole('button', { name: /save/i }));

    await waitFor(() => expect(setSettingsMock).toHaveBeenCalledTimes(1));
    expect(prompt).not.toHaveBeenCalled();
  });
});

describe('SettingsDialog.svelte — security-reducing changes are gated', () => {
  // The whole point of write re-auth is to defend an unlocked-but-unattended
  // session. Disabling the gate (or widening its window) from Settings without
  // re-auth would be a trivial bypass, so those saves route through the same
  // authorizeWrite chokepoint as any other write.

  it('disabling the toggle prompts re-auth; cancel aborts the save', async () => {
    __setWriteGuardTestSeam({
      readSettings: () => ({ enabled: true, windowMs: 0 }),
      now: () => 0,
      biometricPrefEnabled: () => false,
      tryBiometric: () => Promise.resolve('unavailable' as const),
      prompt: () => Promise.reject(ReauthCancelled)
    });
    unlockWith({ autoLockTimeoutMs: 600_000, requirePasswordBeforeEdits: true, reauthGraceWindowMs: 120_000, retentionWindowMs: RETENTION_WINDOW_DEFAULT_MS });
    const onClose = vi.fn();
    const { getByLabelText, getByRole } = renderOpen(onClose);

    await fireEvent.click(getByLabelText(/require password before edits/i)); // true → false
    await fireEvent.click(getByRole('button', { name: /save/i }));

    await new Promise((r) => setTimeout(r, 50));
    expect(setSettingsMock).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
  });

  it('widening the grace window prompts re-auth; resolve lets the save proceed', async () => {
    const prompt = vi.fn(() => Promise.resolve());
    __setWriteGuardTestSeam({
      readSettings: () => ({ enabled: true, windowMs: 0 }),
      now: () => 0,
      biometricPrefEnabled: () => false,
      tryBiometric: () => Promise.resolve('unavailable' as const),
      prompt
    });
    unlockWith({ autoLockTimeoutMs: 600_000, requirePasswordBeforeEdits: true, reauthGraceWindowMs: 120_000, retentionWindowMs: RETENTION_WINDOW_DEFAULT_MS }); // 2 min
    const { getByLabelText, getByRole } = renderOpen();

    await fireEvent.input(getByLabelText(/re-?auth.*grace|grace.*window|grace.*minutes/i), {
      target: { value: '5' } // 2 min → 5 min: wider = weaker
    });
    await fireEvent.click(getByRole('button', { name: /save/i }));

    await waitFor(() => expect(prompt).toHaveBeenCalledTimes(1));
    await waitFor(() =>
      expect(setSettingsMock).toHaveBeenCalledWith(
        expect.objectContaining({ reauthGraceWindowMs: 5 * MS_PER_MINUTE })
      )
    );
  });

  it('security-NEUTRAL/strengthening changes do not prompt (tighten window, auto-lock only)', async () => {
    const prompt = vi.fn(() => Promise.resolve());
    __setWriteGuardTestSeam({
      readSettings: () => ({ enabled: true, windowMs: 0 }),
      now: () => 0,
      biometricPrefEnabled: () => false,
      tryBiometric: () => Promise.resolve('unavailable' as const),
      prompt
    });
    unlockWith({ autoLockTimeoutMs: 600_000, requirePasswordBeforeEdits: true, reauthGraceWindowMs: 300_000, retentionWindowMs: RETENTION_WINDOW_DEFAULT_MS }); // 5 min
    const { getByLabelText, getByRole } = renderOpen();

    // Tighten the window (5 → 1 min) — strengthens protection, must not prompt.
    await fireEvent.input(getByLabelText(/re-?auth.*grace|grace.*window|grace.*minutes/i), {
      target: { value: '1' }
    });
    await fireEvent.click(getByRole('button', { name: /save/i }));

    await waitFor(() => expect(setSettingsMock).toHaveBeenCalledTimes(1));
    expect(prompt).not.toHaveBeenCalled();
  });

  it('does not prompt when the gate is currently off (nothing to bypass)', async () => {
    const prompt = vi.fn(() => Promise.resolve());
    __setWriteGuardTestSeam({
      readSettings: () => ({ enabled: false, windowMs: 0 }),
      now: () => 0,
      biometricPrefEnabled: () => false,
      tryBiometric: () => Promise.resolve('unavailable' as const),
      prompt
    });
    unlockWith({ autoLockTimeoutMs: 600_000, requirePasswordBeforeEdits: false, reauthGraceWindowMs: 120_000, retentionWindowMs: RETENTION_WINDOW_DEFAULT_MS });
    const { getByLabelText, getByRole } = renderOpen();

    // Widen the window while the gate is off — no live protection to reduce.
    await fireEvent.input(getByLabelText(/re-?auth.*grace|grace.*window|grace.*minutes/i), {
      target: { value: '30' }
    });
    await fireEvent.click(getByRole('button', { name: /save/i }));

    await waitFor(() => expect(setSettingsMock).toHaveBeenCalledTimes(1));
    expect(prompt).not.toHaveBeenCalled();
  });
});

describe('SettingsDialog.svelte — Touch ID (biometric) toggle (#277)', () => {
  // Baseline settings that hold the write-reauth gate fixed (unchanged
  // requirePasswordBeforeEdits / reauthGraceWindowMs / autoLockTimeoutMs)
  // so only the biometric toggle can move `reducesProtection`.
  const BASE_SETTINGS: SettingsDto = {
    autoLockTimeoutMs: 600_000,
    requirePasswordBeforeEdits: true,
    reauthGraceWindowMs: 120_000,
    retentionWindowMs: RETENTION_WINDOW_DEFAULT_MS
  };

  it('hides the Touch ID toggle when biometry is unavailable', () => {
    setPresencePref({ biometricEnabled: true, availability: 'unsupported' });
    unlockWith();
    const { queryByLabelText } = renderOpen();
    expect(queryByLabelText(/use touch id/i)).toBeNull();
  });

  it('renders the Touch ID toggle when biometry is available', () => {
    setPresencePref({ biometricEnabled: false, availability: 'available' });
    unlockWith();
    const { getByLabelText } = renderOpen();
    expect(getByLabelText(/use touch id/i)).toBeTruthy();
  });

  it('enabling Touch ID from disabled routes through authorizeWrite before writePresencePref(true) and mirrors the store', async () => {
    const callOrder: string[] = [];
    const prompt = vi.fn(() => {
      callOrder.push('authorizeWrite');
      return Promise.resolve();
    });
    __setWriteGuardTestSeam({
      readSettings: () => ({ enabled: true, windowMs: 0 }),
      now: () => 0,
      biometricPrefEnabled: () => false,
      tryBiometric: () => Promise.resolve('unavailable' as const),
      prompt
    });
    writePresencePrefMock.mockImplementationOnce(async () => {
      callOrder.push('writePresencePref');
    });
    setPresencePref({ biometricEnabled: false, availability: 'available' });
    unlockWith(BASE_SETTINGS);
    const { getByLabelText, getByRole } = renderOpen();

    await fireEvent.click(getByLabelText(/use touch id/i)); // false -> true

    await fireEvent.click(getByRole('button', { name: /save/i }));

    await waitFor(() => expect(writePresencePrefMock).toHaveBeenCalledWith(true));
    expect(callOrder).toEqual(['authorizeWrite', 'writePresencePref']);
    expect(get(presencePref)).toEqual({ biometricEnabled: true, availability: 'available' });
  });

  it('cancelling re-auth on the enable path persists nothing — neither setSettings nor writePresencePref', async () => {
    // The abort must land BEFORE both persistence calls: a cancelled
    // authorizeWrite may not leave the vault settings written with only the
    // pref write skipped (or vice versa), and the store mirror must not move.
    __setWriteGuardTestSeam({
      readSettings: () => ({ enabled: true, windowMs: 0 }),
      now: () => 0,
      biometricPrefEnabled: () => false,
      tryBiometric: () => Promise.resolve('unavailable' as const),
      prompt: () => Promise.reject(ReauthCancelled)
    });
    setPresencePref({ biometricEnabled: false, availability: 'available' });
    unlockWith(BASE_SETTINGS);
    const onClose = vi.fn();
    const { getByLabelText, getByRole } = renderOpen(onClose);

    await fireEvent.click(getByLabelText(/use touch id/i)); // false -> true

    await fireEvent.click(getByRole('button', { name: /save/i }));

    await new Promise((r) => setTimeout(r, 50));
    expect(setSettingsMock).not.toHaveBeenCalled();
    expect(writePresencePrefMock).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
    // Biometry stays structurally unreachable — the mirror never moved.
    expect(get(presencePref)).toEqual({ biometricEnabled: false, availability: 'available' });
  });

  it('disabling Touch ID from enabled does not trigger authorizeWrite but still persists the pref', async () => {
    const prompt = vi.fn(() => Promise.resolve());
    __setWriteGuardTestSeam({
      readSettings: () => ({ enabled: true, windowMs: 0 }),
      now: () => 0,
      biometricPrefEnabled: () => true,
      tryBiometric: () => Promise.resolve('unavailable' as const),
      prompt
    });
    setPresencePref({ biometricEnabled: true, availability: 'available' });
    unlockWith(BASE_SETTINGS);
    const { getByLabelText, getByRole } = renderOpen();

    await fireEvent.click(getByLabelText(/use touch id/i)); // true -> false

    await fireEvent.click(getByRole('button', { name: /save/i }));

    await waitFor(() => expect(writePresencePrefMock).toHaveBeenCalledWith(false));
    expect(prompt).not.toHaveBeenCalled();
    expect(get(presencePref)).toEqual({ biometricEnabled: false, availability: 'available' });
  });

  it('does not call writePresencePref when the toggle is left unchanged', async () => {
    setPresencePref({ biometricEnabled: true, availability: 'available' });
    unlockWith(BASE_SETTINGS);
    const { getByRole } = renderOpen();

    await fireEvent.click(getByRole('button', { name: /save/i }));

    await waitFor(() => expect(setSettingsMock).toHaveBeenCalledTimes(1));
    expect(writePresencePrefMock).not.toHaveBeenCalled();
  });

  it('writePresencePref rejecting after a successful setSettings surfaces the error and keeps the dialog open without rolling back the vault settings', async () => {
    // Hardening direction (enabled -> disabled) needs no re-auth, so the
    // PASS_THROUGH_SEAM from beforeEach is fine here — isolates the
    // partial-save behaviour from the gating behaviour.
    setPresencePref({ biometricEnabled: true, availability: 'available' });
    unlockWith(BASE_SETTINGS);
    writePresencePrefMock.mockRejectedValueOnce({ code: 'internal' });
    const onClose = vi.fn();
    const { getByLabelText, getByRole, findByText } = renderOpen(onClose);

    await fireEvent.click(getByLabelText(/use touch id/i)); // true -> false

    await fireEvent.click(getByRole('button', { name: /save/i }));

    expect(await findByText(/internal error/i)).toBeTruthy();
    expect(onClose).not.toHaveBeenCalled();
    expect(setSettingsMock).toHaveBeenCalledTimes(1);
    // The vault settings write already succeeded and is not rolled back —
    // sessionState reflects the persisted (unchanged, in this case) values.
    const s = get(sessionState);
    if (s.status === 'unlocked') {
      expect(s.settings.autoLockTimeoutMs).toBe(BASE_SETTINGS.autoLockTimeoutMs);
    } else {
      throw new Error('expected unlocked');
    }
    // The pref store was NOT mirrored to the failed value.
    expect(get(presencePref)).toEqual({ biometricEnabled: true, availability: 'available' });
  });

  it('disabling the toggle AND changing a vault setting in one Save mirrors biometricEnabled: false to the store', async () => {
    // MAJOR regression (#277 final review): when the save ALSO changes a vault
    // setting, `settingsUpdated` moves the `$derived` current* values, which
    // re-runs the input-re-seeding $effect during the pref-write await —
    // resetting `inputBiometric` to the PRE-save store value. The disk write
    // reads the value before that flush (correct), but the post-await
    // `setPresencePref` mirror must not read the clobbered binding: otherwise
    // disk says OFF while the session store still says ON, and Touch ID keeps
    // firing all session despite the user disabling the kill-switch.
    setPresencePref({ biometricEnabled: true, availability: 'available' });
    unlockWith(BASE_SETTINGS); // autoLockTimeoutMs 600_000 = 10 min
    const onClose = vi.fn();
    const { container, getByLabelText, getByRole } = renderOpen(onClose);

    const autoLockInput = container.querySelector('input[type="number"]') as HTMLInputElement;
    await fireEvent.input(autoLockInput, { target: { value: '5' } }); // 10 -> 5 min (tightening)
    await fireEvent.click(getByLabelText(/use touch id/i)); // true -> false (hardening)

    await fireEvent.click(getByRole('button', { name: /save/i }));

    await waitFor(() => expect(onClose).toHaveBeenCalledTimes(1));
    // Disk got the disable...
    expect(writePresencePrefMock).toHaveBeenCalledWith(false);
    // ...and the session store mirror agrees with the disk.
    expect(get(presencePref)).toEqual({ biometricEnabled: false, availability: 'available' });
  });

  it('pref-write rejection still surfaces the error when the vault settings also changed', async () => {
    // The changed-settings variant of the partial-save test above: here
    // `settingsUpdated` mutates the store, which re-runs the input-re-seeding
    // $effect (formError = null). The catch that sets formError must land
    // after that flush — this pins the ordering so the error is never wiped.
    setPresencePref({ biometricEnabled: true, availability: 'available' });
    unlockWith(BASE_SETTINGS);
    writePresencePrefMock.mockRejectedValueOnce({ code: 'internal' });
    const onClose = vi.fn();
    const { container, getByLabelText, getByRole, findByText } = renderOpen(onClose);

    const autoLockInput = container.querySelector('input[type="number"]') as HTMLInputElement;
    await fireEvent.input(autoLockInput, { target: { value: '5' } }); // 10 -> 5 min (tightening)
    await fireEvent.click(getByLabelText(/use touch id/i)); // true -> false (hardening)

    await fireEvent.click(getByRole('button', { name: /save/i }));

    expect(await findByText(/internal error/i)).toBeTruthy();
    expect(onClose).not.toHaveBeenCalled();
    // The vault settings write succeeded and stuck.
    const s = get(sessionState);
    if (s.status === 'unlocked') {
      expect(s.settings.autoLockTimeoutMs).toBe(5 * MS_PER_MINUTE);
    } else {
      throw new Error('expected unlocked');
    }
  });
});

describe('SettingsDialog.svelte — accessibility', () => {
  it('Save / Cancel buttons have type="button" (never form-submit)', () => {
    unlockWith();
    const { getByRole } = renderOpen();
    const save = getByRole('button', { name: /save/i });
    const cancel = getByRole('button', { name: /cancel/i });
    expect(save.getAttribute('type')).toBe('button');
    expect(cancel.getAttribute('type')).toBe('button');
  });

  it('renders a heading so screen readers announce the dialog purpose', () => {
    unlockWith();
    const { getByRole } = renderOpen();
    expect(getByRole('heading', { name: /settings/i })).toBeTruthy();
  });

  // #389: wire the heading to the dialog so its accessible name is the title.
  it('labels the dialog with its title via aria-labelledby (#389)', () => {
    unlockWith();
    const { container } = renderOpen();
    const dialog = container.querySelector('dialog') as HTMLDialogElement;
    const labelId = dialog.getAttribute('aria-labelledby');
    expect(labelId).toBeTruthy();
    const title = container.querySelector(`#${labelId}`);
    expect(title).not.toBeNull();
    expect(dialog.contains(title)).toBe(true);
    expect(title?.textContent).toBe('Settings');
  });
});
