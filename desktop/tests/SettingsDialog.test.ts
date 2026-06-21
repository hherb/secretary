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

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import { get } from 'svelte/store';
import SettingsDialog from '../src/components/SettingsDialog.svelte';
import {
  sessionState,
  beginUnlock,
  unlockSucceeded,
  _resetSessionStateForTest
} from '../src/lib/stores';
import {
  MS_PER_MINUTE,
  AUTO_LOCK_MIN_MS,
  AUTO_LOCK_MAX_MS,
  AUTO_LOCK_DEFAULT_MS,
  REAUTH_WINDOW_MIN_MS,
  REAUTH_WINDOW_MAX_MS,
  REAUTH_WINDOW_DEFAULT_MS,
  REQUIRE_PASSWORD_DEFAULT
} from '../src/lib/constants';
import type { ManifestDto, SettingsDto } from '../src/lib/ipc';
import type { AppError } from '../src/lib/errors';

const MANIFEST: ManifestDto = {
  vaultUuidHex: 'aa',
  ownerUserUuidHex: 'bb',
  blockCount: 0,
  blockSummaries: [],
  warnings: []
};
const INITIAL_SETTINGS: SettingsDto = { autoLockTimeoutMs: 900_000, requirePasswordBeforeEdits: false, reauthGraceWindowMs: 120_000 }; // 15 minutes

// Hoist the setSettings IPC mock so individual tests can drive
// resolve / reject as needed.
const { setSettingsMock, lockMock } = vi.hoisted(() => ({
  setSettingsMock: vi.fn(),
  lockMock: vi.fn()
}));
vi.mock('../src/lib/ipc', async () => {
  const real = await vi.importActual<typeof import('../src/lib/ipc')>('../src/lib/ipc');
  return { ...real, setSettings: setSettingsMock, lock: lockMock };
});

beforeEach(() => {
  _resetSessionStateForTest();
  setSettingsMock.mockReset();
  setSettingsMock.mockResolvedValue(undefined);
  lockMock.mockReset();
  lockMock.mockResolvedValue(undefined);
});

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
    unlockWith({ autoLockTimeoutMs: 900_000, requirePasswordBeforeEdits: false, reauthGraceWindowMs: 120_000 }); // 15 min
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
    unlockWith({ autoLockTimeoutMs: 600_000, requirePasswordBeforeEdits: true, reauthGraceWindowMs: 120_000 });
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

  it('Save with a window minutes value below REAUTH_WINDOW_MIN_MS surfaces settings_out_of_range', async () => {
    // REAUTH_WINDOW_MIN_MS is 0 (0 min is valid); there is no sub-zero
    // integer we can enter in a min=0 number field — the browser/JSDOM
    // clamps. Test a value above MAX instead.
    unlockWith({ autoLockTimeoutMs: 600_000, requirePasswordBeforeEdits: true, reauthGraceWindowMs: 120_000 });
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
    unlockWith({ autoLockTimeoutMs: 600_000, requirePasswordBeforeEdits: true, reauthGraceWindowMs: 180_000 }); // 3 min
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
});
