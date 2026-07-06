// Tests for ReauthPasswordDialog.svelte — the native <dialog> overlay that
// prompts for a password re-confirmation before a write operation. It is
// driven by the `reauthPrompt` store and the writeGuard module.
//
// Behaviour contract:
//   - When `reauthPrompt` is non-null, the dialog opens and shows `reason`.
//   - Confirm: calls verifyPassword with the typed password.
//     On success → calls __resolveReauthPrompt() (no password argument).
//     On failure (wrong password) → renders role="alert", stays open.
//   - Cancel: calls __cancelReauthPrompt().

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import ReauthPasswordDialog from '../src/components/ReauthPasswordDialog.svelte';
import { openReauthPrompt, closeReauthPrompt, _resetSessionStateForTest } from '../src/lib/stores';

// Mock ipc so verifyPassword is injectable per-test.
vi.mock('../src/lib/ipc', () => ({
  verifyPassword: vi.fn(),
  isAppError: (e: unknown) => typeof e === 'object' && e !== null && 'code' in e
}));
import { verifyPassword } from '../src/lib/ipc';

// Mock writeGuard so we can assert the callbacks are invoked without running
// the real production seam (which touches pendingResolve/pendingReject state
// set up outside this test harness). Use vi.hoisted so the factory vars are
// available at hoist time (vi.mock factories are evaluated before imports).
const { resolveReauthMock, cancelReauthMock } = vi.hoisted(() => ({
  resolveReauthMock: vi.fn(),
  cancelReauthMock: vi.fn()
}));
vi.mock('../src/lib/writeGuard', () => ({
  __resolveReauthPrompt: resolveReauthMock,
  __cancelReauthPrompt: cancelReauthMock,
  ReauthCancelled: Symbol('ReauthCancelled'),
  authorizeWrite: vi.fn(),
  resetReauthGuard: vi.fn(),
  seedReauthClock: vi.fn()
}));

beforeEach(() => {
  vi.clearAllMocks();
  _resetSessionStateForTest();
  closeReauthPrompt(); // ensure prompt is null between tests
});

describe('ReauthPasswordDialog.svelte — prompt display', () => {
  it('renders a <dialog> element', () => {
    const { container } = render(ReauthPasswordDialog);
    expect(container.querySelector('dialog')).not.toBeNull();
  });

  it('shows the reason text when the prompt is open', async () => {
    const { getByText } = render(ReauthPasswordDialog);
    openReauthPrompt('Confirm deleting this entry');
    await waitFor(() => {
      expect(getByText('Confirm deleting this entry')).toBeTruthy();
    });
  });

  it('shows a password input with autocomplete="current-password"', async () => {
    const { container } = render(ReauthPasswordDialog);
    openReauthPrompt('test reason');
    await waitFor(() => {
      const input = container.querySelector('input[type="password"]') as HTMLInputElement;
      expect(input).not.toBeNull();
      expect(input.getAttribute('autocomplete')).toBe('current-password');
    });
  });
});

describe('ReauthPasswordDialog.svelte — confirm happy path', () => {
  it('shows the reason and verifies on confirm', async () => {
    (verifyPassword as ReturnType<typeof vi.fn>).mockResolvedValueOnce(undefined);
    const { getByText, getByLabelText } = render(ReauthPasswordDialog);
    openReauthPrompt('Confirm deleting this entry');
    await waitFor(() => getByText('Confirm deleting this entry'));
    await fireEvent.input(getByLabelText(/^password$/i), { target: { value: 'pw' } });
    await fireEvent.click(getByText('Confirm'));
    await waitFor(() => {
      expect(verifyPassword).toHaveBeenCalledWith('pw');
    });
  });

  it('calls __resolveReauthPrompt (not __cancelReauthPrompt) after successful verify', async () => {
    (verifyPassword as ReturnType<typeof vi.fn>).mockResolvedValueOnce(undefined);
    const { getByText, getByLabelText } = render(ReauthPasswordDialog);
    openReauthPrompt('Confirm saving');
    await waitFor(() => getByText('Confirm saving'));
    await fireEvent.input(getByLabelText(/^password$/i), { target: { value: 'correct-pw' } });
    await fireEvent.click(getByText('Confirm'));
    await waitFor(() => {
      expect(resolveReauthMock).toHaveBeenCalledTimes(1);
      expect(cancelReauthMock).not.toHaveBeenCalled();
    });
  });
});

describe('ReauthPasswordDialog.svelte — wrong password stays open', () => {
  it('shows an inline error on wrong password and stays open', async () => {
    (verifyPassword as ReturnType<typeof vi.fn>).mockRejectedValueOnce({ code: 'wrong_password' });
    const { getByText, getByLabelText, queryByRole } = render(ReauthPasswordDialog);
    openReauthPrompt('Confirm saving this entry');
    await waitFor(() => getByText('Confirm saving this entry'));
    await fireEvent.input(getByLabelText(/^password$/i), { target: { value: 'bad' } });
    await fireEvent.click(getByText('Confirm'));
    await waitFor(() => {
      expect(queryByRole('alert')).toBeTruthy();
    });
  });

  it('does NOT call __resolveReauthPrompt on wrong password', async () => {
    (verifyPassword as ReturnType<typeof vi.fn>).mockRejectedValueOnce({ code: 'wrong_password' });
    const { getByText, getByLabelText, queryByRole } = render(ReauthPasswordDialog);
    openReauthPrompt('Confirm saving this entry');
    await waitFor(() => getByText('Confirm saving this entry'));
    await fireEvent.input(getByLabelText(/^password$/i), { target: { value: 'bad' } });
    await fireEvent.click(getByText('Confirm'));
    // Wait for the error alert to appear (means verify settled), then assert no resolve.
    await waitFor(() => expect(queryByRole('alert')).toBeTruthy());
    expect(resolveReauthMock).not.toHaveBeenCalled();
  });
});

describe('ReauthPasswordDialog.svelte — cancel', () => {
  it('Cancel calls __cancelReauthPrompt', async () => {
    const { getByText } = render(ReauthPasswordDialog);
    openReauthPrompt('Confirm something');
    await waitFor(() => getByText('Confirm something'));
    await fireEvent.click(getByText('Cancel'));
    await waitFor(() => {
      expect(cancelReauthMock).toHaveBeenCalledTimes(1);
    });
  });

  it('Cancel does not call __resolveReauthPrompt', async () => {
    const { getByText } = render(ReauthPasswordDialog);
    openReauthPrompt('Confirm something');
    await waitFor(() => getByText('Confirm something'));
    await fireEvent.click(getByText('Cancel'));
    await waitFor(() => {
      expect(resolveReauthMock).not.toHaveBeenCalled();
    });
  });
});

describe('ReauthPasswordDialog.svelte — accessibility', () => {
  // #389: when open, the dialog's accessible name is its title heading.
  it('labels the dialog with its title via aria-labelledby (#389)', async () => {
    const { container, getByText } = render(ReauthPasswordDialog);
    openReauthPrompt('Confirm something');
    await waitFor(() => getByText('Confirm something'));
    const dialog = container.querySelector('dialog') as HTMLDialogElement;
    const labelId = dialog.getAttribute('aria-labelledby');
    expect(labelId).toBeTruthy();
    const title = container.querySelector(`#${labelId}`);
    expect(title).not.toBeNull();
    expect(dialog.contains(title)).toBe(true);
    expect(title?.textContent).toBe('Confirm with your password');
  });
});
