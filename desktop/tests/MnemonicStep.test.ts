import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';

// Audit DT-2: the copy affordance goes through the Rust `copy_secret_text` /
// `clear_clipboard` commands (OS concealment flags), never the webview
// clipboard plugin — so the seam under test is `invoke`, not `writeText`.
const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));

import MnemonicStep from '../src/components/create/MnemonicStep.svelte';

const PHRASE = Array.from({ length: 24 }, (_, i) => `word${i + 1}`).join(' ');

function lastCommand(): unknown {
  return invokeMock.mock.calls.at(-1)?.[0];
}

describe('MnemonicStep', () => {
  beforeEach(() => {
    invokeMock.mockReset();
    invokeMock.mockResolvedValue(undefined);
  });

  it('renders 24 numbered words and gates Continue on acknowledge', async () => {
    const onDone = vi.fn();
    const { getAllByTestId, getByRole, getByLabelText } = render(MnemonicStep, {
      props: { mnemonic: PHRASE, onDone }
    });
    expect(getAllByTestId('mnemonic-word')).toHaveLength(24);

    const cont = getByRole('button', { name: /continue/i }) as HTMLButtonElement;
    expect(cont.disabled).toBe(true);

    await fireEvent.click(getByLabelText(/written down/i));
    expect(cont.disabled).toBe(false);
    await fireEvent.click(cont);
    expect(onDone).toHaveBeenCalled();
  });

  it('copy button writes the phrase through the Rust concealed-clipboard command', async () => {
    const { getByRole } = render(MnemonicStep, { props: { mnemonic: PHRASE, onDone: vi.fn() } });
    await fireEvent.click(getByRole('button', { name: /copy/i }));
    expect(invokeMock).toHaveBeenCalledWith('copy_secret_text', { text: PHRASE });
  });

  // Security regression: a copied recovery phrase must not outlive the wizard step.
  // On unmount (user clicks Continue shortly after copying), the pending clipboard
  // auto-clear must fire NOW, not be silently dropped — mirroring the FieldRow
  // precedent (spec §7 / D.1.2).
  it('clears the clipboard immediately on unmount when a copy is pending', async () => {
    vi.useFakeTimers();
    try {
      const { getByRole, unmount } = render(MnemonicStep, {
        props: { mnemonic: PHRASE, onDone: vi.fn() }
      });
      await fireEvent.click(getByRole('button', { name: /copy/i }));
      await vi.advanceTimersByTimeAsync(0); // flush the copy promise
      expect(invokeMock).toHaveBeenCalledWith('copy_secret_text', { text: PHRASE });
      // Unmount before the 30s auto-clear fires (simulates user clicking Continue quickly).
      unmount();
      // The clear must have been fired eagerly, not stranded in the clipboard.
      expect(lastCommand()).toBe('clear_clipboard');
    } finally {
      vi.useRealTimers();
    }
  });

  it('does not touch the clipboard on unmount when nothing was copied', async () => {
    vi.useFakeTimers();
    try {
      const { unmount } = render(MnemonicStep, {
        props: { mnemonic: PHRASE, onDone: vi.fn() }
      });
      // Unmount without ever clicking Copy.
      unmount();
      expect(invokeMock).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });
});
