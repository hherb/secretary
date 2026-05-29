import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import MnemonicStep from '../src/components/create/MnemonicStep.svelte';

vi.mock('@tauri-apps/plugin-clipboard-manager', () => ({
  writeText: vi.fn().mockResolvedValue(undefined)
}));
import { writeText } from '@tauri-apps/plugin-clipboard-manager';

const PHRASE = Array.from({ length: 24 }, (_, i) => `word${i + 1}`).join(' ');

describe('MnemonicStep', () => {
  beforeEach(() => vi.clearAllMocks());

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

  it('copy button writes the phrase to the clipboard', async () => {
    const { getByRole } = render(MnemonicStep, { props: { mnemonic: PHRASE, onDone: vi.fn() } });
    await fireEvent.click(getByRole('button', { name: /copy/i }));
    expect(writeText).toHaveBeenCalledWith(PHRASE);
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
      await vi.advanceTimersByTimeAsync(0); // flush writeText(PHRASE) promise
      expect(writeText).toHaveBeenCalledWith(PHRASE);
      // Unmount before the 30s auto-clear fires (simulates user clicking Continue quickly).
      unmount();
      // The clear must have been fired eagerly, not stranded in the clipboard.
      expect(writeText).toHaveBeenLastCalledWith('');
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
      expect(writeText).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });
});
