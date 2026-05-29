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
});
