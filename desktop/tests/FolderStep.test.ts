import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import FolderStep from '../src/components/create/FolderStep.svelte';

vi.mock('../src/lib/ipc', () => ({
  probeCreateTarget: vi.fn()
}));
import { probeCreateTarget } from '../src/lib/ipc';

vi.mock('@tauri-apps/plugin-dialog', () => ({
  open: vi.fn().mockResolvedValue('/Users/h/Docs')
}));

describe('FolderStep', () => {
  beforeEach(() => vi.clearAllMocks());

  it('offers the subfolder field when the picked folder is non-empty', async () => {
    (probeCreateTarget as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      exists: true,
      isEmpty: false
    });
    const onNext = vi.fn();
    const { getByText, findByLabelText } = render(FolderStep, {
      props: { seedPath: '/Users/h/Docs', onNext, onCancel: vi.fn() }
    });
    expect(await findByLabelText(/subfolder name/i)).toBeTruthy();
    expect(getByText(/already contains files/i)).toBeTruthy();
  });

  it('continues with the picked folder when it is empty', async () => {
    (probeCreateTarget as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      exists: true,
      isEmpty: true
    });
    const onNext = vi.fn();
    const { findByRole } = render(FolderStep, {
      props: { seedPath: '/Users/h/empty', onNext, onCancel: vi.fn() }
    });
    const cont = (await findByRole('button', { name: /continue/i })) as HTMLButtonElement;
    expect(cont.disabled).toBe(false);
    await fireEvent.click(cont);
    expect(onNext).toHaveBeenCalledWith('/Users/h/empty');
  });
});
