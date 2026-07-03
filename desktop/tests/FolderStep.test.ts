import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import FolderStep from '../src/components/create/FolderStep.svelte';

vi.mock('../src/lib/ipc', () => ({
  probeCreateTarget: vi.fn()
}));
import { probeCreateTarget } from '../src/lib/ipc';

// PathPicker invokes `pick_vault_folder` directly via `@tauri-apps/api/core`
// (#353); these tests seed the picker via `seedPath` and never click the
// Choose… button, so the mock only needs to exist to satisfy the import.
vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn().mockResolvedValue('/Users/h/Docs')
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

  it('Cancel invokes onCancel', async () => {
    (probeCreateTarget as ReturnType<typeof vi.fn>).mockResolvedValue({
      exists: true,
      isEmpty: true
    });
    const onCancel = vi.fn();
    const { getByRole } = render(FolderStep, {
      props: { seedPath: '', onNext: vi.fn(), onCancel }
    });
    await fireEvent.click(getByRole('button', { name: /cancel/i }));
    expect(onCancel).toHaveBeenCalled();
  });

  it('subfolder path: typing a name yields the joined path on Continue', async () => {
    (probeCreateTarget as ReturnType<typeof vi.fn>).mockResolvedValue({
      exists: true,
      isEmpty: false
    });
    const onNext = vi.fn();
    const { findByLabelText, findByRole } = render(FolderStep, {
      props: { seedPath: '/Users/h/Docs', onNext, onCancel: vi.fn() }
    });
    const subfolderInput = await findByLabelText(/subfolder name/i);
    await fireEvent.input(subfolderInput, { target: { value: 'vault' } });
    const cont = (await findByRole('button', { name: /continue/i })) as HTMLButtonElement;
    await fireEvent.click(cont);
    expect(onNext).toHaveBeenCalledWith('/Users/h/Docs/vault');
  });
});
