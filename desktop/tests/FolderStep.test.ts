import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import FolderStep from '../src/components/create/FolderStep.svelte';

vi.mock('../src/lib/ipc', () => ({
  probeCreateTarget: vi.fn()
}));
import { probeCreateTarget } from '../src/lib/ipc';

// PathPicker invokes `pick_create_folder` directly via `@tauri-apps/api/core`
// (#353/#378); these tests seed the picker via `seedPath` and never click the
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

  // #378: a seed path carried over from the Unlock screen has no CreateParent
  // approval — the probe rejects with path_not_approved. The step must keep
  // Continue disabled and ask the user to confirm the folder via the picker.
  it('unapproved seed path disables Continue and asks for a fresh pick', async () => {
    (probeCreateTarget as ReturnType<typeof vi.fn>).mockRejectedValueOnce({
      code: 'path_not_approved',
      path: '/Users/h/Docs'
    });
    const onNext = vi.fn();
    const { findByText, findByRole } = render(FolderStep, {
      props: { seedPath: '/Users/h/Docs', onNext, onCancel: vi.fn() }
    });
    expect(await findByText(/confirm the folder/i)).toBeTruthy();
    const cont = (await findByRole('button', { name: /continue/i })) as HTMLButtonElement;
    expect(cont.disabled).toBe(true);
  });

  // #378 regression: re-picking the SAME folder as the rejected seed must
  // re-probe. The pick returns a string identical to the seed, so `picked`
  // never changes — a `picked`-tracking effect would not re-fire and the step
  // would strand with Continue disabled even though `pick_create_folder` just
  // approved the path. The explicit re-probe in `onPick` fixes it.
  it('re-picking the same folder as the rejected seed re-probes and enables Continue', async () => {
    (probeCreateTarget as ReturnType<typeof vi.fn>)
      .mockRejectedValueOnce({ code: 'path_not_approved', path: '/Users/h/Docs' })
      .mockResolvedValueOnce({ exists: true, isEmpty: true });
    const onNext = vi.fn();
    const { findByText, findByRole, getByRole } = render(FolderStep, {
      props: { seedPath: '/Users/h/Docs', onNext, onCancel: vi.fn() }
    });
    // Seed probe rejected → the "confirm the folder" prompt is shown.
    expect(await findByText(/confirm the folder/i)).toBeTruthy();
    // The picker (mocked invoke) returns '/Users/h/Docs' — the SAME string.
    await fireEvent.click(getByRole('button', { name: /choose/i }));
    // The explicit re-probe resolves empty → Continue enables and works.
    expect(await findByText(/ready to create/i)).toBeTruthy();
    const cont = (await findByRole('button', { name: /continue/i })) as HTMLButtonElement;
    expect(cont.disabled).toBe(false);
    await fireEvent.click(cont);
    expect(onNext).toHaveBeenCalledWith('/Users/h/Docs');
  });

  // A non-approval probe failure (e.g. io) must surface a concrete message
  // rather than silently greying out Continue with no explanation.
  it('a non-approval probe error is shown inline and keeps Continue disabled', async () => {
    (probeCreateTarget as ReturnType<typeof vi.fn>).mockRejectedValueOnce({ code: 'io' });
    const { findByText, findByRole } = render(FolderStep, {
      props: { seedPath: '/Users/h/Docs', onNext: vi.fn(), onCancel: vi.fn() }
    });
    expect(await findByText(/filesystem error/i)).toBeTruthy();
    const cont = (await findByRole('button', { name: /continue/i })) as HTMLButtonElement;
    expect(cont.disabled).toBe(true);
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
