// Component-level tests for PathPicker.svelte.
//
// PathPicker wraps `@tauri-apps/plugin-dialog`'s native folder-picker
// dialog. The component itself is small (text field + button); the
// behaviour worth pinning is the open()-then-onSelect contract: the
// dialog opens with the expected options, a returned string fires the
// callback, a cancelled dialog (null return) is a no-op, and the
// disabled prop blocks the click handler entirely.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import PathPicker from '../src/components/PathPicker.svelte';

// The dialog plugin must be mocked: jsdom has no Tauri runtime, so the
// real module would fail at import. `vi.hoisted` returns the mock fn
// before the `vi.mock` factory runs (the factory body executes BEFORE
// module-scope `const` initializers).
const { openMock } = vi.hoisted(() => ({ openMock: vi.fn() }));
vi.mock('@tauri-apps/plugin-dialog', () => ({ open: openMock }));

beforeEach(() => {
  openMock.mockReset();
});

describe('PathPicker', () => {
  it('renders the current value in the text input', () => {
    const { getByRole } = render(PathPicker, {
      props: { value: '/home/alice/vault', onSelect: vi.fn() }
    });
    const input = getByRole('textbox') as HTMLInputElement;
    expect(input.value).toBe('/home/alice/vault');
  });

  it('shows placeholder when value is empty', () => {
    const { getByRole } = render(PathPicker, {
      props: { value: '', onSelect: vi.fn() }
    });
    const input = getByRole('textbox') as HTMLInputElement;
    expect(input.value).toBe('');
    expect(input.placeholder).toMatch(/no folder/i);
  });

  it('input is readonly — value comes from the dialog only', () => {
    const { getByRole } = render(PathPicker, {
      props: { value: '/x', onSelect: vi.fn() }
    });
    const input = getByRole('textbox') as HTMLInputElement;
    expect(input.readOnly).toBe(true);
  });

  it('opens the folder picker dialog when the button is clicked', async () => {
    openMock.mockResolvedValueOnce('/home/alice/picked');
    const onSelect = vi.fn();
    const { getByRole } = render(PathPicker, {
      props: { value: '', onSelect }
    });
    await fireEvent.click(getByRole('button'));
    expect(openMock).toHaveBeenCalledTimes(1);
    expect(openMock).toHaveBeenCalledWith({
      directory: true,
      multiple: false,
      title: expect.any(String)
    });
  });

  it('calls onSelect with the chosen folder path', async () => {
    openMock.mockResolvedValueOnce('/home/alice/vault');
    const onSelect = vi.fn();
    const { getByRole } = render(PathPicker, {
      props: { value: '', onSelect }
    });
    await fireEvent.click(getByRole('button'));
    // `waitFor` polls until the assertion passes — robust against any
    // future microtask-depth changes in `pick()`.
    await waitFor(() => expect(onSelect).toHaveBeenCalledWith('/home/alice/vault'));
    expect(onSelect).toHaveBeenCalledTimes(1);
  });

  it('does NOT call onSelect when the dialog is cancelled (returns null)', async () => {
    openMock.mockResolvedValueOnce(null);
    const onSelect = vi.fn();
    const { getByRole } = render(PathPicker, {
      props: { value: '', onSelect }
    });
    await fireEvent.click(getByRole('button'));
    // Settle the awaited dialog promise + the conditional branch
    // continuation before asserting the negative.
    await openMock.mock.results[0].value;
    await Promise.resolve();
    expect(onSelect).not.toHaveBeenCalled();
  });

  it('disabled prop prevents opening the dialog', async () => {
    const onSelect = vi.fn();
    const { getByRole } = render(PathPicker, {
      props: { value: '', onSelect, disabled: true }
    });
    const button = getByRole('button') as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    await fireEvent.click(button);
    // Disabled buttons don't fire click handlers; even if the user
    // manages to dispatch one programmatically the open() call must
    // be a no-op so we never leak a stray dialog.
    expect(openMock).not.toHaveBeenCalled();
    expect(onSelect).not.toHaveBeenCalled();
  });

  it('does not crash when the dialog returns a non-string array (multi-select misuse)', async () => {
    // `multiple: false` is hard-coded so the return type is `string | null`,
    // but the runtime can't enforce that. Defensive check: if a future
    // refactor changes the options and yields an array, we ignore it
    // rather than calling onSelect with the wrong shape.
    openMock.mockResolvedValueOnce(['/a', '/b'] as unknown as string);
    const onSelect = vi.fn();
    const { getByRole } = render(PathPicker, {
      props: { value: '', onSelect }
    });
    await fireEvent.click(getByRole('button'));
    // Settle the awaited dialog promise + the conditional branch
    // continuation before asserting the negative.
    await openMock.mock.results[0].value;
    await Promise.resolve();
    expect(onSelect).not.toHaveBeenCalled();
  });

  // --- File mode (D.1.6 contact-card import) ---------------------------
  // `directory={false}` + `filters`/`title`/`label` is the contact-import
  // path; the assertions below pin the branching that folder-mode tests
  // never exercise. The folder default must stay byte-identical (covered
  // above), so these only assert the file-mode deltas.

  it('file mode: opens the dialog with directory:false and the given filters', async () => {
    openMock.mockResolvedValueOnce('/home/alice/bob.card');
    const onSelect = vi.fn();
    const filters = [{ name: 'Contact card', extensions: ['card'] }];
    const { getByRole } = render(PathPicker, {
      props: { value: '', onSelect, directory: false, filters, title: 'Import a contact card' }
    });
    await fireEvent.click(getByRole('button'));
    expect(openMock).toHaveBeenCalledWith({
      directory: false,
      multiple: false,
      title: 'Import a contact card',
      filters
    });
    await waitFor(() => expect(onSelect).toHaveBeenCalledWith('/home/alice/bob.card'));
  });

  it('file mode: title falls back to undefined (not the folder prompt) when omitted', async () => {
    openMock.mockResolvedValueOnce(null);
    const { getByRole } = render(PathPicker, {
      props: { value: '', onSelect: vi.fn(), directory: false, filters: [] }
    });
    await fireEvent.click(getByRole('button'));
    expect(openMock).toHaveBeenCalledWith({
      directory: false,
      multiple: false,
      title: undefined,
      filters: []
    });
  });

  it('file mode: placeholder and custom button label switch for files', () => {
    const { getByRole } = render(PathPicker, {
      props: { value: '', onSelect: vi.fn(), directory: false, label: 'Import a contact…' }
    });
    const input = getByRole('textbox') as HTMLInputElement;
    expect(input.placeholder).toMatch(/no file/i);
    expect(getByRole('button').textContent).toContain('Import a contact…');
  });
});
