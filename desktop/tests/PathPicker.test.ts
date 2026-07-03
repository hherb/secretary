// Component-level tests for PathPicker.svelte.
//
// #353: PathPicker no longer opens a dialog in the webview. It invokes a
// backend `pick_*` command (which opens the native dialog server-side,
// records the chosen path in Rust state, and returns it for display). The
// behaviour worth pinning is the invoke()-then-onSelect contract: invoke is
// called with the exact `command` prop, a returned string fires the
// callback, a cancelled dialog (null return) is a no-op, and the disabled
// prop blocks the click handler entirely.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import PathPicker from '../src/components/PathPicker.svelte';

// `@tauri-apps/api/core` must be mocked: jsdom has no Tauri runtime, so the
// real module would fail at import. `vi.hoisted` returns the mock fn
// before the `vi.mock` factory runs (the factory body executes BEFORE
// module-scope `const` initializers).
const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));

beforeEach(() => {
  invokeMock.mockReset();
});

describe('PathPicker', () => {
  it('renders the current value in the text input', () => {
    const { getByRole } = render(PathPicker, {
      props: { value: '/home/alice/vault', onSelect: vi.fn(), command: 'pick_vault_folder' }
    });
    const input = getByRole('textbox') as HTMLInputElement;
    expect(input.value).toBe('/home/alice/vault');
  });

  it('shows the default placeholder when value is empty', () => {
    const { getByRole } = render(PathPicker, {
      props: { value: '', onSelect: vi.fn(), command: 'pick_vault_folder' }
    });
    const input = getByRole('textbox') as HTMLInputElement;
    expect(input.value).toBe('');
    expect(input.placeholder).toBe('No path selected');
  });

  it('honours a custom placeholder prop', () => {
    const { getByRole } = render(PathPicker, {
      props: {
        value: '',
        onSelect: vi.fn(),
        command: 'pick_export_dir',
        placeholder: 'No folder selected'
      }
    });
    const input = getByRole('textbox') as HTMLInputElement;
    expect(input.placeholder).toBe('No folder selected');
  });

  it('input is readonly — value comes from the backend picker only', () => {
    const { getByRole } = render(PathPicker, {
      props: { value: '/x', onSelect: vi.fn(), command: 'pick_vault_folder' }
    });
    const input = getByRole('textbox') as HTMLInputElement;
    expect(input.readOnly).toBe(true);
  });

  it('invokes the given command when the button is clicked', async () => {
    invokeMock.mockResolvedValueOnce('/home/alice/picked');
    const onSelect = vi.fn();
    const { getByRole } = render(PathPicker, {
      props: { value: '', onSelect, command: 'pick_vault_folder' }
    });
    await fireEvent.click(getByRole('button'));
    expect(invokeMock).toHaveBeenCalledTimes(1);
    expect(invokeMock).toHaveBeenCalledWith('pick_vault_folder');
  });

  it('calls onSelect with the path returned by the backend command', async () => {
    invokeMock.mockResolvedValueOnce('/home/alice/vault');
    const onSelect = vi.fn();
    const { getByRole } = render(PathPicker, {
      props: { value: '', onSelect, command: 'pick_vault_folder' }
    });
    await fireEvent.click(getByRole('button'));
    // `waitFor` polls until the assertion passes — robust against any
    // future microtask-depth changes in `pick()`.
    await waitFor(() => expect(onSelect).toHaveBeenCalledWith('/home/alice/vault'));
    expect(onSelect).toHaveBeenCalledTimes(1);
  });

  it('does NOT call onSelect when the backend returns null (dialog cancelled)', async () => {
    invokeMock.mockResolvedValueOnce(null);
    const onSelect = vi.fn();
    const { getByRole } = render(PathPicker, {
      props: { value: '', onSelect, command: 'pick_vault_folder' }
    });
    await fireEvent.click(getByRole('button'));
    // Settle the awaited invoke promise + the conditional branch
    // continuation before asserting the negative.
    await invokeMock.mock.results[0].value;
    await Promise.resolve();
    expect(onSelect).not.toHaveBeenCalled();
  });

  it('disabled prop prevents invoking the command', async () => {
    const onSelect = vi.fn();
    const { getByRole } = render(PathPicker, {
      props: { value: '', onSelect, command: 'pick_vault_folder', disabled: true }
    });
    const button = getByRole('button') as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    await fireEvent.click(button);
    // Disabled buttons don't fire click handlers; even if the user
    // manages to dispatch one programmatically the invoke() call must
    // be a no-op so we never leak a stray dialog.
    expect(invokeMock).not.toHaveBeenCalled();
    expect(onSelect).not.toHaveBeenCalled();
  });

  it('does not crash when the backend returns a non-string value (defensive check)', async () => {
    // The Rust command's return type is `Option<String>`, but the runtime
    // can't enforce that on the JS side. Defensive check: if a future
    // refactor changes the return shape, we ignore it rather than calling
    // onSelect with the wrong shape.
    invokeMock.mockResolvedValueOnce(['/a', '/b'] as unknown as string);
    const onSelect = vi.fn();
    const { getByRole } = render(PathPicker, {
      props: { value: '', onSelect, command: 'pick_vault_folder' }
    });
    await fireEvent.click(getByRole('button'));
    // Settle the awaited invoke promise + the conditional branch
    // continuation before asserting the negative.
    await invokeMock.mock.results[0].value;
    await Promise.resolve();
    expect(onSelect).not.toHaveBeenCalled();
  });

  // --- Other commands (D.1.6/D.1.7 contact-card import / export) --------
  // Each PathPicker instance is bound to exactly one command; these pin
  // that the correct command string reaches `invoke` and that `label`
  // still customises the button text.

  it('contact-card mode: invokes pick_contact_card and applies the custom label', async () => {
    invokeMock.mockResolvedValueOnce('/home/alice/bob.card');
    const onSelect = vi.fn();
    const { getByRole } = render(PathPicker, {
      props: {
        value: '',
        onSelect,
        command: 'pick_contact_card',
        label: 'Import a contact…',
        placeholder: 'No file selected'
      }
    });
    const input = getByRole('textbox') as HTMLInputElement;
    expect(input.placeholder).toBe('No file selected');
    expect(getByRole('button').textContent).toContain('Import a contact…');
    await fireEvent.click(getByRole('button'));
    expect(invokeMock).toHaveBeenCalledWith('pick_contact_card');
    await waitFor(() => expect(onSelect).toHaveBeenCalledWith('/home/alice/bob.card'));
  });

  it('export-dir mode: invokes pick_export_dir', async () => {
    invokeMock.mockResolvedValueOnce('/tmp/exports');
    const onSelect = vi.fn();
    const { getByRole } = render(PathPicker, {
      props: { value: '', onSelect, command: 'pick_export_dir', label: 'Export…' }
    });
    await fireEvent.click(getByRole('button'));
    expect(invokeMock).toHaveBeenCalledWith('pick_export_dir');
    await waitFor(() => expect(onSelect).toHaveBeenCalledWith('/tmp/exports'));
  });
});
