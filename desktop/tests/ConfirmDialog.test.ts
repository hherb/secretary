// Tests for ConfirmDialog.svelte — the shared destructive-action confirm
// modal (delete record, trash block). Native <dialog> mirroring
// SettingsDialog; callback props (onConfirm / onCancel), no event
// dispatcher. Behaviour contract:
//
//   - Renders a <dialog> with the given title + body and two buttons:
//     Cancel and a confirm button labelled with `confirmLabel`.
//   - Clicking the confirm button fires onConfirm.
//   - Clicking Cancel fires onCancel.
//
// JSDOM's <dialog> showModal/close are polyfilled in tests/setup.ts.

import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import ConfirmDialog from '../src/components/delete/ConfirmDialog.svelte';

function renderDialog(overrides: Record<string, unknown> = {}) {
  const onConfirm = vi.fn();
  const onCancel = vi.fn();
  const utils = render(ConfirmDialog, {
    props: {
      title: 'Delete this record?',
      body: 'You can restore it from Show deleted.',
      confirmLabel: 'Delete',
      onConfirm,
      onCancel,
      ...overrides
    }
  });
  return { ...utils, onConfirm, onCancel };
}

describe('ConfirmDialog.svelte', () => {
  it('renders a <dialog> with the title and body', async () => {
    const { container, getByText } = renderDialog();
    expect(container.querySelector('dialog')).not.toBeNull();
    expect(getByText('Delete this record?')).toBeTruthy();
    expect(getByText(/restore it from show deleted/i)).toBeTruthy();
  });

  it('opens the dialog (showModal) on mount', async () => {
    const { container } = renderDialog();
    await waitFor(() => {
      const dialog = container.querySelector('dialog') as HTMLDialogElement;
      expect(dialog.hasAttribute('open')).toBe(true);
    });
  });

  it('fires onConfirm when the confirm button is clicked', async () => {
    const { getByRole, onConfirm, onCancel } = renderDialog();
    await fireEvent.click(getByRole('button', { name: 'Delete' }));
    expect(onConfirm).toHaveBeenCalledTimes(1);
    expect(onCancel).not.toHaveBeenCalled();
  });

  it('fires onCancel when the Cancel button is clicked', async () => {
    const { getByRole, onConfirm, onCancel } = renderDialog();
    await fireEvent.click(getByRole('button', { name: /cancel/i }));
    expect(onCancel).toHaveBeenCalledTimes(1);
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it('uses the supplied confirmLabel as the confirm button name', () => {
    const { getByRole } = renderDialog({ confirmLabel: 'Trash' });
    expect(getByRole('button', { name: 'Trash' })).toBeTruthy();
  });

  it('confirm and cancel buttons have type="button" (never form-submit)', () => {
    const { getByRole } = renderDialog();
    expect(getByRole('button', { name: 'Delete' }).getAttribute('type')).toBe('button');
    expect(getByRole('button', { name: /cancel/i }).getAttribute('type')).toBe('button');
  });

  // #389: screen readers should announce the dialog's title on open. Native
  // <dialog> gives an implicit role="dialog" but no accessible name unless the
  // title is wired via aria-labelledby.
  it('labels the dialog with its title via aria-labelledby (#389)', () => {
    const { container } = renderDialog();
    const dialog = container.querySelector('dialog') as HTMLDialogElement;
    const labelId = dialog.getAttribute('aria-labelledby');
    expect(labelId).toBeTruthy();
    const title = container.querySelector(`#${labelId}`);
    expect(title).not.toBeNull();
    expect(dialog.contains(title)).toBe(true);
    expect(title?.textContent).toBe('Delete this record?');
  });
});
