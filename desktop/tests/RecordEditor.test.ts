import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));
import RecordEditor from '../src/components/edit/RecordEditor.svelte';
import type { BlockSummaryDto } from '../src/lib/ipc';

const BLOCK: BlockSummaryDto = { blockUuidHex: 'ab', blockName: 'B', createdAtMs: 1, lastModifiedMs: 1 };

describe('RecordEditor (add mode)', () => {
  beforeEach(() => invokeMock.mockReset());

  it('disables Save until a valid field exists, then saves', async () => {
    invokeMock.mockResolvedValueOnce({ blockUuidHex: 'ab', recordUuidHex: 'cd' });
    const onSaved = vi.fn();
    const { getByLabelText, getByRole } = render(RecordEditor, { props: { block: BLOCK, record: null, onSaved, onCancel: vi.fn() } });
    const save = getByRole('button', { name: /^save/i }) as HTMLButtonElement;
    expect(save.disabled).toBe(true);
    await fireEvent.input(getByLabelText(/field name/i), { target: { value: 'user' } });
    await fireEvent.input(getByLabelText(/field value/i), { target: { value: 'alice' } });
    expect(save.disabled).toBe(false);
    await fireEvent.click(save);
    await waitFor(() => expect(invokeMock).toHaveBeenCalledWith('save_record', expect.objectContaining({ blockUuidHex: 'ab' })));
    await waitFor(() => expect(onSaved).toHaveBeenCalled());
  });

  it('clears the draft and calls onCancel when Cancel is clicked', async () => {
    const onCancel = vi.fn();
    const { getByLabelText, getByRole } = render(RecordEditor, { props: { block: BLOCK, record: null, onSaved: vi.fn(), onCancel } });
    // Type a secret-bearing value into the draft, then cancel.
    await fireEvent.input(getByLabelText(/field value/i), { target: { value: 'hunter2' } });
    await fireEvent.click(getByRole('button', { name: /cancel/i }));
    expect(onCancel).toHaveBeenCalledTimes(1);
    // The field value input is reset to empty (draft cleared), so the
    // plaintext is no longer held in the editor's reactive state.
    expect((getByLabelText(/field value/i) as HTMLInputElement).value).toBe('');
  });
});
