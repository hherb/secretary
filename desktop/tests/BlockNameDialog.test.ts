import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));
import BlockNameDialog from '../src/components/edit/BlockNameDialog.svelte';

const block = { blockUuidHex: 'ab', blockName: 'Before', createdAtMs: 1, lastModifiedMs: 1 };

describe('BlockNameDialog', () => {
  beforeEach(() => invokeMock.mockReset());

  it('create mode: empty field, invokes create_block, calls onDone', async () => {
    invokeMock.mockResolvedValueOnce({ blockUuidHex: 'ab', blockName: 'Logins', createdAtMs: 1, lastModifiedMs: 1 });
    const onDone = vi.fn();
    const { getByLabelText, getByRole } = render(BlockNameDialog, {
      props: { mode: { kind: 'create' }, onDone, onCancel: vi.fn() }
    });
    expect((getByLabelText(/block name/i) as HTMLInputElement).value).toBe('');
    await fireEvent.input(getByLabelText(/block name/i), { target: { value: 'Logins' } });
    await fireEvent.click(getByRole('button', { name: /create block/i }));
    await waitFor(() => expect(invokeMock).toHaveBeenCalledWith('create_block', { blockName: 'Logins' }));
    await waitFor(() => expect(onDone).toHaveBeenCalled());
  });

  it('rename mode: pre-fills name, invokes rename_block', async () => {
    invokeMock.mockResolvedValueOnce({ blockUuidHex: 'ab', blockName: 'After', createdAtMs: 1, lastModifiedMs: 2 });
    const onDone = vi.fn();
    const { getByLabelText, getByRole } = render(BlockNameDialog, {
      props: { mode: { kind: 'rename', block }, onDone, onCancel: vi.fn() }
    });
    expect((getByLabelText(/block name/i) as HTMLInputElement).value).toBe('Before');
    await fireEvent.input(getByLabelText(/block name/i), { target: { value: 'After' } });
    await fireEvent.click(getByRole('button', { name: /rename block/i }));
    await waitFor(() => expect(invokeMock).toHaveBeenCalledWith('rename_block', { blockUuidHex: 'ab', newName: 'After' }));
    await waitFor(() => expect(onDone).toHaveBeenCalled());
  });

  it('blank name: no IPC call, shows error, stays open', async () => {
    const onDone = vi.fn();
    const { getByLabelText, getByRole } = render(BlockNameDialog, {
      props: { mode: { kind: 'create' }, onDone, onCancel: vi.fn() }
    });
    await fireEvent.input(getByLabelText(/block name/i), { target: { value: '   ' } });
    await fireEvent.click(getByRole('button', { name: /create block/i }));
    expect(invokeMock).not.toHaveBeenCalled();
    expect(onDone).not.toHaveBeenCalled();
    await waitFor(() => expect(getByRole('alert')).toBeTruthy());
  });
});
