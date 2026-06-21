import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import {
  __setWriteGuardTestSeam,
  ReauthCancelled,
  resetReauthGuard
} from '../src/lib/writeGuard';
const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));
import BlockNameDialog from '../src/components/edit/BlockNameDialog.svelte';

const PASS_THROUGH_SEAM = {
  readSettings: () => ({ enabled: false, windowMs: 0 }),
  now: () => 0,
  prompt: () => Promise.resolve()
};

const block = { blockUuidHex: 'ab', blockName: 'Before', createdAtMs: 1, lastModifiedMs: 1 };

describe('BlockNameDialog', () => {
  beforeEach(() => {
    invokeMock.mockReset();
    __setWriteGuardTestSeam(PASS_THROUGH_SEAM);
  });
  afterEach(() => resetReauthGuard());

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

describe('BlockNameDialog — write-reauth gate (create)', () => {
  beforeEach(() => invokeMock.mockReset());
  afterEach(() => resetReauthGuard());

  it('cancel: guard rejects ReauthCancelled → create_block NOT called, onDone not called', async () => {
    __setWriteGuardTestSeam({
      readSettings: () => ({ enabled: true, windowMs: 0 }),
      now: () => 0,
      prompt: () => Promise.reject(ReauthCancelled)
    });

    const onDone = vi.fn();
    const { getByLabelText, getByRole } = render(BlockNameDialog, {
      props: { mode: { kind: 'create' }, onDone, onCancel: vi.fn() }
    });
    await fireEvent.input(getByLabelText(/block name/i), { target: { value: 'Logins' } });
    await fireEvent.click(getByRole('button', { name: /create block/i }));

    await new Promise((r) => setTimeout(r, 50));
    expect(invokeMock).not.toHaveBeenCalled();
    expect(onDone).not.toHaveBeenCalled();
  });

  it('happy path: guard resolves → create_block called once, onDone called', async () => {
    __setWriteGuardTestSeam({
      readSettings: () => ({ enabled: true, windowMs: 0 }),
      now: () => 0,
      prompt: () => Promise.resolve()
    });
    invokeMock.mockResolvedValueOnce({ blockUuidHex: 'ab', blockName: 'Logins', createdAtMs: 1, lastModifiedMs: 1 });

    const onDone = vi.fn();
    const { getByLabelText, getByRole } = render(BlockNameDialog, {
      props: { mode: { kind: 'create' }, onDone, onCancel: vi.fn() }
    });
    await fireEvent.input(getByLabelText(/block name/i), { target: { value: 'Logins' } });
    await fireEvent.click(getByRole('button', { name: /create block/i }));

    await waitFor(() => expect(invokeMock).toHaveBeenCalledWith('create_block', { blockName: 'Logins' }));
    await waitFor(() => expect(onDone).toHaveBeenCalled());
  });
});
