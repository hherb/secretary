import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));
import NewBlock from '../src/components/edit/NewBlock.svelte';

describe('NewBlock', () => {
  beforeEach(() => invokeMock.mockReset());
  it('creates a block and calls onCreated', async () => {
    invokeMock.mockResolvedValueOnce({ blockUuidHex: 'ab', blockName: 'Logins', createdAtMs: 1, lastModifiedMs: 1 });
    const onCreated = vi.fn();
    const { getByLabelText, getByRole } = render(NewBlock, { props: { onCreated, onCancel: vi.fn() } });
    await fireEvent.input(getByLabelText(/block name/i), { target: { value: 'Logins' } });
    await fireEvent.click(getByRole('button', { name: /create block/i }));
    await waitFor(() => expect(invokeMock).toHaveBeenCalledWith('create_block', { blockName: 'Logins' }));
    await waitFor(() => expect(onCreated).toHaveBeenCalled());
  });
});
