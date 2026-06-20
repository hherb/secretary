import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));
import MoveTargetPicker from '../src/components/edit/MoveTargetPicker.svelte';

const blocks = [
  { blockUuidHex: 'src', blockName: 'Source', createdAtMs: 1, lastModifiedMs: 1 },
  { blockUuidHex: 'dst', blockName: 'Target', createdAtMs: 1, lastModifiedMs: 1 }
];

describe('MoveTargetPicker', () => {
  beforeEach(() => invokeMock.mockReset());

  it('lists candidate blocks excluding the source and fires onSelect', async () => {
    invokeMock.mockResolvedValueOnce(blocks); // list_blocks
    const onSelect = vi.fn();
    const { getByRole, queryByRole } = render(MoveTargetPicker, {
      props: { sourceBlockUuidHex: 'src', onSelect, onCancel: vi.fn() }
    });
    await waitFor(() => expect(getByRole('button', { name: /Target/ })).toBeTruthy());
    expect(queryByRole('button', { name: /^Source$/ })).toBeNull();
    await fireEvent.click(getByRole('button', { name: /Target/ }));
    expect(onSelect).toHaveBeenCalledWith(blocks[1]);
  });
});
