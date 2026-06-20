import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import BlockCard from '../src/components/BlockCard.svelte';

const block = { blockUuidHex: 'ab', blockName: 'Logins', createdAtMs: 1, lastModifiedMs: 1 };

describe('BlockCard rename action', () => {
  it('renders a Rename button when onRename supplied and fires it', async () => {
    const onRename = vi.fn();
    const { getByRole } = render(BlockCard, { props: { block, onClick: vi.fn(), onRename } });
    await fireEvent.click(getByRole('button', { name: /rename block/i }));
    expect(onRename).toHaveBeenCalledWith(block);
  });

  it('omits the Rename button when onRename absent', () => {
    const { queryByRole } = render(BlockCard, { props: { block, onClick: vi.fn() } });
    expect(queryByRole('button', { name: /rename block/i })).toBeNull();
  });
});
