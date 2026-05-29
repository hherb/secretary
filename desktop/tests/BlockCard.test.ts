// Tests for BlockCard.svelte — the leaf component that renders a single
// vault block summary. BlockCard is clickable from D.1.2 onward; callers
// supply an `onClick` callback that receives the full BlockSummaryDto.

import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import BlockCard from '../src/components/BlockCard.svelte';
import type { BlockSummaryDto } from '../src/lib/ipc';

// Fixed-noon-UTC timestamp survives ±14h timezone shifts as the same
// calendar date in every populated timezone — keeps the date assertion
// portable across CI servers.
const MS_2024_06_15_NOON_UTC = Date.UTC(2024, 5, 15, 12, 0, 0); // 1718452800000
const MS_2024_06_10_NOON_UTC = Date.UTC(2024, 5, 10, 12, 0, 0);

const BLOCK: BlockSummaryDto = {
  blockUuidHex: 'a1b2c3d4e5f6',
  blockName: 'Banking',
  createdAtMs: MS_2024_06_10_NOON_UTC,
  lastModifiedMs: MS_2024_06_15_NOON_UTC
};

describe('BlockCard.svelte — rendering', () => {
  it('renders the block name', () => {
    const { getByText } = render(BlockCard, { props: { block: BLOCK, onClick: () => {} } });
    expect(getByText('Banking')).toBeTruthy();
  });

  it('renders the last-modified date with the year', () => {
    const { getByText } = render(BlockCard, { props: { block: BLOCK, onClick: () => {} } });
    // Format is locale-dependent ("Jun 15, 2024" vs "15 Jun 2024" etc.).
    // Year is robust; the substring match doesn't pin format.
    expect(getByText(/2024/)).toBeTruthy();
  });

  it('rendered button has type="button" (no implicit form submit)', () => {
    const { getByRole } = render(BlockCard, { props: { block: BLOCK, onClick: () => {} } });
    const button = getByRole('button', { name: /banking/i });
    expect(button.getAttribute('type')).toBe('button');
  });

  it('calls onClick with the block when clicked', async () => {
    const onClick = vi.fn();
    const { getByRole } = render(BlockCard, { props: { block: BLOCK, onClick } });
    await fireEvent.click(getByRole('button'));
    expect(onClick).toHaveBeenCalledWith(BLOCK);
  });

  it('button has an aria-label that includes the block name', () => {
    // Screen readers read the aria-label; the visible content is
    // "Banking" + "modified ...", and the aria-label needs to include
    // the name so users picking from a list of cards can disambiguate.
    const { getByRole } = render(BlockCard, { props: { block: BLOCK, onClick: () => {} } });
    const button = getByRole('button', { name: /banking/i });
    const ariaLabel = button.getAttribute('aria-label') ?? '';
    expect(ariaLabel).toMatch(/banking/i);
  });
});

describe('BlockCard.svelte — empty / edge-case block names', () => {
  it('still renders when blockName is empty', () => {
    // Defensive — backend doesn't promise non-empty names today.
    // We accept whatever the manifest contains and don't crash.
    const empty: BlockSummaryDto = { ...BLOCK, blockName: '' };
    const { container } = render(BlockCard, { props: { block: empty, onClick: () => {} } });
    expect(container.querySelector('button')).not.toBeNull();
  });

  it('handles a block created and modified at the same instant', () => {
    const sameTime: BlockSummaryDto = {
      ...BLOCK,
      createdAtMs: MS_2024_06_15_NOON_UTC,
      lastModifiedMs: MS_2024_06_15_NOON_UTC
    };
    const { getByText } = render(BlockCard, { props: { block: sameTime, onClick: () => {} } });
    expect(getByText(/2024/)).toBeTruthy();
  });
});
