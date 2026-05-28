// Tests for BlockCard.svelte — the leaf component that renders a single
// vault block summary. Clicks are intentionally stubbed for D.1.1 (the
// block-detail view lands in D.1.2), so the card renders as a disabled
// button: the user gets accessible feedback that the element exists but
// isn't interactive yet, rather than a focusable element that does nothing.

import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/svelte';
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
    const { getByText } = render(BlockCard, { props: { block: BLOCK } });
    expect(getByText('Banking')).toBeTruthy();
  });

  it('renders the last-modified date with the year', () => {
    const { getByText } = render(BlockCard, { props: { block: BLOCK } });
    // Format is locale-dependent ("Jun 15, 2024" vs "15 Jun 2024" etc.).
    // Year is robust; the substring match doesn't pin format.
    expect(getByText(/2024/)).toBeTruthy();
  });

  it('rendered button has type="button" (no implicit form submit)', () => {
    const { getByRole } = render(BlockCard, { props: { block: BLOCK } });
    const button = getByRole('button', { name: /banking/i });
    expect(button.getAttribute('type')).toBe('button');
  });

  it('rendered button is disabled (clicks land in D.1.2)', () => {
    // Explicitly disabled rather than CSS `cursor: not-allowed` only:
    // keyboard-focus users get the correct affordance instead of a
    // focusable element that does nothing.
    const { getByRole } = render(BlockCard, { props: { block: BLOCK } });
    const button = getByRole('button', { name: /banking/i });
    expect((button as HTMLButtonElement).disabled).toBe(true);
  });

  it('button has an aria-label that includes the block name', () => {
    // Screen readers read the aria-label; the visible content is
    // "Banking" + "modified ...", and the aria-label needs to include
    // the name so users picking from a list of cards can disambiguate.
    const { getByRole } = render(BlockCard, { props: { block: BLOCK } });
    const button = getByRole('button', { name: /banking/i });
    const ariaLabel = button.getAttribute('aria-label') ?? '';
    expect(ariaLabel).toMatch(/banking/i);
  });

  it('button has a title attribute hinting at the deferred functionality', () => {
    // The title surfaces on hover; the copy explains why a visible card
    // is non-interactive so the user doesn't think the app is broken.
    const { getByRole } = render(BlockCard, { props: { block: BLOCK } });
    const button = getByRole('button', { name: /banking/i });
    const title = button.getAttribute('title') ?? '';
    expect(title.length).toBeGreaterThan(0);
  });
});

describe('BlockCard.svelte — empty / edge-case block names', () => {
  it('still renders when blockName is empty', () => {
    // Defensive — backend doesn't promise non-empty names today.
    // We accept whatever the manifest contains and don't crash.
    const empty: BlockSummaryDto = { ...BLOCK, blockName: '' };
    const { container } = render(BlockCard, { props: { block: empty } });
    expect(container.querySelector('button')).not.toBeNull();
  });

  it('handles a block created and modified at the same instant', () => {
    const sameTime: BlockSummaryDto = {
      ...BLOCK,
      createdAtMs: MS_2024_06_15_NOON_UTC,
      lastModifiedMs: MS_2024_06_15_NOON_UTC
    };
    const { getByText } = render(BlockCard, { props: { block: sameTime } });
    expect(getByText(/2024/)).toBeTruthy();
  });
});
