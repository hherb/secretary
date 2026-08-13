// Tests for pane width persistence and clamping (#526).
//
// Storage is injected rather than read from a global, so these are pure-
// function tests with no jsdom localStorage dependency.

import { describe, it, expect, vi } from 'vitest';
import {
  loadFractions,
  saveFraction,
  clampPaneWidthPx,
  SIDEBAR_MIN_PX,
  LIST_MIN_PX,
  DETAIL_MIN_PX,
  SIDEBAR_DEFAULT_FRACTION,
  LIST_DEFAULT_FRACTION,
  SIDEBAR_KEY,
  LIST_KEY
} from '../src/lib/paneWidths';

function storageOf(entries: Record<string, string>) {
  return { getItem: (k: string) => entries[k] ?? null };
}

describe('loadFractions — defaults and sanity', () => {
  it('returns defaults when nothing is stored', () => {
    const out = loadFractions(storageOf({}));
    expect(out).toEqual({ sidebar: SIDEBAR_DEFAULT_FRACTION, list: LIST_DEFAULT_FRACTION });
  });

  it('round-trips a stored pair', () => {
    const out = loadFractions(storageOf({ [SIDEBAR_KEY]: '0.22', [LIST_KEY]: '0.3' }));
    expect(out).toEqual({ sidebar: 0.22, list: 0.3 });
  });

  it('falls back per-pane when only one is stored', () => {
    const out = loadFractions(storageOf({ [SIDEBAR_KEY]: '0.22' }));
    expect(out).toEqual({ sidebar: 0.22, list: LIST_DEFAULT_FRACTION });
  });

  it.each([
    ['not a number', 'banana'],
    ['empty', ''],
    ['NaN literal', 'NaN'],
    ['negative', '-0.4'],
    ['zero', '0'],
    ['over one', '1.4'],
    ['Infinity', 'Infinity'],
    ['injected object', '{"sidebar":0.9}']
  ])('falls back to the default on a %s value', (_label, raw) => {
    const out = loadFractions(storageOf({ [SIDEBAR_KEY]: raw }));
    expect(out.sidebar).toBe(SIDEBAR_DEFAULT_FRACTION);
  });

  it('scales an over-committed pair down proportionally rather than overflowing', () => {
    // Restoring geometry saved on a much wider monitor must not sum past the
    // container: the detail pane has to keep a share.
    const out = loadFractions(storageOf({ [SIDEBAR_KEY]: '0.6', [LIST_KEY]: '0.5' }));
    expect(out.sidebar + out.list).toBeLessThanOrEqual(0.85 + 1e-9);
    // Proportions are preserved (0.6 : 0.5).
    expect(out.sidebar / out.list).toBeCloseTo(1.2, 5);
  });
});

describe('saveFraction', () => {
  it('writes the namespaced key', () => {
    const setItem = vi.fn();
    saveFraction({ setItem }, 'sidebar', 0.25);
    expect(setItem).toHaveBeenCalledWith(SIDEBAR_KEY, '0.25');
  });

  it('writes the list key for the list pane', () => {
    const setItem = vi.fn();
    saveFraction({ setItem }, 'list', 0.31);
    expect(setItem).toHaveBeenCalledWith(LIST_KEY, '0.31');
  });

  it('never throws when storage rejects the write', () => {
    // Safari private browsing throws on setItem when the quota is zero. A
    // failed geometry save must not break the app.
    const setItem = vi.fn(() => {
      throw new DOMException('QuotaExceededError');
    });
    expect(() => saveFraction({ setItem }, 'sidebar', 0.25)).not.toThrow();
  });
});

describe('clampPaneWidthPx — lower bound is the pane floor', () => {
  it('raises a too-small request to the floor', () => {
    const px = clampPaneWidthPx({
      requestedPx: 40,
      ownMinPx: SIDEBAR_MIN_PX,
      containerPx: 1400,
      siblingsMinPx: LIST_MIN_PX + DETAIL_MIN_PX
    });
    expect(px).toBe(SIDEBAR_MIN_PX);
  });
});

describe('clampPaneWidthPx — upper bound is derived, not an arbitrary cap', () => {
  it('lets a pane grow until the OTHER panes hit their floors', () => {
    // 1400 container, siblings need 260 + 320 = 580 → sidebar may reach 820.
    const px = clampPaneWidthPx({
      requestedPx: 9999,
      ownMinPx: SIDEBAR_MIN_PX,
      containerPx: 1400,
      siblingsMinPx: LIST_MIN_PX + DETAIL_MIN_PX
    });
    expect(px).toBe(1400 - (LIST_MIN_PX + DETAIL_MIN_PX));
  });

  it('scales the bound with the container — a wider window allows more', () => {
    const px = clampPaneWidthPx({
      requestedPx: 9999,
      ownMinPx: SIDEBAR_MIN_PX,
      containerPx: 2560,
      siblingsMinPx: LIST_MIN_PX + DETAIL_MIN_PX
    });
    expect(px).toBe(2560 - 580);
    expect(px).toBeGreaterThan(1900); // genuinely generous, not a token cap
  });

  it('passes an in-range request through untouched', () => {
    const px = clampPaneWidthPx({
      requestedPx: 300,
      ownMinPx: SIDEBAR_MIN_PX,
      containerPx: 1400,
      siblingsMinPx: LIST_MIN_PX + DETAIL_MIN_PX
    });
    expect(px).toBe(300);
  });

  it('floor wins when the container is too small to satisfy everyone', () => {
    // Below the enforced window minimum — should degrade to the floor, not
    // return a negative width.
    const px = clampPaneWidthPx({
      requestedPx: 400,
      ownMinPx: SIDEBAR_MIN_PX,
      containerPx: 500,
      siblingsMinPx: LIST_MIN_PX + DETAIL_MIN_PX
    });
    expect(px).toBe(SIDEBAR_MIN_PX);
  });
});
