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
  LIST_KEY,
  SPLITTER_PX,
  SPLITTER_COUNT,
  MIN_SHELL_WIDTH_PX,
  paneStorage,
  resetStorageWarningForTest
} from '../src/lib/paneWidths';
import tauriConf from '../src-tauri/tauri.conf.json';

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
      reservedPx: LIST_MIN_PX + DETAIL_MIN_PX
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
      reservedPx: LIST_MIN_PX + DETAIL_MIN_PX
    });
    expect(px).toBe(1400 - (LIST_MIN_PX + DETAIL_MIN_PX));
  });

  it('scales the bound with the container — a wider window allows more', () => {
    const px = clampPaneWidthPx({
      requestedPx: 9999,
      ownMinPx: SIDEBAR_MIN_PX,
      containerPx: 2560,
      reservedPx: LIST_MIN_PX + DETAIL_MIN_PX
    });
    expect(px).toBe(2560 - 580);
    expect(px).toBeGreaterThan(1900); // genuinely generous, not a token cap
  });

  it('passes an in-range request through untouched', () => {
    const px = clampPaneWidthPx({
      requestedPx: 300,
      ownMinPx: SIDEBAR_MIN_PX,
      containerPx: 1400,
      reservedPx: LIST_MIN_PX + DETAIL_MIN_PX
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
      reservedPx: LIST_MIN_PX + DETAIL_MIN_PX
    });
    expect(px).toBe(SIDEBAR_MIN_PX);
  });
});

describe('the floors stay in sync with tauri.conf.json (#526 review)', () => {
  // JSON cannot import a TS constant, and tauri.conf.json is strict JSON —
  // not JSON5 — so it can't even hold a `//` comment pointing back here
  // (Tauri's Config/WindowConfig structs derive
  // #[serde(deny_unknown_fields)], and this crate doesn't enable the
  // config-json5 Cargo feature; either would break `cargo build`). This
  // test is the mechanical substitute: it fails the moment a floor changes
  // here without minWidth changing to match, instead of the two silently
  // drifting apart.
  it('MIN_SHELL_WIDTH_PX equals app.windows[0].minWidth', () => {
    expect(MIN_SHELL_WIDTH_PX).toBe(tauriConf.app.windows[0].minWidth);
  });

  it('counts the splitter columns, not just the three pane floors', () => {
    // The bug this replaced: the sum of the three floors alone was asserted
    // against minWidth, but the grid has FIVE tracks. At the enforced minimum
    // the layout wanted 10px more than the window could ever be, so it
    // overflowed into `overflow: hidden` and clipped the detail pane below its
    // own floor — silently, with no scrollbar. Pin the splitter term so the
    // arithmetic cannot regress to the three-floor version.
    expect(MIN_SHELL_WIDTH_PX).toBe(
      SIDEBAR_MIN_PX + LIST_MIN_PX + DETAIL_MIN_PX + SPLITTER_COUNT * SPLITTER_PX
    );
    expect(MIN_SHELL_WIDTH_PX).toBeGreaterThan(SIDEBAR_MIN_PX + LIST_MIN_PX + DETAIL_MIN_PX);
  });

  it('leaves every pane at or above its floor at the minimum window width', () => {
    // The guarantee the comment actually claims, stated as arithmetic: at
    // exactly minWidth, the three floors plus the splitters fit.
    const container = tauriConf.app.windows[0].minWidth;
    const used = SIDEBAR_MIN_PX + LIST_MIN_PX + DETAIL_MIN_PX + SPLITTER_COUNT * SPLITTER_PX;
    expect(used).toBeLessThanOrEqual(container);
  });
});

describe('clampPaneWidthPx — reservedPx is what the rest of the layout occupies', () => {
  // Regression for the drag that stopped tracking the cursor (#526 review).
  // The old signature reserved every sibling's FLOOR; CSS grid does not shrink
  // a sibling below what its own fraction asks for, so the clamp handed back a
  // width the grid would not render and `currentPx` then read that phantom
  // value out of state on the next drag.
  it('reserves the sibling’s CURRENT width, so the result is renderable', () => {
    const container = 1200;
    const listCurrent = 312; // the 26% default of 1200
    const px = clampPaneWidthPx({
      requestedPx: 9999,
      ownMinPx: SIDEBAR_MIN_PX,
      containerPx: container,
      reservedPx: SPLITTER_COUNT * SPLITTER_PX + listCurrent + DETAIL_MIN_PX
    });
    expect(px).toBe(container - 10 - listCurrent - DETAIL_MIN_PX);
    // The width CSS grid actually renders for these inputs.
    expect(px).toBe(558);
  });

  it('never lets the panes plus splitters exceed the container', () => {
    const container = 1200;
    for (const listCurrent of [LIST_MIN_PX, 312, 500]) {
      const reserved = SPLITTER_COUNT * SPLITTER_PX + listCurrent + DETAIL_MIN_PX;
      const px = clampPaneWidthPx({
        requestedPx: 9999,
        ownMinPx: SIDEBAR_MIN_PX,
        containerPx: container,
        reservedPx: reserved
      });
      expect(px + reserved).toBeLessThanOrEqual(container);
    }
  });
});

describe('storage that throws is survivable (#526 review)', () => {
  it('loadFractions returns defaults when getItem throws', () => {
    // A blocked-storage policy throws on read, not only on write. This ran at
    // PaneShell init, so an unguarded throw took down the whole vault screen.
    const hostile = {
      getItem: () => {
        throw new DOMException('SecurityError');
      }
    };
    expect(() => loadFractions(hostile)).not.toThrow();
    expect(loadFractions(hostile)).toEqual({
      sidebar: SIDEBAR_DEFAULT_FRACTION,
      list: LIST_DEFAULT_FRACTION
    });
  });

  it('warns once, not once per pointermove, when the write fails', () => {
    resetStorageWarningForTest();
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const setItem = vi.fn(() => {
      throw new DOMException('QuotaExceededError');
    });
    for (let i = 0; i < 50; i++) saveFraction({ setItem }, 'sidebar', 0.25);
    expect(setItem).toHaveBeenCalledTimes(50);
    expect(warn).toHaveBeenCalledTimes(1);
    warn.mockRestore();
  });

  it('paneStorage never throws and always returns a usable pair', () => {
    const s = paneStorage();
    expect(() => s.getItem(SIDEBAR_KEY)).not.toThrow();
    expect(() => s.setItem(SIDEBAR_KEY, '0.2')).not.toThrow();
  });
});

describe('clampPaneWidthPx — non-finite input degrades to the floor (#530)', () => {
  // The finiteness guarantee used to live in the single caller, not in this
  // function, so a second caller would not have inherited it. NaN reaches the
  // DOM as `width: NaN%`, which silently collapses the pane.
  it.each([
    ['NaN request', NaN],
    ['Infinity request', Infinity],
    ['-Infinity request', -Infinity]
  ])('returns the floor for a %s', (_label, requestedPx) => {
    expect(
      clampPaneWidthPx({
        requestedPx,
        ownMinPx: SIDEBAR_MIN_PX,
        containerPx: 1400,
        reservedPx: LIST_MIN_PX + DETAIL_MIN_PX
      })
    ).toBe(SIDEBAR_MIN_PX);
  });

  it('returns the floor for a non-finite container', () => {
    expect(
      clampPaneWidthPx({
        requestedPx: 400,
        ownMinPx: SIDEBAR_MIN_PX,
        containerPx: NaN,
        reservedPx: LIST_MIN_PX + DETAIL_MIN_PX
      })
    ).toBe(SIDEBAR_MIN_PX);
  });
});
