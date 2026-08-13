// #526 — pane geometry.
//
// Widths are stored as FRACTIONS of the container, not pixels, so CSS can
// scale the panes on window resize with no JS involved and so restored
// geometry stays meaningful across differently-sized displays.
//
// Minimums are absolute pixels because legibility is an absolute property:
// a 180px sidebar is equally cramped on a 1440p and a 6K panel. There is
// deliberately NO maximum token — a drag's upper bound is derived from
// whatever the other panes need for their own floors.
//
// STORAGE POLICY: `secretary.panes.*` holds UI geometry only. Never vault
// data, never anything derived from a decrypted record. This is the first and
// so far only localStorage use in the frontend; keep it that way.

// These three floors are consumed in TWO places: the drag/keyboard clamp
// below, and PaneShell.svelte's `grid-template-columns` `minmax()` floors —
// set as CSS custom properties (`--pane-*-min`) from these exact constants,
// so CSS never hand-copies the numbers (#526 review).
export const SIDEBAR_MIN_PX = 180;
export const LIST_MIN_PX = 260;
export const DETAIL_MIN_PX = 320;

/// Width of one splitter column, also plumbed to CSS as `--pane-splitter-w`
/// so the grid and the arithmetic below cannot drift.
export const SPLITTER_PX = 5;

/** Splitter columns in the full three-pane grid (sidebar│list│detail). The
    spanned Trash/Contacts layout has one. */
export const SPLITTER_COUNT = 2;

// The narrowest the shell can be laid out in: three floors PLUS the splitter
// columns between them. This must equal `app.windows[0].minWidth` in
// `desktop/src-tauri/tauri.conf.json`, and `paneWidths.test.ts` asserts it.
//
// The splitter term is not decoration — omitting it was a real 10px defect
// (#526 review). The grid has FIVE tracks, not three, and under
// `box-sizing: border-box` each splitter really does occupy its 5px. With
// minWidth at 760 the layout needed 770, so at the enforced minimum window
// the grid overflowed and `.pane-shell { overflow: hidden }` clipped the
// detail pane below its own floor, silently and with no scrollbar.
//
// tauri.conf.json is strict JSON, not JSON5 — Tauri's `Config`/`WindowConfig`
// structs derive `#[serde(deny_unknown_fields)]` and this crate does not
// enable the `config-json5` Cargo feature, so neither a `//` comment nor an
// extra key can be added there. The test is therefore the only mechanism that
// can tie the two together; this comment is the reader-facing half.
export const MIN_SHELL_WIDTH_PX =
  SIDEBAR_MIN_PX + LIST_MIN_PX + DETAIL_MIN_PX + SPLITTER_COUNT * SPLITTER_PX;

export const SIDEBAR_DEFAULT_FRACTION = 0.18;
export const LIST_DEFAULT_FRACTION = 0.26;

export const SIDEBAR_KEY = 'secretary.panes.sidebarFraction';
export const LIST_KEY = 'secretary.panes.listFraction';

/** Ceiling on the two left panes' combined share, applied to **RESTORED**
    geometry only — `loadFractions` is its only reader. A live drag is bounded
    by `clampPaneWidthPx` (pixels) instead, so this is a startup sanity rule
    for whatever was in storage, not an invariant the layout maintains. Said
    the other way round: do not read this as a cap the drag respects (#526
    review — it previously claimed to be one). */
const MAX_COMBINED_FRACTION = 0.85;

export type PaneKey = 'sidebar' | 'list';

function keyFor(pane: PaneKey): string {
  return pane === 'sidebar' ? SIDEBAR_KEY : LIST_KEY;
}

/** Reads and writes that cannot throw. A storage object may be absent
    (non-browser host) or hostile (Safari private browsing throws on
    `setItem`; a blocked-storage policy throws on the `localStorage` property
    access itself). Geometry must never be able to take the app down. */
const NULL_STORAGE: Pick<Storage, 'getItem' | 'setItem'> = {
  getItem: () => null,
  setItem: () => {}
};

/**
 * The platform's `localStorage`, or a no-op stand-in when it is unavailable.
 *
 * The property ACCESS is what throws under a blocked-storage policy, before
 * any method is called — so `PaneShell` must not touch the global directly.
 * It used to, unguarded, at component init: a `SecurityError` there took down
 * the whole unlocked vault screen over a pane-width preference, while the
 * matching WRITE was already wrapped in `try`/`catch` (#526 review).
 */
export function paneStorage(): Pick<Storage, 'getItem' | 'setItem'> {
  try {
    return globalThis.localStorage ?? NULL_STORAGE;
  } catch {
    return NULL_STORAGE;
  }
}

/** Parse one stored fraction, falling back on anything not a real number
    strictly inside (0, 1). Guards NaN, Infinity, negatives and junk. */
function parseFraction(raw: string | null, fallback: number): number {
  if (raw === null) return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0 || value >= 1) return fallback;
  return value;
}

/** Read one key, treating a throwing storage as an absent value. */
function readRaw(storage: Pick<Storage, 'getItem'>, key: string): string | null {
  try {
    return storage.getItem(key);
  } catch {
    return null;
  }
}

export function loadFractions(storage: Pick<Storage, 'getItem'>): {
  sidebar: number;
  list: number;
} {
  let sidebar = parseFraction(readRaw(storage, SIDEBAR_KEY), SIDEBAR_DEFAULT_FRACTION);
  let list = parseFraction(readRaw(storage, LIST_KEY), LIST_DEFAULT_FRACTION);
  const combined = sidebar + list;
  if (combined > MAX_COMBINED_FRACTION) {
    // Scale both down proportionally rather than truncating one, so restoring
    // a wide-monitor layout on a narrow screen keeps its shape.
    const scale = MAX_COMBINED_FRACTION / combined;
    sidebar *= scale;
    list *= scale;
  }
  return { sidebar, list };
}

/** One-shot latch: `saveFraction` runs on every pointermove of a drag, so an
    unavailable storage would otherwise emit hundreds of identical warnings. */
let storageWarned = false;

/** Reset the once-only storage warning. Test-only — the latch is module
    state, so without this the second test to exercise the failure path would
    observe no warning and pass vacuously. */
export function resetStorageWarningForTest(): void {
  storageWarned = false;
}

/** Persist one pane's fraction. Never throws — a storage failure (Safari
    private browsing throws on setItem) must not break the app over geometry.
    It does warn ONCE: geometry is not worth an error path, but it is worth
    the user being able to find out why their layout resets every launch
    instead of the failure being wholly invisible (#526 review). */
export function saveFraction(
  storage: Pick<Storage, 'setItem'>,
  pane: PaneKey,
  fraction: number
): void {
  try {
    storage.setItem(keyFor(pane), String(fraction));
  } catch {
    if (!storageWarned) {
      storageWarned = true;
      console.warn('Pane geometry will not persist: browser storage is unavailable.');
    }
  }
}

/**
 * Clamp a dragged pane's width in pixels.
 *
 * Lower bound is the pane's own floor. Upper bound is whatever the container
 * has left once `reservedPx` is set aside — derived, so a wider window
 * genuinely allows a wider pane, with no arbitrary maximum. If the container
 * cannot satisfy everyone (below the enforced window minimum) the floor wins
 * rather than returning a nonsensical width.
 *
 * `reservedPx` is what the REST of the layout will actually occupy: the
 * splitter columns, plus each other pane's effective width. It used to be
 * `siblingsMinPx` — every sibling at its FLOOR — which overstated the
 * available room twice over and made the splitter stop tracking the cursor
 * (#526 review). CSS grid does not shrink a sibling below the width its own
 * fraction asks for just because this clamp assumed it would, so on a 1200px
 * container the sidebar could be told it had 620px while the grid rendered
 * 558px; `currentPx` then read the 620 out of state and the NEXT drag jumped
 * 62px away from the pointer. Reserving the sibling's real width makes the
 * clamp agree with what the grid renders, so the splitter lands under the
 * cursor and stays there.
 */
export function clampPaneWidthPx(args: {
  requestedPx: number;
  ownMinPx: number;
  containerPx: number;
  reservedPx: number;
}): number {
  // #530 — the finiteness guarantee used to live in the single caller
  // (PaneShell guards `width <= 0`, and all four paths in were traced as
  // finite). Nothing carried it INTO the function, so a second caller would
  // not have inherited it and `NaN` in meant `NaN` out — which reaches the
  // DOM as `width: NaN%` and silently collapses the pane. The floor is the
  // safe answer for any input that is not a usable number.
  if (!Number.isFinite(args.requestedPx) || !Number.isFinite(args.containerPx)) {
    return args.ownMinPx;
  }
  const max = args.containerPx - args.reservedPx;
  if (!Number.isFinite(max) || max < args.ownMinPx) return args.ownMinPx;
  return Math.min(Math.max(args.requestedPx, args.ownMinPx), max);
}
