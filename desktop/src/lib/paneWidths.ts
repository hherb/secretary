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
//
// Their SUM must also equal `app.windows[0].minWidth` in
// `desktop/src-tauri/tauri.conf.json` (currently 760 = 180 + 260 + 320),
// which guarantees the three floors are always simultaneously satisfiable.
// That file is strict JSON, not JSON5 — Tauri's `Config`/`WindowConfig`
// structs derive `#[serde(deny_unknown_fields)]` and this crate does not
// enable the `config-json5` Cargo feature, so neither a `//` comment nor an
// extra key can be added there without breaking `cargo build`. This comment
// is the closest a reader gets to a reference from that value back to these
// constants — if you change SIDEBAR_MIN_PX / LIST_MIN_PX / DETAIL_MIN_PX,
// update tauri.conf.json's minWidth by hand to match.
export const SIDEBAR_MIN_PX = 180;
export const LIST_MIN_PX = 260;
export const DETAIL_MIN_PX = 320;

export const SIDEBAR_DEFAULT_FRACTION = 0.18;
export const LIST_DEFAULT_FRACTION = 0.26;

export const SIDEBAR_KEY = 'secretary.panes.sidebarFraction';
export const LIST_KEY = 'secretary.panes.listFraction';

/** The two left panes may not claim the whole container — the detail pane
    keeps a share, on top of its own pixel floor. Not a per-pane cap: a single
    pane can still be dragged out to nearly this whole budget. */
const MAX_COMBINED_FRACTION = 0.85;

export type PaneKey = 'sidebar' | 'list';

function keyFor(pane: PaneKey): string {
  return pane === 'sidebar' ? SIDEBAR_KEY : LIST_KEY;
}

/** Parse one stored fraction, falling back on anything not a real number
    strictly inside (0, 1). Guards NaN, Infinity, negatives and junk. */
function parseFraction(raw: string | null, fallback: number): number {
  if (raw === null) return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0 || value >= 1) return fallback;
  return value;
}

export function loadFractions(storage: Pick<Storage, 'getItem'>): {
  sidebar: number;
  list: number;
} {
  let sidebar = parseFraction(storage.getItem(SIDEBAR_KEY), SIDEBAR_DEFAULT_FRACTION);
  let list = parseFraction(storage.getItem(LIST_KEY), LIST_DEFAULT_FRACTION);
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

/** Persist one pane's fraction. Never throws — a storage failure (Safari
    private browsing throws on setItem) must not break the app over geometry. */
export function saveFraction(
  storage: Pick<Storage, 'setItem'>,
  pane: PaneKey,
  fraction: number
): void {
  try {
    storage.setItem(keyFor(pane), String(fraction));
  } catch {
    // Geometry is not worth an error path.
  }
}

/**
 * Clamp a dragged pane's width in pixels.
 *
 * Lower bound is the pane's own floor. Upper bound is whatever the container
 * has left once every OTHER pane keeps its floor — derived, so a wider window
 * genuinely allows a wider pane. If the container cannot satisfy everyone
 * (below the enforced window minimum) the floor wins rather than returning a
 * nonsensical width.
 */
export function clampPaneWidthPx(args: {
  requestedPx: number;
  ownMinPx: number;
  containerPx: number;
  siblingsMinPx: number;
}): number {
  const max = args.containerPx - args.siblingsMinPx;
  if (max < args.ownMinPx) return args.ownMinPx;
  return Math.min(Math.max(args.requestedPx, args.ownMinPx), max);
}
