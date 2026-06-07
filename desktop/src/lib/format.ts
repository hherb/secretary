// Pure formatting helpers shared across browse components. No side effects.

/** Locale-aware short date (year + abbreviated month + day). Uses the
 *  browser-bundled Intl.DateTimeFormat — no external dep. Format varies by
 *  locale ("Jun 15, 2024" vs "15 Jun 2024"); tests pin year-substring
 *  presence rather than exact format. */
export function formatShortDate(ms: number): string {
  return new Intl.DateTimeFormat(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  }).format(new Date(ms));
}

const MS_PER_SECOND = 1_000;
const MS_PER_MINUTE = 60 * MS_PER_SECOND;
const MS_PER_HOUR = 60 * MS_PER_MINUTE;
const MS_PER_DAY = 24 * MS_PER_HOUR;
/** Days 1–RELATIVE_DAYS_CUTOFF show "Nd ago"; strictly more than this many
 *  days falls back to an absolute date. */
const RELATIVE_DAYS_CUTOFF = 7;

/** Pure relative-time label: "just now" / "Nm ago" / "Nh ago" / "Nd ago",
 *  falling back to {@link formatShortDate} beyond {@link RELATIVE_DAYS_CUTOFF}
 *  days. A `pastMs` at or after `nowMs` (clock skew) reads as "just now". */
export function formatRelativeTime(pastMs: number, nowMs: number): string {
  const delta = nowMs - pastMs;
  if (delta < MS_PER_MINUTE) return 'just now';
  if (delta < MS_PER_HOUR) return `${Math.floor(delta / MS_PER_MINUTE)}m ago`;
  if (delta < MS_PER_DAY) return `${Math.floor(delta / MS_PER_HOUR)}h ago`;
  const days = Math.floor(delta / MS_PER_DAY);
  if (days <= RELATIVE_DAYS_CUTOFF) return `${days}d ago`;
  return formatShortDate(pastMs);
}
