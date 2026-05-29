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
