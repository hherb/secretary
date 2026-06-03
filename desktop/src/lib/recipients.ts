// Pure per-block recipient helpers (D.1.8). No IPC / DOM — the IPC wrapper
// lives in ipc.ts. Mirrors the lib/contacts.ts pure-helper discipline.
import type { RecipientDto } from './ipc';

/** Number of leading hex chars shown for an unresolved recipient uuid. */
const UNKNOWN_UUID_PREFIX_LEN = 8;

/** Display rank: owner first, contacts middle, unknowns last. */
function rank(r: RecipientDto): number {
  return r.kind === 'owner' ? 0 : r.kind === 'contact' ? 1 : 2;
}

/**
 * Order recipients for display: owner first → contacts sorted case-insensitively
 * by displayName → unknowns last. Pure (returns a new array).
 */
export function sortRecipients(rs: RecipientDto[]): RecipientDto[] {
  return [...rs].sort((a, b) => {
    const dr = rank(a) - rank(b);
    if (dr !== 0) return dr;
    if (a.kind === 'contact' && b.kind === 'contact') {
      return (a.displayName ?? '').localeCompare(b.displayName ?? '', undefined, {
        sensitivity: 'base'
      });
    }
    return 0;
  });
}

/**
 * Human label for one recipient. Owner → "You"; contact → its display name;
 * unknown → "Unknown contact (<8 hex>…)", surfacing the residual-keyholder uuid
 * so a deleted contact's lingering access stays visible (delete ≠ revoke).
 */
export function recipientLabel(r: RecipientDto): string {
  if (r.kind === 'owner') return 'You';
  if (r.kind === 'contact') return r.displayName ?? 'Unknown contact';
  return `Unknown contact (${r.uuidHex.slice(0, UNKNOWN_UUID_PREFIX_LEN)}…)`;
}
