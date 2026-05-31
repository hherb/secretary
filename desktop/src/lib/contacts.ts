// Pure contact-list helpers (D.1.6). No IPC / DOM. IPC wrappers live in ipc.ts.
import type { ContactSummaryDto } from './ipc';

/** Order contacts case-insensitively by displayName. Pure (new array). */
export function sortContacts(dtos: ContactSummaryDto[]): ContactSummaryDto[] {
  return [...dtos].sort((a, b) =>
    a.displayName.localeCompare(b.displayName, undefined, { sensitivity: 'base' })
  );
}
