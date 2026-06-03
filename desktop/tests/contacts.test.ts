import { describe, it, expect } from 'vitest';
import { sortContacts } from '../src/lib/contacts';
import type { ContactSummaryDto } from '../src/lib/ipc';

const c = (displayName: string): ContactSummaryDto => ({ contactUuidHex: displayName, displayName, sharedBlockCount: 0 });

describe('sortContacts', () => {
  it('orders case-insensitively by displayName, returns a new array', () => {
    const input = [c('bob'), c('Alice'), c('charlie')];
    const out = sortContacts(input);
    expect(out.map((x) => x.displayName)).toEqual(['Alice', 'bob', 'charlie']);
    expect(out).not.toBe(input);
  });
});
