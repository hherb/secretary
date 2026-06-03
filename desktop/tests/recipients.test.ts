// D.1.8 — pure recipient helpers: display ordering + label resolution.
import { describe, it, expect } from 'vitest';
import { sortRecipients, recipientLabel } from '../src/lib/recipients';
import type { RecipientDto } from '../src/lib/ipc';

const owner: RecipientDto = { uuidHex: '00', kind: 'owner', displayName: null };
const alice: RecipientDto = { uuidHex: 'a1', kind: 'contact', displayName: 'Alice' };
const bob: RecipientDto = { uuidHex: 'b2', kind: 'contact', displayName: 'bob' };
const unknown: RecipientDto = {
  uuidHex: 'a1b2c3d4e5f60718',
  kind: 'unknown',
  displayName: null
};

describe('sortRecipients', () => {
  it('orders owner first, then contacts alpha (case-insensitive), then unknowns', () => {
    const out = sortRecipients([unknown, bob, alice, owner]);
    expect(out.map((r) => r.kind)).toEqual(['owner', 'contact', 'contact', 'unknown']);
    expect(out[1].displayName).toBe('Alice');
    expect(out[2].displayName).toBe('bob');
  });

  it('is pure (does not mutate the input array)', () => {
    const input = [bob, alice];
    sortRecipients(input);
    expect(input[0]).toBe(bob);
  });
});

describe('recipientLabel', () => {
  it('labels the owner "You"', () => {
    expect(recipientLabel(owner)).toBe('You');
  });

  it('labels a contact by its display name', () => {
    expect(recipientLabel(alice)).toBe('Alice');
  });

  it('labels an unknown with an 8-hex uuid prefix', () => {
    expect(recipientLabel(unknown)).toBe('Unknown contact (a1b2c3d4…)');
  });
});
