import { describe, it, expect } from 'vitest';
import { isBlankName, isSameBlock } from '../src/lib/blockCrud';

describe('blockCrud pure guards', () => {
  it('isBlankName: empty / whitespace are blank', () => {
    expect(isBlankName('')).toBe(true);
    expect(isBlankName('   ')).toBe(true);
    expect(isBlankName('\t\n')).toBe(true);
  });
  it('isBlankName: non-blank is not blank', () => {
    expect(isBlankName('Logins')).toBe(false);
    expect(isBlankName('  x  ')).toBe(false);
  });
  it('isSameBlock: equal uuids match', () => {
    expect(isSameBlock('ab', 'ab')).toBe(true);
    expect(isSameBlock('ab', 'cd')).toBe(false);
  });
  it('isSameBlock: case-insensitive (hex case variants are the same uuid)', () => {
    expect(isSameBlock('AB', 'ab')).toBe(true);
    expect(isSameBlock('aB', 'Ab')).toBe(true);
  });
});
