import { describe, it, expect } from 'vitest';
import {
  startWizard,
  toCredentials,
  toMnemonic,
  passwordsMatch,
  joinSubfolder,
  groupMnemonicWords
} from '../src/lib/create';

describe('wizard step machine', () => {
  it('starts at folder', () => {
    expect(startWizard()).toEqual({ step: 'folder' });
  });
  it('advances to credentials carrying the folder', () => {
    expect(toCredentials('/v')).toEqual({ step: 'credentials', folder: '/v' });
  });
  it('advances to mnemonic carrying folder + phrase', () => {
    expect(toMnemonic('/v', 'a b c')).toEqual({ step: 'mnemonic', folder: '/v', mnemonic: 'a b c' });
  });
});

describe('passwordsMatch', () => {
  it('true only when non-empty and equal', () => {
    expect(passwordsMatch('hunter2', 'hunter2')).toBe(true);
    expect(passwordsMatch('a', 'b')).toBe(false);
    expect(passwordsMatch('', '')).toBe(false);
  });
});

describe('joinSubfolder', () => {
  it('joins with the parent separator', () => {
    expect(joinSubfolder('/Users/h/Docs', 'vault')).toBe('/Users/h/Docs/vault');
    expect(joinSubfolder('/Users/h/Docs/', 'vault')).toBe('/Users/h/Docs/vault');
  });
  it('rejects empty or separator-bearing names', () => {
    expect(joinSubfolder('/x', '  ')).toBeNull();
    expect(joinSubfolder('/x', 'a/b')).toBeNull();
    expect(joinSubfolder('/x', 'a\\b')).toBeNull();
  });
  it('rejects traversal segments so the path can never escape the parent', () => {
    expect(joinSubfolder('/Users/h/Docs', '.')).toBeNull();
    expect(joinSubfolder('/Users/h/Docs', '..')).toBeNull();
    expect(joinSubfolder('/Users/h/Docs', '  ..  ')).toBeNull();
  });
});

describe('groupMnemonicWords', () => {
  it('numbers words from 1 and drops blanks', () => {
    const out = groupMnemonicWords('alpha   bravo charlie');
    expect(out).toEqual([
      { index: 1, word: 'alpha' },
      { index: 2, word: 'bravo' },
      { index: 3, word: 'charlie' }
    ]);
  });
});
