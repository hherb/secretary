import { describe, it, expect } from 'vitest';
import { isContentlessTombstone } from '../src/lib/records';
import type { RecordDto } from '../src/lib/ipc';

const base: RecordDto = {
  recordUuidHex: 'cd',
  recordType: 'login',
  tags: [],
  createdAtMs: 1,
  lastModMs: 2,
  fieldCount: 0,
  fields: []
};

describe('isContentlessTombstone', () => {
  it('is true for a tombstoned record with zero fields', () => {
    expect(isContentlessTombstone({ ...base, tombstoned: true, fieldCount: 0 })).toBe(true);
  });

  it('is false for a tombstoned record that still has fields', () => {
    expect(isContentlessTombstone({ ...base, tombstoned: true, fieldCount: 3 })).toBe(false);
  });

  it('is false for a live record with zero fields', () => {
    expect(isContentlessTombstone({ ...base, tombstoned: false, fieldCount: 0 })).toBe(false);
  });

  it('is false for a live record with fields', () => {
    expect(isContentlessTombstone({ ...base, tombstoned: false, fieldCount: 3 })).toBe(false);
  });

  it('is false when tombstoned is undefined', () => {
    expect(isContentlessTombstone({ ...base, fieldCount: 0 })).toBe(false);
  });
});
