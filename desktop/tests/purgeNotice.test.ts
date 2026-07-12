// desktop/tests/purgeNotice.test.ts
// Unit tests for the pure post-op purge-notice formatter (#411). Pins every
// row of the design's message table incl. pluralization boundaries and the
// filesFailed warning branch. No I/O; no ambient state.
import { describe, it, expect } from 'vitest';
import { formatPurgeNotice } from '../src/lib/purgeNotice';

describe('formatPurgeNotice', () => {
  it('single-block purge is always "Deleted forever" (success)', () => {
    expect(formatPurgeNotice({ op: 'singlePurge' })).toEqual({
      text: 'Deleted forever',
      severity: 'success'
    });
  });

  it('empty-trash of one block is singular', () => {
    expect(formatPurgeNotice({ op: 'emptyTrash', purgedCount: 1, filesFailed: 0 })).toEqual({
      text: 'Purged 1 item',
      severity: 'success'
    });
  });

  it('empty-trash of several blocks is plural, success', () => {
    expect(formatPurgeNotice({ op: 'emptyTrash', purgedCount: 4, filesFailed: 0 })).toEqual({
      text: 'Purged 4 items',
      severity: 'success'
    });
  });

  it('one failed file is a singular warning', () => {
    expect(formatPurgeNotice({ op: 'emptyTrash', purgedCount: 4, filesFailed: 1 })).toEqual({
      text: 'Purged 4 items · 1 file could not be removed',
      severity: 'warning'
    });
  });

  it('multiple failed files are a plural warning', () => {
    expect(formatPurgeNotice({ op: 'retention', purgedCount: 4, filesFailed: 2 })).toEqual({
      text: 'Purged 4 items · 2 files could not be removed',
      severity: 'warning'
    });
  });

  it('retention with nothing expired is a distinct success message', () => {
    expect(formatPurgeNotice({ op: 'retention', purgedCount: 0, filesFailed: 0 })).toEqual({
      text: 'No items were past the retention window',
      severity: 'success'
    });
  });

  it('empty-trash that purged nothing (concurrent empty) reports so', () => {
    expect(formatPurgeNotice({ op: 'emptyTrash', purgedCount: 0, filesFailed: 0 })).toEqual({
      text: 'Trash was already empty',
      severity: 'success'
    });
  });
});
