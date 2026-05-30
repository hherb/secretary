import { describe, it, expect } from 'vitest';
import {
  emptyDraft, emptyField, recordToDraft, isValidBase64,
  validateRecordDraft, draftToRecordInputDto, type RecordDraft
} from '../src/lib/editor';
import type { RecordDto, RecordRevealDto } from '../src/lib/ipc';

describe('emptyDraft / emptyField', () => {
  it('emptyField returns a blank text field', () => {
    expect(emptyField()).toEqual({ name: '', kind: 'text', value: '' });
  });
  it('emptyDraft returns one blank field', () => {
    expect(emptyDraft()).toEqual({ recordType: '', tags: [], fields: [{ name: '', kind: 'text', value: '' }] });
  });
});

describe('isValidBase64', () => {
  it('accepts valid + empty, rejects junk', () => {
    expect(isValidBase64('aGVsbG8=')).toBe(true);
    expect(isValidBase64('')).toBe(true);
    expect(isValidBase64('not valid!!')).toBe(false);
  });
});

describe('validateRecordDraft', () => {
  it('passes a clean text-only draft', () => {
    const d: RecordDraft = { recordType: 'login', tags: [], fields: [{ name: 'u', kind: 'text', value: 'a' }] };
    expect(validateRecordDraft(d).ok).toBe(true);
  });
  it('flags empty + duplicate field names', () => {
    const d: RecordDraft = { recordType: '', tags: [], fields: [
      { name: '', kind: 'text', value: 'x' },
      { name: 'dup', kind: 'text', value: '1' },
      { name: 'dup', kind: 'text', value: '2' }
    ] };
    const r = validateRecordDraft(d);
    expect(r.ok).toBe(false);
    expect(r.fieldErrors[0]).toMatch(/name/i);
    expect(r.fieldErrors[2]).toMatch(/unique|duplicate/i);
  });
  it('flags bad base64 on a bytes field', () => {
    const d: RecordDraft = { recordType: '', tags: [], fields: [{ name: 'seed', kind: 'bytes', value: 'nope!!' }] };
    const r = validateRecordDraft(d);
    expect(r.ok).toBe(false);
    expect(r.fieldErrors[0]).toMatch(/base64/i);
  });
});

describe('draftToRecordInputDto', () => {
  it('maps text + bytes to the tagged wire shape', () => {
    const d: RecordDraft = { recordType: 'login', tags: ['work'], fields: [
      { name: 'u', kind: 'text', value: 'alice' },
      { name: 'seed', kind: 'bytes', value: 'aGVsbG8=' }
    ] };
    expect(draftToRecordInputDto(d)).toEqual({
      recordType: 'login', tags: ['work'],
      fields: [
        { name: 'u', value: { kind: 'text', text: 'alice' } },
        { name: 'seed', value: { kind: 'bytes', base64: 'aGVsbG8=' } }
      ]
    });
  });

  it('preserves field values verbatim (does not trim) while trimming name/type/tags', () => {
    // Whitespace inside a stored password or base64 blob is significant;
    // trimming it would silently corrupt secrets. This test pins that invariant.
    const d: RecordDraft = {
      recordType: '  login  ',
      tags: ['  work  ', '   '],   // blank-only tag should be filtered out
      fields: [{ name: '  pw  ', kind: 'text', value: '  hunter2  ' }]
    };
    const dto = draftToRecordInputDto(d);
    expect(dto.recordType).toBe('login');                                    // trimmed
    expect(dto.tags).toEqual(['work']);                                      // trimmed + blank filtered
    expect(dto.fields[0].name).toBe('pw');                                  // trimmed
    expect(dto.fields[0].value).toEqual({ kind: 'text', text: '  hunter2  ' }); // value NOT trimmed
  });
});

describe('recordToDraft', () => {
  it('prefills type + tags from the record and values from the reveal', () => {
    const rec: RecordDto = { recordUuidHex: 'cd', recordType: 'login', tags: ['work'], createdAtMs: 1, lastModMs: 1, fieldCount: 2, fields: [] };
    const reveal: RecordRevealDto = { fields: [
      { name: 'u', isText: true, value: 'alice' },
      { name: 'seed', isText: false, value: 'aGVsbG8=' }
    ] };
    expect(recordToDraft(rec, reveal)).toEqual({
      recordType: 'login', tags: ['work'],
      fields: [
        { name: 'u', kind: 'text', value: 'alice' },
        { name: 'seed', kind: 'bytes', value: 'aGVsbG8=' }
      ]
    });
  });
});
