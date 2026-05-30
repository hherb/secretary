// Pure record-draft model for the D.1.4 editor. No IPC, no DOM — the host
// component (RecordEditor.svelte) holds the draft as $state and calls these.
// A field's `value` is plaintext for kind 'text' and base64 for kind 'bytes'.

import type { RecordDto, RecordInputDto, RecordRevealDto } from './ipc';

export type FieldKind = 'text' | 'bytes';

export interface EditorFieldDraft {
  name: string;
  kind: FieldKind;
  value: string;
}

export interface RecordDraft {
  recordType: string;
  tags: string[];
  fields: EditorFieldDraft[];
}

export function emptyField(): EditorFieldDraft {
  return { name: '', kind: 'text', value: '' };
}

export function emptyDraft(): RecordDraft {
  return { recordType: '', tags: [], fields: [emptyField()] };
}

/** Prefill an edit draft from a record's metadata + its revealed values. */
export function recordToDraft(record: RecordDto, reveal: RecordRevealDto): RecordDraft {
  return {
    recordType: record.recordType,
    tags: [...record.tags],
    fields: reveal.fields.map((f) => ({
      name: f.name,
      kind: f.isText ? 'text' : 'bytes',
      value: f.value
    }))
  };
}

/** True iff `s` is valid standard base64 (empty allowed). */
export function isValidBase64(s: string): boolean {
  if (s.length === 0) return true;
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return false;
  if (s.length % 4 !== 0) return false;
  try {
    atob(s);
    return true;
  } catch {
    return false;
  }
}

export interface ValidationResult {
  ok: boolean;
  fieldErrors: Record<number, string>;
  formError?: string;
}

/** Validate a draft: field names required + unique; bytes values valid base64. */
export function validateRecordDraft(draft: RecordDraft): ValidationResult {
  const fieldErrors: Record<number, string> = {};
  const seen = new Set<string>();
  draft.fields.forEach((f, i) => {
    const name = f.name.trim();
    if (name.length === 0) {
      fieldErrors[i] = 'Field name is required.';
    } else if (seen.has(name)) {
      fieldErrors[i] = 'Field name must be unique.';
    } else if (f.kind === 'bytes' && !isValidBase64(f.value)) {
      fieldErrors[i] = 'Value must be valid base64.';
    }
    if (name.length > 0) seen.add(name);
  });
  return { ok: Object.keys(fieldErrors).length === 0, fieldErrors };
}

/** Map a (presumed-valid) draft to the IPC wire shape. */
export function draftToRecordInputDto(draft: RecordDraft): RecordInputDto {
  return {
    recordType: draft.recordType.trim(),
    tags: draft.tags.map((t) => t.trim()).filter((t) => t.length > 0),
    fields: draft.fields.map((f) => ({
      name: f.name.trim(),
      value: f.kind === 'text' ? { kind: 'text', text: f.value } : { kind: 'bytes', base64: f.value }
    }))
  };
}
