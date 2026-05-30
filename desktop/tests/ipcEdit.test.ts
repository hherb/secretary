import { describe, it, expect, vi, beforeEach } from 'vitest';
const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));

import { createBlock, saveRecord, saveRecordEdit, revealRecord } from '../src/lib/ipc';

describe('edit IPC wrappers', () => {
  beforeEach(() => invokeMock.mockReset());

  it('createBlock forwards blockName', async () => {
    invokeMock.mockResolvedValueOnce({ blockUuidHex: 'ab', blockName: 'Logins', createdAtMs: 1, lastModifiedMs: 1 });
    const s = await createBlock('Logins');
    expect(invokeMock).toHaveBeenCalledWith('create_block', { blockName: 'Logins' });
    expect(s.blockUuidHex).toBe('ab');
  });

  it('saveRecord forwards block + record DTO', async () => {
    invokeMock.mockResolvedValueOnce({ blockUuidHex: 'ab', recordUuidHex: 'cd' });
    const dto = { recordType: 'login', tags: [], fields: [{ name: 'u', value: { kind: 'text' as const, text: 'a' } }] };
    const ref = await saveRecord('ab', dto);
    expect(invokeMock).toHaveBeenCalledWith('save_record', { blockUuidHex: 'ab', record: dto });
    expect(ref.recordUuidHex).toBe('cd');
  });

  it('saveRecordEdit forwards block + record uuid + DTO', async () => {
    invokeMock.mockResolvedValueOnce({ blockUuidHex: 'ab', recordUuidHex: 'cd' });
    const dto = { recordType: 'login', tags: [], fields: [] };
    await saveRecordEdit('ab', 'cd', dto);
    expect(invokeMock).toHaveBeenCalledWith('save_record_edit', { blockUuidHex: 'ab', recordUuidHex: 'cd', record: dto });
  });

  it('revealRecord forwards block + record uuid', async () => {
    invokeMock.mockResolvedValueOnce({ fields: [{ name: 'u', isText: true, value: 'a' }] });
    const r = await revealRecord('ab', 'cd');
    expect(invokeMock).toHaveBeenCalledWith('reveal_record', { blockUuidHex: 'ab', recordUuidHex: 'cd' });
    expect(r.fields[0].value).toBe('a');
  });
});
