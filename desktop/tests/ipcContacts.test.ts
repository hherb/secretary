import { describe, it, expect, vi, beforeEach } from 'vitest';
const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));
import { listContacts, importContact, shareBlock, exportContactCard, deleteContactCard, listContactBlocks } from '../src/lib/ipc';

describe('contacts IPC wrappers', () => {
  beforeEach(() => invokeMock.mockReset());

  it('listContacts invokes with empty args', async () => {
    invokeMock.mockResolvedValueOnce({ contacts: [], unreadableCount: 0 });
    await listContacts();
    expect(invokeMock).toHaveBeenCalledWith('list_contacts', {});
  });
  it('importContact forwards cardPath', async () => {
    invokeMock.mockResolvedValueOnce({ contactUuidHex: 'ab', displayName: 'A' });
    await importContact('/tmp/a.card');
    expect(invokeMock).toHaveBeenCalledWith('import_contact', { cardPath: '/tmp/a.card' });
  });
  it('shareBlock forwards both uuids', async () => {
    invokeMock.mockResolvedValueOnce(undefined);
    await shareBlock('blk', 'rcp');
    expect(invokeMock).toHaveBeenCalledWith('share_block', { blockUuidHex: 'blk', recipientUuidHex: 'rcp' });
  });
  it('exportContactCard invokes with destDir and returns path', async () => {
    invokeMock.mockResolvedValueOnce({ path: '/tmp/contact.vcf' });
    const result = await exportContactCard('/tmp');
    expect(invokeMock).toHaveBeenCalledWith('export_contact_card', { destDir: '/tmp' });
    expect(result).toEqual({ path: '/tmp/contact.vcf' });
  });
  it('deleteContactCard invokes with contactUuidHex', async () => {
    invokeMock.mockResolvedValueOnce(undefined);
    await deleteContactCard('abcd');
    expect(invokeMock).toHaveBeenCalledWith('delete_contact_card', { contactUuidHex: 'abcd' });
  });
  it('listContactBlocks forwards contactUuidHex', async () => {
    invokeMock.mockResolvedValueOnce([
      { blockUuidHex: 'b1', blockName: 'Logins', createdAtMs: 0, lastModifiedMs: 0 }
    ]);
    const out = await listContactBlocks('abcd');
    expect(invokeMock).toHaveBeenCalledWith('list_contact_blocks', { contactUuidHex: 'abcd' });
    expect(out).toEqual([
      { blockUuidHex: 'b1', blockName: 'Logins', createdAtMs: 0, lastModifiedMs: 0 }
    ]);
  });
});
