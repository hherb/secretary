import { describe, it, expect, vi, beforeEach } from 'vitest';
const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));
import { listContacts, importContact, shareBlock } from '../src/lib/ipc';

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
});
