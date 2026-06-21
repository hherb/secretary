// Pins the IPC wrapper contract: argument names + shapes match what the
// Rust commands expect, and the error path re-throws as a typed AppError
// rather than the raw Tauri rejection (which may be a string, plain object,
// or AppError-shaped object depending on where in the Rust call stack the
// failure originated).
//
// Mock hoisting note: `vi.mock` factories are hoisted to the top of the
// file but their bodies are evaluated lazily, AFTER module-scope `const`
// declarations. To safely capture a `vi.fn()` inside the factory, we use
// `vi.hoisted` — it runs before the mock factory and returns the shared
// reference. The naive pattern (`const invokeMock = vi.fn(); vi.mock(...)`)
// produces a temporal-dead-zone error on some Vitest versions.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));

vi.mock('@tauri-apps/api/core', () => ({
  invoke: invokeMock
}));

import {
  unlockWithPassword,
  listBlocks,
  getManifest,
  getSettings,
  setSettings,
  verifyPassword,
  lock,
  notifyActivity,
  readBlock,
  createVault,
  probeCreateTarget,
  syncStatus,
  syncNow,
  syncCommitDecisions,
  type SettingsDto
} from '../src/lib/ipc';

beforeEach(() => {
  invokeMock.mockReset();
  // Suppress the IPC error-path log noise; individual tests that assert
  // on console.error re-spy with their own implementation.
  vi.spyOn(console, 'error').mockImplementation(() => {});
});

describe('ipc wrappers — argument shape', () => {
  it('unlockWithPassword sends camelCase folderPath + password', async () => {
    invokeMock.mockResolvedValue({
      vaultUuidHex: 'aa',
      ownerUserUuidHex: 'bb',
      blockCount: 0,
      blockSummaries: [],
      warnings: []
    });
    await unlockWithPassword('/path', 'secret');
    expect(invokeMock).toHaveBeenCalledWith('unlock_with_password', {
      folderPath: '/path',
      password: 'secret'
    });
  });

  it('setSettings nests the DTO under a `settings` key', async () => {
    invokeMock.mockResolvedValue(undefined);
    const dto: SettingsDto = { autoLockTimeoutMs: 60_000, requirePasswordBeforeEdits: false, reauthGraceWindowMs: 120_000 };
    await setSettings(dto);
    expect(invokeMock).toHaveBeenCalledWith('set_settings', { settings: dto });
  });

  it('argument-less commands invoke with no args object', async () => {
    invokeMock.mockResolvedValue(undefined);
    await lock();
    await notifyActivity();
    expect(invokeMock).toHaveBeenNthCalledWith(1, 'lock', undefined);
    expect(invokeMock).toHaveBeenNthCalledWith(2, 'notify_activity', undefined);
  });
});

describe('ipc wrappers — return shape', () => {
  it('listBlocks resolves with the array unchanged', async () => {
    const payload = [
      { blockUuidHex: 'aa', blockName: 'Banking', createdAtMs: 50, lastModifiedMs: 100 }
    ];
    invokeMock.mockResolvedValue(payload);
    const blocks = await listBlocks();
    expect(blocks).toEqual(payload);
  });

  it('getManifest resolves with the DTO unchanged', async () => {
    const payload = {
      vaultUuidHex: 'aa',
      ownerUserUuidHex: 'bb',
      blockCount: 2,
      blockSummaries: [],
      warnings: [{ code: 'settings_clamped', original_ms: 30_000, clamped_ms: 60_000 }]
    };
    invokeMock.mockResolvedValue(payload);
    const manifest = await getManifest();
    expect(manifest).toEqual(payload);
  });

  it('getSettings resolves with the DTO unchanged', async () => {
    invokeMock.mockResolvedValue({ autoLockTimeoutMs: 60_000 });
    const settings = await getSettings();
    expect(settings.autoLockTimeoutMs).toBe(60_000);
  });

  it('verifyPassword invokes verify_password with the password arg', async () => {
    invokeMock.mockResolvedValueOnce(undefined);
    await verifyPassword('hunter2');
    expect(invokeMock).toHaveBeenCalledWith('verify_password', { password: 'hunter2' });
  });

  it('verifyPassword surfaces a wrong_password AppError', async () => {
    invokeMock.mockRejectedValueOnce({ code: 'wrong_password' });
    await expect(verifyPassword('bad')).rejects.toEqual({ code: 'wrong_password' });
  });
});

describe('ipc wrappers — error path', () => {
  it('re-throws typed AppError on rejection', async () => {
    invokeMock.mockRejectedValue({ code: 'wrong_password' });
    await expect(unlockWithPassword('/x', 'wrong')).rejects.toMatchObject({
      code: 'wrong_password'
    });
  });

  it('preserves payload fields on typed rejection', async () => {
    invokeMock.mockRejectedValue({ code: 'vault_path_not_found', path: '/missing' });
    await expect(unlockWithPassword('/missing', 'pw')).rejects.toMatchObject({
      code: 'vault_path_not_found',
      path: '/missing'
    });
  });

  it('wraps non-typed rejection (bare string) as internal', async () => {
    invokeMock.mockRejectedValue('a string, not a typed error');
    await expect(listBlocks()).rejects.toMatchObject({ code: 'internal' });
  });

  it('wraps non-typed rejection (object without code) as internal', async () => {
    invokeMock.mockRejectedValue({ message: 'panic in command handler' });
    await expect(listBlocks()).rejects.toMatchObject({ code: 'internal' });
  });

  it('wraps null and undefined rejections as internal', async () => {
    invokeMock.mockRejectedValueOnce(undefined);
    await expect(listBlocks()).rejects.toMatchObject({ code: 'internal' });
    invokeMock.mockRejectedValueOnce(null);
    await expect(listBlocks()).rejects.toMatchObject({ code: 'internal' });
  });

  // Defense-in-depth: an object whose `code` is a string but is NOT a
  // known AppError discriminator (e.g. emitted by a future Rust variant
  // the TS layer hasn't been updated for) must be coerced to `internal`
  // rather than passed through. Without this, the unknown code would
  // reach `userMessageFor` and fall into its runtime fallback — desired
  // behaviour, but it's safer to coerce at the IPC boundary first so
  // every downstream component sees only known codes.
  it('coerces unknown-code rejection to internal', async () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    invokeMock.mockRejectedValue({ code: 'future_variant_v2', extra: 1 });
    await expect(listBlocks()).rejects.toMatchObject({ code: 'internal' });
    expect(errorSpy).toHaveBeenCalled();
    errorSpy.mockRestore();
  });

  it('logs the original rejection before coercing to internal', async () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const original = { tauri_panic: 'serialize failed' };
    invokeMock.mockRejectedValue(original);
    await expect(listBlocks()).rejects.toMatchObject({ code: 'internal' });
    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining('list_blocks'),
      original
    );
    errorSpy.mockRestore();
  });
});

describe('ipc wrappers — createVault + probeCreateTarget', () => {
  it('createVault forwards camelCase args and returns the DTO', async () => {
    invokeMock.mockResolvedValueOnce({ mnemonic: 'word '.repeat(24).trim() });
    const dto = await createVault('/tmp/v', 'Me', 'pw');
    expect(invokeMock).toHaveBeenCalledWith('create_vault', {
      folderPath: '/tmp/v',
      displayName: 'Me',
      password: 'pw'
    });
    expect(dto.mnemonic).toBe('word '.repeat(24).trim());
  });

  it('probeCreateTarget returns exists + isEmpty', async () => {
    invokeMock.mockResolvedValueOnce({ exists: true, isEmpty: true });
    const probe = await probeCreateTarget('/tmp/v');
    expect(invokeMock).toHaveBeenCalledWith('probe_create_target', { folderPath: '/tmp/v' });
    expect(probe).toEqual({ exists: true, isEmpty: true });
  });
});

describe('ipc wrappers — readBlock', () => {
  it('readBlock returns the BlockDetailDto', async () => {
    invokeMock.mockResolvedValueOnce({
      blockUuidHex: 'ab', blockName: 'Personal logins',
      records: [{ recordUuidHex: 'cd', recordType: 'login', tags: ['work'],
        createdAtMs: 1, lastModMs: 2, fieldCount: 1,
        fields: [{ name: 'password', lastModMs: 2, isText: true, isBytes: false }] }]
    });
    const dto = await readBlock('ab');
    expect(invokeMock).toHaveBeenCalledWith('read_block', { blockUuidHex: 'ab', includeDeleted: false });
    expect(dto.records[0].recordType).toBe('login');
  });
});

describe('ipc.ts — sync wrappers', () => {
  beforeEach(() => invokeMock.mockReset());

  it('syncStatus invokes the sync_status command', async () => {
    invokeMock.mockResolvedValue({ hasState: true, lastStateWriteMs: 123 });
    const dto = await syncStatus();
    expect(invokeMock).toHaveBeenCalledWith('sync_status', undefined);
    expect(dto).toEqual({ hasState: true, lastStateWriteMs: 123 });
  });

  it('syncNow invokes sync_now with the password arg', async () => {
    invokeMock.mockResolvedValue({ kind: 'nothingToDo' });
    const outcome = await syncNow('hunter2');
    expect(invokeMock).toHaveBeenCalledWith('sync_now', { password: 'hunter2' });
    expect(outcome).toEqual({ kind: 'nothingToDo' });
  });

  it('syncNow re-throws a typed AppError on rejection', async () => {
    // `...Once` (not the persistent `mockRejectedValue`) avoids a Vitest
    // unhandled-rejection that fails this test even though `call` catches it.
    invokeMock.mockRejectedValueOnce({ code: 'sync_in_progress' });
    await expect(syncNow('hunter2')).rejects.toMatchObject({ code: 'sync_in_progress' });
  });

  it('syncCommitDecisions invokes the command with decisions + token', async () => {
    invokeMock.mockResolvedValueOnce({ kind: 'mergedClean' });
    const out = await syncCommitDecisions('pw', [{ recordUuidHex: '0a', keepLocal: true }], [1, 2, 3]);
    expect(invokeMock).toHaveBeenCalledWith('sync_commit_decisions', {
      password: 'pw',
      decisions: [{ recordUuidHex: '0a', keepLocal: true }],
      manifestHash: [1, 2, 3]
    });
    expect(out).toEqual({ kind: 'mergedClean' });
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});
