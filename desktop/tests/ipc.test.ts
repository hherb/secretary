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

import { describe, it, expect, vi, beforeEach } from 'vitest';

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
  lock,
  notifyActivity
} from '../src/lib/ipc';

beforeEach(() => {
  invokeMock.mockReset();
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
    await setSettings({ autoLockTimeoutMs: 60_000 });
    expect(invokeMock).toHaveBeenCalledWith('set_settings', {
      settings: { autoLockTimeoutMs: 60_000 }
    });
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
      { blockUuidHex: 'aa', blockName: 'Banking', recordCount: 3, lastModMs: 100 }
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
});
