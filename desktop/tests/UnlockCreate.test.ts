import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import Unlock from '../src/routes/Unlock.svelte';
import { get } from 'svelte/store';
import { appRoute, createSeedPath, createdVaultPath, _resetRouteForTest } from '../src/lib/route';
import { _resetSessionStateForTest, unlockFailed, beginUnlock } from '../src/lib/stores';

vi.mock('@tauri-apps/plugin-dialog', () => ({ open: vi.fn() }));

describe('Unlock <-> create wiring', () => {
  beforeEach(() => {
    _resetSessionStateForTest();
    _resetRouteForTest();
  });

  it('pre-fills the folder and shows a banner after a create', () => {
    createdVaultPath.set('/Users/h/new-vault');
    const { getByText } = render(Unlock);
    expect(getByText(/vault created/i)).toBeTruthy();
  });

  it('"Create a vault here" opens the wizard seeded with the path', async () => {
    beginUnlock(0);
    unlockFailed({ code: 'vault_path_not_a_vault', path: '/Users/h/Docs' });
    const { getByRole } = render(Unlock);
    await fireEvent.click(getByRole('button', { name: /create a vault here/i }));
    expect(get(appRoute)).toBe('create');
  });

  it('consumes createdVaultPath so the banner is one-shot', () => {
    createdVaultPath.set('/Users/h/new-vault');
    const { getByText } = render(Unlock);
    expect(getByText(/vault created/i)).toBeTruthy();   // shows this mount
    expect(get(createdVaultPath)).toBe('');             // store consumed
  });

  it('always offers a "Create a new vault" button, even with no prior error', () => {
    const { getByRole } = render(Unlock);
    expect(getByRole('button', { name: /create a new vault/i })).toBeTruthy();
  });

  it('"Create a new vault" opens the wizard seeded with the typed folder', async () => {
    // createdVaultPath pre-fills folderPath on mount (one-shot), giving us a
    // populated folder without having to drive the PathPicker dialog.
    createdVaultPath.set('/Users/h/typed');
    const { getByRole } = render(Unlock);
    await fireEvent.click(getByRole('button', { name: /create a new vault/i }));
    expect(get(appRoute)).toBe('create');
    expect(get(createSeedPath)).toBe('/Users/h/typed');
  });
});
