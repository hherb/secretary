import { describe, it, expect, beforeEach } from 'vitest';
import { get } from 'svelte/store';
import {
  appRoute,
  createSeedPath,
  createdVaultPath,
  openCreateWizard,
  cancelCreateWizard,
  finishCreateWizard,
  _resetRouteForTest
} from '../src/lib/route';

describe('route store', () => {
  beforeEach(() => _resetRouteForTest());

  it('defaults to unlock with empty paths', () => {
    expect(get(appRoute)).toBe('unlock');
    expect(get(createSeedPath)).toBe('');
    expect(get(createdVaultPath)).toBe('');
  });

  it('openCreateWizard routes to create and seeds the folder', () => {
    openCreateWizard('/Users/h/Docs');
    expect(get(appRoute)).toBe('create');
    expect(get(createSeedPath)).toBe('/Users/h/Docs');
  });

  it('openCreateWizard with no arg routes to create with an empty seed', () => {
    openCreateWizard();
    expect(get(appRoute)).toBe('create');
    expect(get(createSeedPath)).toBe('');
  });

  it('cancelCreateWizard returns to unlock and clears the seed', () => {
    openCreateWizard('/x');
    cancelCreateWizard();
    expect(get(appRoute)).toBe('unlock');
    expect(get(createSeedPath)).toBe('');
  });

  it('finishCreateWizard returns to unlock and records the created path', () => {
    openCreateWizard('/x');
    finishCreateWizard('/Users/h/new-vault');
    expect(get(appRoute)).toBe('unlock');
    expect(get(createdVaultPath)).toBe('/Users/h/new-vault');
    expect(get(createSeedPath)).toBe('');
  });

  it('cancelCreateWizard also clears any pending createdVaultPath', () => {
    finishCreateWizard('/Users/h/new-vault');
    expect(get(createdVaultPath)).toBe('/Users/h/new-vault');
    openCreateWizard('/x');
    cancelCreateWizard();
    expect(get(createdVaultPath)).toBe('');
  });
});
