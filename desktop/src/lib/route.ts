// Pre-unlock app routing. The create-vault wizard is a UI mode shown in the
// locked context (no vault is open during create), so it lives OUTSIDE the
// session state machine (stores.ts) deliberately — keeping `SessionState`
// strictly about an open/closed vault.

import { writable } from 'svelte/store';

export type AppRoute = 'unlock' | 'create';

/** Which pre-unlock screen App.svelte shows. */
export const appRoute = writable<AppRoute>('unlock');

/** Folder to seed the wizard's first step (from the "Not a vault" hint). */
export const createSeedPath = writable<string>('');

/** Path of a just-created vault — Unlock pre-fills it and shows a banner. */
export const createdVaultPath = writable<string>('');

/** Open the wizard, optionally seeding the picked folder. */
export function openCreateWizard(seedPath = ''): void {
  createSeedPath.set(seedPath);
  appRoute.set('create');
}

/** Abandon the wizard; back to Unlock. */
export function cancelCreateWizard(): void {
  createSeedPath.set('');
  appRoute.set('unlock');
}

/** Finish the wizard: record the created path (for Unlock pre-fill + banner)
 *  and return to Unlock. */
export function finishCreateWizard(createdPath: string): void {
  createdVaultPath.set(createdPath);
  createSeedPath.set('');
  appRoute.set('unlock');
}

/** Test-only reset. Matches the `_resetSessionStateForTest` convention. */
export function _resetRouteForTest(): void {
  appRoute.set('unlock');
  createSeedPath.set('');
  createdVaultPath.set('');
}
