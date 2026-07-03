import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render } from '@testing-library/svelte';
import App from '../src/App.svelte';
import { _resetSessionStateForTest } from '../src/lib/stores';
import { openCreateWizard, _resetRouteForTest } from '../src/lib/route';

// App.svelte calls `listen('vault-locked', ...)` on mount. Mock the event
// API so the component can mount in JSDOM without Tauri's runtime present.
vi.mock('@tauri-apps/api/event', () => ({
  listen: vi.fn().mockResolvedValue(() => {})
}));

// App.svelte uses PathPicker, which invokes backend pick_* commands
// directly via `@tauri-apps/api/core` (#353).
vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }));

// App.svelte uses auto_lock for activity tracking.
vi.mock('../src/lib/auto_lock', () => ({
  startActivityTracking: vi.fn().mockReturnValue(() => {})
}));

// When the create wizard is mounted, FolderStep fires probeCreateTarget in
// a $effect. Mock the IPC module so no real Tauri invoke call is made.
vi.mock('../src/lib/ipc', async (importActual) => {
  const actual = await importActual<typeof import('../src/lib/ipc')>();
  return {
    ...actual,
    probeCreateTarget: vi.fn().mockResolvedValue({ exists: true, isEmpty: true }),
    createVault: vi.fn()
  };
});

describe('App pre-unlock routing', () => {
  beforeEach(() => {
    _resetSessionStateForTest();
    _resetRouteForTest();
  });

  it('shows the create wizard when appRoute is create', async () => {
    openCreateWizard('/tmp/v');
    const { findByRole } = render(App);
    expect(await findByRole('heading', { name: /create a vault/i })).toBeTruthy();
  });
});
