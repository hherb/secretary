// Tests for TopBar.svelte — the unlocked-vault top bar. Renders the app
// title + a truncated vault UUID label + a settings-gear button (disabled
// until Task 9 wires up SettingsDialog) + the LockButton.
//
// TopBar takes `vaultLabel` as a prop so the parent (Vault.svelte) can
// pre-truncate the UUID. Keeps the component pure — testable without
// mocking the entire sessionState store.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render } from '@testing-library/svelte';
import TopBar from '../src/components/TopBar.svelte';
import {
  beginUnlock,
  unlockSucceeded,
  _resetSessionStateForTest
} from '../src/lib/stores';
import type { ManifestDto, SettingsDto } from '../src/lib/ipc';

const MANIFEST: ManifestDto = {
  vaultUuidHex: 'aabbccdd',
  ownerUserUuidHex: 'bb',
  blockCount: 0,
  blockSummaries: [],
  warnings: []
};
const SETTINGS: SettingsDto = { autoLockTimeoutMs: 600_000 };

// LockButton imports `lock` from ipc; stub it so the rendered TopBar
// can mount without exploding when the actual button isn't clicked.
const { lockMock } = vi.hoisted(() => ({ lockMock: vi.fn() }));
vi.mock('../src/lib/ipc', async () => {
  const real = await vi.importActual<typeof import('../src/lib/ipc')>('../src/lib/ipc');
  return { ...real, lock: lockMock };
});

beforeEach(() => {
  _resetSessionStateForTest();
  // TopBar contains LockButton which guards on `unlocked` state — set
  // it here so the lock-button is rendered in its real-app condition.
  beginUnlock(0);
  unlockSucceeded(MANIFEST, SETTINGS);
});

describe('TopBar.svelte — rendering', () => {
  it('renders the app title "Secretary"', () => {
    const { getByText } = render(TopBar, { props: { vaultLabel: 'aabbccdd…' } });
    expect(getByText(/secretary/i)).toBeTruthy();
  });

  it('renders the vault label passed via props', () => {
    const { getByText } = render(TopBar, { props: { vaultLabel: 'aabbccdd…' } });
    expect(getByText(/aabbccdd…/)).toBeTruthy();
  });

  it('renders the settings-gear button (disabled — lands in Task 9)', () => {
    const { getByRole } = render(TopBar, { props: { vaultLabel: 'aabbccdd…' } });
    const settings = getByRole('button', { name: /settings/i });
    expect((settings as HTMLButtonElement).disabled).toBe(true);
  });

  it('renders the LockButton', () => {
    const { getByRole } = render(TopBar, { props: { vaultLabel: 'aabbccdd…' } });
    expect(getByRole('button', { name: /lock/i })).toBeTruthy();
  });

  it('settings button has a title hinting at the deferred functionality', () => {
    // Mirrors the BlockCard pattern — visible disabled element with a
    // hover hint explains why it's there but non-interactive yet.
    const { getByRole } = render(TopBar, { props: { vaultLabel: 'aabbccdd…' } });
    const settings = getByRole('button', { name: /settings/i });
    const title = settings.getAttribute('title') ?? '';
    expect(title.length).toBeGreaterThan(0);
  });
});

describe('TopBar.svelte — empty / edge cases', () => {
  it('renders even when vaultLabel is empty', () => {
    // Defensive: don't crash on an empty label. Backend doesn't promise
    // a non-empty UUID slice (it does, but TopBar is dumb about that).
    const { container } = render(TopBar, { props: { vaultLabel: '' } });
    expect(container.textContent).toMatch(/secretary/i);
  });
});
