// Tests for TopBar.svelte — the unlocked-vault top bar. Renders the app
// title + a truncated vault UUID label + a settings-gear button (now
// enabled, fires onOpenSettings) + the LockButton.
//
// TopBar takes `vaultLabel` and `onOpenSettings` as props so the parent
// (Vault.svelte) can pre-truncate the UUID and own the dialog open state.
// Keeps the component pure — testable without mocking the entire
// sessionState store.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
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
const SETTINGS: SettingsDto = { autoLockTimeoutMs: 600_000, requirePasswordBeforeEdits: false, reauthGraceWindowMs: 120_000 };

// LockButton imports `lock` from ipc; SyncPill imports `syncStatus` —
// stub both so the rendered TopBar mounts without side-effects.
const { lockMock } = vi.hoisted(() => ({ lockMock: vi.fn() }));
vi.mock('../src/lib/ipc', async () => {
  const real = await vi.importActual<typeof import('../src/lib/ipc')>('../src/lib/ipc');
  return {
    ...real,
    lock: lockMock,
    syncStatus: vi.fn().mockResolvedValue({ hasState: false, lastStateWriteMs: null })
  };
});

beforeEach(() => {
  _resetSessionStateForTest();
  // TopBar contains LockButton which guards on `unlocked` state — set
  // it here so the lock-button is rendered in its real-app condition.
  beginUnlock(0);
  unlockSucceeded(MANIFEST, SETTINGS);
});

function renderBar(opts: { vaultLabel?: string; onOpenSettings?: () => void } = {}) {
  return render(TopBar, {
    props: {
      vaultLabel: opts.vaultLabel ?? 'aabbccdd…',
      onOpenSettings: opts.onOpenSettings ?? vi.fn()
    }
  });
}

describe('TopBar.svelte — rendering', () => {
  it('renders the app title "Secretary"', () => {
    const { getByText } = renderBar();
    expect(getByText(/secretary/i)).toBeTruthy();
  });

  it('renders the vault label passed via props', () => {
    const { getByText } = renderBar({ vaultLabel: 'aabbccdd…' });
    expect(getByText(/aabbccdd…/)).toBeTruthy();
  });

  it('renders the settings-gear button (enabled — Task 9 wired it up)', () => {
    const { getByRole } = renderBar();
    const settings = getByRole('button', { name: /settings/i });
    expect((settings as HTMLButtonElement).disabled).toBe(false);
  });

  it('clicking the settings button fires the onOpenSettings callback', async () => {
    const onOpenSettings = vi.fn();
    const { getByRole } = renderBar({ onOpenSettings });
    await fireEvent.click(getByRole('button', { name: /settings/i }));
    expect(onOpenSettings).toHaveBeenCalledTimes(1);
  });

  it('renders the LockButton', () => {
    const { getByRole } = renderBar();
    expect(getByRole('button', { name: /lock/i })).toBeTruthy();
  });

  it('settings button has a title attribute (hover hint for the gear icon)', () => {
    // The gear emoji alone isn't enough — sighted users get the hover
    // hint while screen-reader users get aria-label.
    const { getByRole } = renderBar();
    const settings = getByRole('button', { name: /settings/i });
    const title = settings.getAttribute('title') ?? '';
    expect(title.length).toBeGreaterThan(0);
  });

  it('mounts the sync pill with a Sync control', async () => {
    const { findByRole } = renderBar();
    expect(await findByRole('button', { name: /sync now/i })).toBeTruthy();
  });
});

describe('TopBar.svelte — empty / edge cases', () => {
  it('renders even when vaultLabel is empty', () => {
    // Defensive: don't crash on an empty label. Backend doesn't promise
    // a non-empty UUID slice (it does, but TopBar is dumb about that).
    const { container } = renderBar({ vaultLabel: '' });
    expect(container.textContent).toMatch(/secretary/i);
  });
});
