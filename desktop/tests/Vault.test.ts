// Tests for Vault.svelte — the post-unlock route. Renders the TopBar
// (with a truncated vault UUID), any AppWarning banners from the
// manifest, the block-count label, and the vertical stack of BlockCards.
//
// Only renders when `sessionState.status === 'unlocked'`. App.svelte's
// router gates us, but defensive narrowing inside guards against the
// router ever invoking Vault from another state.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import Vault from '../src/routes/Vault.svelte';
import {
  beginUnlock,
  unlockSucceeded,
  _resetSessionStateForTest
} from '../src/lib/stores';
import type { ManifestDto, SettingsDto, BlockSummaryDto } from '../src/lib/ipc';
import type { AppWarning } from '../src/lib/errors';

// LockButton (transitively imported via TopBar) calls `lock` ipc, and
// SettingsDialog calls `setSettings`. Stub both so the rendered tree
// doesn't blow up on missing Tauri.
const { lockMock, setSettingsMock } = vi.hoisted(() => ({
  lockMock: vi.fn(),
  setSettingsMock: vi.fn()
}));
vi.mock('../src/lib/ipc', async () => {
  const real = await vi.importActual<typeof import('../src/lib/ipc')>('../src/lib/ipc');
  return { ...real, lock: lockMock, setSettings: setSettingsMock };
});

const SETTINGS: SettingsDto = { autoLockTimeoutMs: 600_000 };

function blockFixture(name: string, uuidHex: string): BlockSummaryDto {
  return {
    blockUuidHex: uuidHex,
    blockName: name,
    createdAtMs: Date.UTC(2024, 0, 1, 12, 0, 0),
    lastModifiedMs: Date.UTC(2024, 5, 15, 12, 0, 0)
  };
}

function manifestFixture(opts: {
  vaultUuidHex?: string;
  blocks?: BlockSummaryDto[];
  warnings?: AppWarning[];
}): ManifestDto {
  const blocks = opts.blocks ?? [];
  return {
    vaultUuidHex: opts.vaultUuidHex ?? 'aabbccddeeff1122',
    ownerUserUuidHex: 'owner-uuid-hex',
    blockCount: blocks.length,
    blockSummaries: blocks,
    warnings: opts.warnings ?? []
  };
}

function unlockWith(manifest: ManifestDto) {
  beginUnlock(0);
  unlockSucceeded(manifest, SETTINGS);
}

beforeEach(() => {
  _resetSessionStateForTest();
  lockMock.mockReset();
  lockMock.mockResolvedValue(undefined);
  setSettingsMock.mockReset();
  setSettingsMock.mockResolvedValue(undefined);
});

describe('Vault.svelte — initial render contract', () => {
  it('renders TopBar (Secretary title visible)', () => {
    unlockWith(manifestFixture({}));
    const { getByText } = render(Vault);
    expect(getByText(/secretary/i)).toBeTruthy();
  });

  it('renders the truncated vault UUID as the TopBar label', () => {
    // First 8 hex chars + ellipsis. Pins the truncation policy so a
    // change here can't silently widen / narrow the visible identifier.
    unlockWith(manifestFixture({ vaultUuidHex: 'aabbccddeeff1122' }));
    const { getByText } = render(Vault);
    expect(getByText(/aabbccdd…/)).toBeTruthy();
  });

  it('renders the LockButton (via TopBar)', () => {
    unlockWith(manifestFixture({}));
    const { getByRole } = render(Vault);
    expect(getByRole('button', { name: /lock/i })).toBeTruthy();
  });

  it('renders a short vault UUID without a misleading ellipsis tail', () => {
    // Backend currently emits 32-hex-char UUIDs so the slice is always a
    // strict prefix. But if a future build or debug fixture ever produces
    // a value shorter than the prefix length, the bar must show the full
    // string rather than "abc…" (where the "…" implies a hidden suffix).
    unlockWith(manifestFixture({ vaultUuidHex: 'abc' }));
    const { getByText, queryByText } = render(Vault);
    expect(getByText('abc')).toBeTruthy();
    expect(queryByText(/abc…/)).toBeNull();
  });
});

describe('Vault.svelte — block count pluralisation', () => {
  it('shows "0 blocks" when the vault is empty', () => {
    unlockWith(manifestFixture({ blocks: [] }));
    const { getByText } = render(Vault);
    expect(getByText(/0 blocks/i)).toBeTruthy();
  });

  it('shows "1 block" (singular) when there is exactly one block', () => {
    unlockWith(manifestFixture({ blocks: [blockFixture('Banking', 'aa')] }));
    const { getByText } = render(Vault);
    expect(getByText(/1 block(?!s)/i)).toBeTruthy();
  });

  it('shows "N blocks" (plural) when there are multiple blocks', () => {
    unlockWith(
      manifestFixture({
        blocks: [
          blockFixture('Banking', 'aa'),
          blockFixture('Email', 'bb'),
          blockFixture('Servers', 'cc')
        ]
      })
    );
    const { getByText } = render(Vault);
    expect(getByText(/3 blocks/i)).toBeTruthy();
  });
});

describe('Vault.svelte — block list rendering', () => {
  it('renders one BlockCard per block, in manifest order', () => {
    unlockWith(
      manifestFixture({
        blocks: [
          blockFixture('Banking', 'aa'),
          blockFixture('Email', 'bb'),
          blockFixture('Servers', 'cc')
        ]
      })
    );
    const { getByText } = render(Vault);
    expect(getByText('Banking')).toBeTruthy();
    expect(getByText('Email')).toBeTruthy();
    expect(getByText('Servers')).toBeTruthy();
  });

  it('renders no BlockCards when the manifest has no blocks', () => {
    unlockWith(manifestFixture({ blocks: [] }));
    const { container } = render(Vault);
    // BlockCard renders a <button class="block-card">; counting them is
    // the simplest pin that's robust against label changes.
    expect(container.querySelectorAll('.block-card').length).toBe(0);
  });
});

describe('Vault.svelte — manifest warning banners', () => {
  it('renders a banner per warning in the manifest', () => {
    const warnings: AppWarning[] = [
      { code: 'settings_corrupt' },
      { code: 'settings_clamped', original_ms: 1_000_000, clamped_ms: 600_000 }
    ];
    unlockWith(manifestFixture({ warnings }));
    const { getByText } = render(Vault);
    // userMessageForWarning(settings_corrupt) → title "Settings record malformed"
    // userMessageForWarning(settings_clamped) → title "Settings value clamped"
    expect(getByText(/settings record malformed/i)).toBeTruthy();
    expect(getByText(/settings value clamped/i)).toBeTruthy();
  });

  it('does not render any banner when warnings is empty', () => {
    unlockWith(manifestFixture({ warnings: [] }));
    const { container } = render(Vault);
    expect(container.querySelectorAll('.vault__warning').length).toBe(0);
  });
});

describe('Vault.svelte — settings dialog wiring', () => {
  it('mounts SettingsDialog in the closed state by default', () => {
    // The dialog is always in the DOM (the bindable `open` prop drives
    // showModal/close inside the component) but starts hidden.
    unlockWith(manifestFixture({}));
    const { container } = render(Vault);
    const dialog = container.querySelector('.settings-dialog') as HTMLDialogElement | null;
    expect(dialog).not.toBeNull();
    expect(dialog?.hasAttribute('open')).toBe(false);
  });

  it('clicking the TopBar settings gear opens the dialog', async () => {
    unlockWith(manifestFixture({}));
    const { container, getByRole } = render(Vault);
    const gear = getByRole('button', { name: /settings/i });
    await fireEvent.click(gear);
    await waitFor(() => {
      const dialog = container.querySelector('.settings-dialog') as HTMLDialogElement;
      expect(dialog.hasAttribute('open')).toBe(true);
    });
  });
});

describe('Vault.svelte — defensive non-unlocked render', () => {
  it('renders nothing when sessionState is locked', () => {
    // Initial state is `locked`. App.svelte's router won't invoke
    // Vault from `locked`, but if it ever did, narrowing inside Vault
    // returns null and the component renders empty rather than crashing
    // on `manifest` access.
    const { container } = render(Vault);
    expect(container.querySelector('.vault')).toBeNull();
  });
});
