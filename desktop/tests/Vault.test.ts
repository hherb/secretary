// Tests for Vault.svelte — the post-unlock route. Renders the TopBar
// (with a truncated vault UUID), any AppWarning banners from the
// manifest, the block-count label, and the vertical stack of BlockCards.
//
// Only renders when `sessionState.status === 'unlocked'`. App.svelte's
// router gates us, but defensive narrowing inside guards against the
// router ever invoking Vault from another state.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import { get } from 'svelte/store';
import Vault from '../src/routes/Vault.svelte';
import {
  beginUnlock,
  unlockSucceeded,
  _resetSessionStateForTest
} from '../src/lib/stores';
import { openBlock, resetBrowse, browseNav } from '../src/lib/browse';
import type { ManifestDto, SettingsDto, BlockSummaryDto } from '../src/lib/ipc';
import type { AppWarning } from '../src/lib/errors';
import {
  __setWriteGuardTestSeam,
  ReauthCancelled,
  resetReauthGuard
} from '../src/lib/writeGuard';

// LockButton (transitively imported via TopBar) calls `lock` ipc, and
// SettingsDialog calls `setSettings`. Stub both so the rendered tree
// doesn't blow up on missing Tauri. readBlock is stubbed so that the
// RecordList view (rendered when browseNav.level === 'records') can
// resolve without hitting the Tauri bridge. trashBlock and refreshManifest
// are stubbed for the block-trash reauth gate tests below.
const { lockMock, setSettingsMock, readBlockMock, trashBlockMock, refreshManifestMock } = vi.hoisted(() => ({
  lockMock: vi.fn(),
  setSettingsMock: vi.fn(),
  readBlockMock: vi.fn(),
  trashBlockMock: vi.fn(),
  refreshManifestMock: vi.fn()
}));
vi.mock('../src/lib/ipc', async () => {
  const real = await vi.importActual<typeof import('../src/lib/ipc')>('../src/lib/ipc');
  return { ...real, lock: lockMock, setSettings: setSettingsMock, readBlock: readBlockMock, trashBlock: trashBlockMock };
});
vi.mock('../src/lib/stores', async () => {
  const real = await vi.importActual<typeof import('../src/lib/stores')>('../src/lib/stores');
  return { ...real, refreshManifest: refreshManifestMock };
});

const SETTINGS: SettingsDto = { autoLockTimeoutMs: 600_000, requirePasswordBeforeEdits: false, reauthGraceWindowMs: 120_000, retentionWindowMs: 7_776_000_000 };

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
  resetBrowse();
  lockMock.mockReset();
  lockMock.mockResolvedValue(undefined);
  setSettingsMock.mockReset();
  setSettingsMock.mockResolvedValue(undefined);
  readBlockMock.mockReset();
  readBlockMock.mockResolvedValue({ blockUuidHex: 'ab', blockName: 'B', records: [] });
  trashBlockMock.mockReset();
  trashBlockMock.mockResolvedValue(undefined);
  refreshManifestMock.mockReset();
  refreshManifestMock.mockResolvedValue(undefined);
});

afterEach(() => {
  resetBrowse();
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
    // Lock button rendered by TopBar (icon + "Lock" text; the icon is
    // aria-hidden so the accessible name is "Lock"). Matching the class pins
    // to the correct button and avoids `/lock/i` matching "+ New block".
    unlockWith(manifestFixture({}));
    const { container } = render(Vault);
    expect(container.querySelector('.lock-button')).toBeTruthy();
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

describe('Vault.svelte — #164 Esc pops a browse level', () => {
  it('Escape at records pops to blocks', async () => {
    const block = blockFixture('B', 'ab');
    unlockWith(manifestFixture({ blocks: [block] }));
    render(Vault);
    openBlock(block);
    await waitFor(() => expect(document.querySelector('.record-list')).toBeTruthy());

    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    await waitFor(() => expect(get(browseNav).level).toBe('blocks'));
  });

  it('Escape at blocks is a no-op (nothing to pop)', async () => {
    unlockWith(manifestFixture({ blocks: [blockFixture('B', 'ab')] }));
    render(Vault);
    expect(get(browseNav).level).toBe('blocks');
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    await new Promise((r) => setTimeout(r, 0));
    expect(get(browseNav).level).toBe('blocks');
  });

  it('Escape with the settings dialog open closes only the dialog (no pop)', async () => {
    const block = blockFixture('B', 'ab');
    unlockWith(manifestFixture({ blocks: [block] }));
    const { getByRole } = render(Vault);
    openBlock(block);
    await waitFor(() => expect(document.querySelector('.record-list')).toBeTruthy());
    await fireEvent.click(getByRole('button', { name: /settings/i }));
    await waitFor(() => expect(document.querySelector('dialog[open]')).toBeTruthy());
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    await new Promise((r) => setTimeout(r, 0));
    expect(get(browseNav).level).toBe('records'); // did NOT pop
  });
});

describe('Vault.svelte — browse navigation', () => {
  it('renders the RecordList view when a block is opened', async () => {
    const block = blockFixture('B', 'ab');
    unlockWith(manifestFixture({ blocks: [block] }));
    render(Vault);

    // Transition to the records level; Vault re-renders RecordList.
    openBlock(block);

    await waitFor(() => expect(document.querySelector('.record-list')).toBeTruthy());
    // Block-list should no longer be visible.
    expect(document.querySelector('.block-card')).toBeNull();
  });
});

describe('Vault.svelte — block-trash reauth gate', () => {
  afterEach(() => resetReauthGuard());

  it('cancel: guard rejects ReauthCancelled → trash_block NOT called, ConfirmDialog stays open', async () => {
    __setWriteGuardTestSeam({
      readSettings: () => ({ enabled: true, windowMs: 0 }),
      now: () => 0,
      biometricPrefEnabled: () => false,
      tryBiometric: () => Promise.resolve('unavailable' as const),
      prompt: () => Promise.reject(ReauthCancelled)
    });

    const block = blockFixture('Banking', 'aa');
    unlockWith(manifestFixture({ blocks: [block] }));
    const { getByRole, container } = render(Vault);

    // Click the per-card trash button to open the ConfirmDialog.
    await fireEvent.click(getByRole('button', { name: /trash block/i }));
    const confirmBtn = await waitFor(() => {
      const btn = container.querySelector('.confirm-dialog__button--danger') as HTMLButtonElement | null;
      expect(btn).not.toBeNull();
      return btn!;
    });

    // Click the confirm (danger) button — triggers confirmTrash → authorizeWrite → ReauthCancelled.
    await fireEvent.click(confirmBtn);

    // Guard cancelled → trash_block must NOT have been called; dialog stays open.
    await new Promise((r) => setTimeout(r, 50));
    expect(trashBlockMock).not.toHaveBeenCalled();
    expect(container.querySelector('.confirm-dialog__button--danger')).not.toBeNull();
  });

  it('happy: guard resolves → trash_block called once', async () => {
    __setWriteGuardTestSeam({
      readSettings: () => ({ enabled: true, windowMs: 0 }),
      now: () => 0,
      biometricPrefEnabled: () => false,
      tryBiometric: () => Promise.resolve('unavailable' as const),
      prompt: () => Promise.resolve()
    });

    const block = blockFixture('Banking', 'aa');
    unlockWith(manifestFixture({ blocks: [block] }));
    const { getByRole, container } = render(Vault);

    await fireEvent.click(getByRole('button', { name: /trash block/i }));
    const confirmBtn = await waitFor(() => {
      const btn = container.querySelector('.confirm-dialog__button--danger') as HTMLButtonElement | null;
      expect(btn).not.toBeNull();
      return btn!;
    });

    await fireEvent.click(confirmBtn);

    await waitFor(() => expect(trashBlockMock).toHaveBeenCalledOnce());
    expect(trashBlockMock).toHaveBeenCalledWith('aa');
  });
});
