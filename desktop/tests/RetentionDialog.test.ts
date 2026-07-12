// Tests for RetentionDialog.svelte — the two-step "run retention now"
// dialog reached from Settings. Step 1: preview which trashed blocks are
// past the retention window (previewRetention() on mount). Step 2: an
// irreversible bulk purge gated by the same authorizeWrite chokepoint as
// every other write, then runRetention() -> refreshManifest() -> onClose().
//
// Mirrors ConfirmDialog.test.ts (native <dialog> lifecycle) and
// TrashView.test.ts (load/error/empty state shape).

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import { MS_PER_DAY } from '../src/lib/constants';
import type { RetentionPreviewDto } from '../src/lib/ipc';

const { previewRetentionMock, runRetentionMock, authorizeWriteMock, refreshManifestMock, reauthCancelledSymbol } =
  vi.hoisted(() => ({
    previewRetentionMock: vi.fn(),
    runRetentionMock: vi.fn(),
    authorizeWriteMock: vi.fn(),
    refreshManifestMock: vi.fn(),
    reauthCancelledSymbol: Symbol('ReauthCancelled')
  }));

vi.mock('../src/lib/ipc', async () => {
  const real = await vi.importActual<typeof import('../src/lib/ipc')>('../src/lib/ipc');
  return { ...real, previewRetention: previewRetentionMock, runRetention: runRetentionMock };
});

vi.mock('../src/lib/stores', () => ({ refreshManifest: refreshManifestMock }));

vi.mock('../src/lib/writeGuard', () => ({
  authorizeWrite: authorizeWriteMock,
  ReauthCancelled: reauthCancelledSymbol
}));

import RetentionDialog from '../src/components/delete/RetentionDialog.svelte';

const WINDOW_MS = 30 * MS_PER_DAY;

function nonEmptyPreview(): RetentionPreviewDto {
  return {
    entries: [{ blockUuidHex: 'ab', tombstonedAtMs: 0, ageMs: 45 * MS_PER_DAY }],
    windowMs: WINDOW_MS
  };
}

function emptyPreview(): RetentionPreviewDto {
  return { entries: [], windowMs: WINDOW_MS };
}

describe('RetentionDialog.svelte', () => {
  beforeEach(() => {
    previewRetentionMock.mockReset();
    runRetentionMock.mockReset();
    authorizeWriteMock.mockReset();
    authorizeWriteMock.mockResolvedValue(undefined);
    refreshManifestMock.mockReset();
    refreshManifestMock.mockResolvedValue(undefined);
  });

  it('calls previewRetention on mount and renders the resolved summary', async () => {
    previewRetentionMock.mockResolvedValueOnce(nonEmptyPreview());
    const { findByText } = render(RetentionDialog, { props: { onClose: vi.fn() } });

    expect(await findByText(/1 item trashed more than 30 days ago/i)).toBeTruthy();
    expect(previewRetentionMock).toHaveBeenCalledTimes(1);
  });

  it('empty preview renders the "No trashed items" text and no Purge button', async () => {
    previewRetentionMock.mockResolvedValueOnce(emptyPreview());
    const { findByText, queryByRole } = render(RetentionDialog, { props: { onClose: vi.fn() } });

    expect(await findByText(/no trashed items/i)).toBeTruthy();
    const purgeButton = queryByRole('button', { name: /purge/i });
    expect(purgeButton === null || (purgeButton as HTMLButtonElement).disabled).toBe(true);
  });

  it('non-empty: clicking Purge calls authorizeWrite, then runRetention, then refreshManifest, then onClose', async () => {
    previewRetentionMock.mockResolvedValueOnce(nonEmptyPreview());
    runRetentionMock.mockResolvedValueOnce({
      purgedCount: 1,
      sharedCount: 0,
      ownerOnlyCount: 1,
      unknownCount: 0,
      filesRemoved: 1,
      filesFailed: 0,
      windowMs: WINDOW_MS
    });
    const onClose = vi.fn();
    const { findByRole } = render(RetentionDialog, { props: { onClose } });

    const purgeButton = await findByRole('button', { name: /purge/i });
    await fireEvent.click(purgeButton);

    await waitFor(() => expect(onClose).toHaveBeenCalledTimes(1));

    expect(authorizeWriteMock).toHaveBeenCalledTimes(1);
    expect(runRetentionMock).toHaveBeenCalledTimes(1);
    expect(refreshManifestMock).toHaveBeenCalledTimes(1);

    const authorizeOrder = authorizeWriteMock.mock.invocationCallOrder[0];
    const runOrder = runRetentionMock.mock.invocationCallOrder[0];
    const refreshOrder = refreshManifestMock.mock.invocationCallOrder[0];
    expect(authorizeOrder).toBeLessThan(runOrder);
    expect(runOrder).toBeLessThan(refreshOrder);
  });

  it('authorizeWrite rejecting with ReauthCancelled: no runRetention, dialog stays open', async () => {
    previewRetentionMock.mockResolvedValueOnce(nonEmptyPreview());
    // mockRejectedValueOnce (not persistent mockRejectedValue): a persistent
    // rejection would spuriously fail any later test whose click handler
    // catches the error, and leaks unresolved-promise state across tests.
    authorizeWriteMock.mockRejectedValueOnce(reauthCancelledSymbol);
    const onClose = vi.fn();
    const { findByRole } = render(RetentionDialog, { props: { onClose } });

    const purgeButton = await findByRole('button', { name: /purge/i });
    await fireEvent.click(purgeButton);

    await waitFor(() => expect(authorizeWriteMock).toHaveBeenCalledTimes(1));
    expect(runRetentionMock).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
  });

  it('runRetention rejecting with a typed error renders userMessageFor text; no onClose', async () => {
    previewRetentionMock.mockResolvedValueOnce(nonEmptyPreview());
    // mockRejectedValueOnce per the same hygiene note as above.
    runRetentionMock.mockRejectedValueOnce({ code: 'io' });
    const onClose = vi.fn();
    const { findByRole, findByText } = render(RetentionDialog, { props: { onClose } });

    const purgeButton = await findByRole('button', { name: /purge/i });
    await fireEvent.click(purgeButton);

    expect(await findByText(/filesystem error/i)).toBeTruthy();
    expect(onClose).not.toHaveBeenCalled();
  });

  it('passes a formatted purge notice to onClose after a successful run', async () => {
    previewRetentionMock.mockResolvedValue({ entries: [{ blockUuidHex: 'ab', tombstonedAtMs: 0, ageMs: 100 * MS_PER_DAY }], windowMs: 90 * MS_PER_DAY });
    runRetentionMock.mockResolvedValueOnce({
      purgedCount: 3, sharedCount: 0, ownerOnlyCount: 3, unknownCount: 0, filesRemoved: 3, filesFailed: 0, windowMs: 90 * MS_PER_DAY
    });
    const onClose = vi.fn();
    const { findByRole } = render(RetentionDialog, { props: { onClose } });
    const purge = await findByRole('button', { name: /purge \d+ items/i });
    await fireEvent.click(purge);
    await waitFor(() => expect(onClose).toHaveBeenCalledWith({ text: 'Purged 3 items', severity: 'success' }));
  });
});
