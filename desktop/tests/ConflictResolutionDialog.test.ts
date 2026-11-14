import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import ConflictResolutionDialog from '../src/components/ConflictResolutionDialog.svelte';
import * as ipc from '../src/lib/ipc';
import {
  __setWriteGuardTestSeam,
  ReauthCancelled,
  resetReauthGuard
} from '../src/lib/writeGuard';

vi.mock('../src/lib/ipc', async (orig) => ({
  ...(await orig<typeof ipc>()),
  syncCommitDecisions: vi.fn()
}));
const mockCommit = vi.mocked(ipc.syncCommitDecisions);

const PASS_THROUGH_SEAM = {
  readSettings: () => ({ enabled: false, windowMs: 0 }),
  now: () => 0,
  biometricPrefEnabled: () => false,
  tryBiometric: () => Promise.resolve('unavailable' as const),
  prompt: () => Promise.resolve()
};
const CANCELLING_SEAM = {
  ...PASS_THROUGH_SEAM,
  readSettings: () => ({ enabled: true, windowMs: 0 }),
  prompt: () => Promise.reject(ReauthCancelled)
};

const veto = (id: string) => ({
  recordUuidHex: id,
  recordType: 'login',
  tags: ['work'],
  fieldNames: ['password'],
  localLastModMs: 1,
  peerTombstonedAtMs: 2,
  peerDeviceHex: 'ab'.repeat(16)
});

const baseProps = (over: Record<string, unknown> = {}) => ({
  vetoes: [veto('0a')],
  collisions: [] as { recordUuidHex: string; fieldNames: string[] }[],
  manifestHash: [1, 2, 3],
  onResolved: vi.fn(),
  onCancel: vi.fn(),
  ...over
});

function renderDialog(over: Record<string, unknown> = {}) {
  const props = baseProps(over);
  const utils = render(ConflictResolutionDialog, { props });
  return { ...utils, onResolved: props.onResolved, onCancel: props.onCancel };
}

describe('ConflictResolutionDialog.svelte', () => {
  beforeEach(() => {
    mockCommit.mockReset();
    __setWriteGuardTestSeam(PASS_THROUGH_SEAM);
  });
  afterEach(() => resetReauthGuard());

  it('Apply commits nothing when the re-auth prompt is cancelled', async () => {
    const prompt = vi.fn(() => Promise.reject(ReauthCancelled));
    __setWriteGuardTestSeam({ ...CANCELLING_SEAM, prompt });
    const { getByRole, queryByRole, onResolved } = renderDialog();
    await fireEvent.click(getByRole('button', { name: /apply & finish sync/i }));
    await waitFor(() => expect(prompt).toHaveBeenCalledTimes(1));
    await new Promise((resolve) => setTimeout(resolve, 0)); // let apply() run to its end
    expect(mockCommit).not.toHaveBeenCalled();
    expect(onResolved).not.toHaveBeenCalled();
    expect(queryByRole('alert')).toBeNull();
  });

  it('Apply shows a failed re-auth (not a cancel) inline and commits nothing', async () => {
    __setWriteGuardTestSeam({ ...CANCELLING_SEAM, prompt: () => Promise.reject({ code: 'internal' }) });
    const { getByRole, findByRole, onResolved } = renderDialog();
    await fireEvent.click(getByRole('button', { name: /apply & finish sync/i }));
    expect(await findByRole('alert')).toBeTruthy();
    expect(mockCommit).not.toHaveBeenCalled();
    expect(onResolved).not.toHaveBeenCalled();
  });

  it('Apply commits after the re-auth prompt is accepted', async () => {
    const prompt = vi.fn(() => Promise.resolve());
    __setWriteGuardTestSeam({ ...CANCELLING_SEAM, prompt });
    mockCommit.mockResolvedValueOnce({ kind: 'mergedClean' });
    const { getByRole, onResolved } = renderDialog();
    await fireEvent.click(getByRole('button', { name: /apply & finish sync/i }));
    await waitFor(() => expect(onResolved).toHaveBeenCalledWith({ kind: 'mergedClean' }));
    expect(prompt.mock.invocationCallOrder[0]).toBeLessThan(mockCommit.mock.invocationCallOrder[0]);
  });

  it('renders one card per veto showing the formatVetoSummary label', () => {
    const { getAllByText } = renderDialog();
    // formatVetoSummary -> "login · work"
    expect(getAllByText(/login · work/).length).toBe(1);
  });

  it('Apply commits keepLocal:true (default) then calls onResolved on success', async () => {
    mockCommit.mockResolvedValueOnce({ kind: 'mergedClean' });
    const { getByRole, onResolved } = renderDialog();
    await fireEvent.click(getByRole('button', { name: /apply & finish sync/i }));
    await waitFor(() =>
      expect(mockCommit).toHaveBeenCalledWith([{ recordUuidHex: '0a', keepLocal: true }], [1, 2, 3])
    );
    expect(onResolved).toHaveBeenCalledWith({ kind: 'mergedClean' });
  });

  it('renders an inline alert and stays open on failure, without resolving', async () => {
    mockCommit.mockRejectedValueOnce({ code: 'sync_decisions_incomplete' });
    const { getByRole, findByRole, onResolved } = renderDialog();
    await fireEvent.click(getByRole('button', { name: /apply & finish sync/i }));
    const alert = await findByRole('alert');
    expect(alert.textContent).toMatch(/couldn.t apply your choices/i);
    expect(onResolved).not.toHaveBeenCalled();
    // busy reset: the Apply button is enabled again for a retry
    const applyBtn = getByRole('button', { name: /apply & finish sync/i }) as HTMLButtonElement;
    expect(applyBtn.disabled).toBe(false);
  });

  it('toggling "Accept delete" sends keepLocal:false for that veto', async () => {
    mockCommit.mockResolvedValueOnce({ kind: 'mergedClean' });
    const { getByRole } = renderDialog();
    await fireEvent.click(getByRole('button', { name: /accept delete/i }));
    await fireEvent.click(getByRole('button', { name: /apply & finish sync/i }));
    await waitFor(() =>
      expect(mockCommit).toHaveBeenCalledWith([{ recordUuidHex: '0a', keepLocal: false }], [1, 2, 3])
    );
  });

  it('renders the collisions notice when non-empty and omits it when empty', () => {
    const empty = renderDialog();
    expect(empty.queryByText(/auto-merged/i)).toBeNull();
    empty.unmount();

    const { getByText } = renderDialog({
      collisions: [{ recordUuidHex: '0b', fieldNames: ['url'] }]
    });
    expect(getByText(/auto-merged/i)).toBeTruthy();
  });

  // #389: announce the dialog's title to screen readers on open.
  it('labels the dialog with its title via aria-labelledby (#389)', () => {
    const { container } = renderDialog();
    const dialog = container.querySelector('dialog') as HTMLDialogElement;
    const labelId = dialog.getAttribute('aria-labelledby');
    expect(labelId).toBeTruthy();
    const title = container.querySelector(`#${labelId}`);
    expect(title).not.toBeNull();
    expect(dialog.contains(title)).toBe(true);
    expect(title?.textContent).toBe('Resolve sync conflicts');
  });
});
