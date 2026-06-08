import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import ConflictResolutionDialog from '../src/components/ConflictResolutionDialog.svelte';
import * as ipc from '../src/lib/ipc';

vi.mock('../src/lib/ipc', async (orig) => ({
  ...(await orig<typeof ipc>()),
  syncCommitDecisions: vi.fn()
}));
const mockCommit = vi.mocked(ipc.syncCommitDecisions);

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
  password: 'pw',
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
  beforeEach(() => mockCommit.mockReset());

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
      expect(mockCommit).toHaveBeenCalledWith('pw', [{ recordUuidHex: '0a', keepLocal: true }], [1, 2, 3])
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
      expect(mockCommit).toHaveBeenCalledWith('pw', [{ recordUuidHex: '0a', keepLocal: false }], [1, 2, 3])
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
});
