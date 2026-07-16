// D.1.8 — BlockRecipients banner: loads block_recipients on mount, renders a
// collapsed summary, expands to a per-recipient list, surfaces errors.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import {
  __setWriteGuardTestSeam,
  ReauthCancelled,
  resetReauthGuard
} from '../src/lib/writeGuard';

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));

import BlockRecipients from '../src/components/BlockRecipients.svelte';

const block = { blockUuidHex: 'deadbeef', blockName: 'Logins', createdAtMs: 0, lastModifiedMs: 0 };

describe('BlockRecipients', () => {
  beforeEach(() => invokeMock.mockReset());

  it('shows a collapsed summary then expands to the full list', async () => {
    invokeMock.mockResolvedValueOnce([
      { uuidHex: '00', kind: 'owner', displayName: null },
      { uuidHex: 'a1', kind: 'contact', displayName: 'Alice' },
      { uuidHex: 'a1b2c3d4e5f6', kind: 'unknown', displayName: null }
    ]);
    const { getByRole, getByText, queryByText } = render(BlockRecipients, { block });

    // Collapsed: summary names owner + contact + unknown count.
    await waitFor(() => expect(getByText(/Shared with:/)).toBeTruthy());
    expect(getByText(/You, Alice, \+1 unknown/)).toBeTruthy();
    // List rows not shown until expanded.
    expect(queryByText('Unknown contact (a1b2c3d4…)')).toBeNull();

    await fireEvent.click(getByRole('button', { name: /shared with/i }));
    expect(getByText('Unknown contact (a1b2c3d4…)')).toBeTruthy();
    expect(invokeMock).toHaveBeenCalledWith('block_recipients', { blockUuidHex: 'deadbeef' });
  });

  it('collapses the banner when the block prop changes', async () => {
    // First block: one named contact + one unknown row (to make expanded state observable).
    invokeMock.mockResolvedValueOnce([
      { uuidHex: '00', kind: 'owner', displayName: null },
      { uuidHex: 'bb', kind: 'unknown', displayName: null }
    ]);
    const block2 = { blockUuidHex: 'cafef00d', blockName: 'Cards', createdAtMs: 1, lastModifiedMs: 1 };
    // Second block returns a different recipient so we can prove the new data loaded.
    invokeMock.mockResolvedValueOnce([
      { uuidHex: 'cc', kind: 'contact', displayName: 'Bob' }
    ]);

    const { getByRole, queryByRole, rerender } = render(BlockRecipients, { block });

    // Wait for the first block to finish loading.
    await waitFor(() => expect(getByRole('button', { name: /shared with/i })).toBeTruthy());

    // Expand the banner.
    await fireEvent.click(getByRole('button', { name: /shared with/i }));
    // Confirm it is expanded: the toggle button now has aria-expanded=true.
    expect(getByRole('button', { name: /shared with/i }).getAttribute('aria-expanded')).toBe('true');

    // Switch to a different block.
    await rerender({ block: block2 });

    // Wait for the second block's data to arrive.
    await waitFor(() =>
      expect(getByRole('button', { name: /shared with/i }).textContent).toMatch(/Bob/)
    );

    // Banner must be collapsed again — aria-expanded should be false.
    expect(getByRole('button', { name: /shared with/i }).getAttribute('aria-expanded')).toBe('false');
    // The expanded list must not be in the DOM.
    expect(queryByRole('list')).toBeNull();
  });

  it('surfaces a typed error when the call rejects', async () => {
    invokeMock.mockRejectedValueOnce({ code: 'internal' });
    const { findByRole } = render(BlockRecipients, { block });
    const alert = await findByRole('alert');
    expect(alert.textContent).toMatch(/internal error/i);
  });

  it('revokes a non-owner recipient and reloads', async () => {
    invokeMock
      .mockResolvedValueOnce([
        { uuidHex: '00', kind: 'owner', displayName: null },
        { uuidHex: 'a1', kind: 'contact', displayName: 'Alice' }
      ]) // initial load
      .mockResolvedValueOnce(undefined) // revoke_block_from
      .mockResolvedValueOnce([{ uuidHex: '00', kind: 'owner', displayName: null }]); // reload

    const { getByRole, getByText } = render(BlockRecipients, { block });
    await waitFor(() => expect(getByText(/Shared with:/)).toBeTruthy());
    await fireEvent.click(getByRole('button', { name: /shared with/i })); // expand

    await fireEvent.click(getByRole('button', { name: /Revoke Alice/i })); // row ✕
    await fireEvent.click(getByRole('button', { name: 'Revoke' })); // confirm

    await waitFor(() =>
      expect(invokeMock).toHaveBeenCalledWith('revoke_block_from', {
        blockUuidHex: 'deadbeef',
        recipientUuidHex: 'a1'
      })
    );
    // The banner stays expanded after the reload (consistent with ContactRow),
    // so a follow-up revoke doesn't require re-expanding.
    await waitFor(() =>
      expect(getByRole('button', { name: /shared with/i }).getAttribute('aria-expanded')).toBe(
        'true'
      )
    );
  });

  it('surfaces a typed error when a revoke rejects (no mutation-path leniency)', async () => {
    invokeMock
      .mockResolvedValueOnce([
        { uuidHex: '00', kind: 'owner', displayName: null },
        { uuidHex: 'a1', kind: 'contact', displayName: 'Alice' }
      ]) // initial load
      .mockRejectedValueOnce({ code: 'recipient_not_present' }); // revoke_block_from fails

    const { getByRole, getByText, findByRole } = render(BlockRecipients, { block });
    await waitFor(() => expect(getByText(/Shared with:/)).toBeTruthy());
    await fireEvent.click(getByRole('button', { name: /shared with/i })); // expand
    await fireEvent.click(getByRole('button', { name: /Revoke Alice/i })); // row ✕
    await fireEvent.click(getByRole('button', { name: 'Revoke' })); // confirm

    // The typed error is surfaced, not swallowed or folded to an empty list.
    const alert = await findByRole('alert');
    expect(alert.textContent).toMatch(/no longer a recipient/i);
  });

  it('does not force-expand when the post-revoke reload fails', async () => {
    invokeMock
      .mockResolvedValueOnce([
        { uuidHex: '00', kind: 'owner', displayName: null },
        { uuidHex: 'a1', kind: 'contact', displayName: 'Alice' }
      ]) // initial load
      .mockResolvedValueOnce(undefined) // revoke_block_from succeeds
      .mockRejectedValueOnce({ code: 'internal' }); // reload fails

    const { getByRole, getByText, findByRole, queryByRole } = render(BlockRecipients, { block });
    await waitFor(() => expect(getByText(/Shared with:/)).toBeTruthy());
    await fireEvent.click(getByRole('button', { name: /shared with/i })); // expand
    await fireEvent.click(getByRole('button', { name: /Revoke Alice/i })); // row ✕
    await fireEvent.click(getByRole('button', { name: 'Revoke' })); // confirm

    // The reload error is surfaced; the banner is not force-expanded into the
    // error branch (no toggle/list rendered while an error is showing).
    const alert = await findByRole('alert');
    expect(alert.textContent).toMatch(/internal error/i);
    expect(queryByRole('button', { name: /shared with/i })).toBeNull();
  });

  it('renders no revoke control on the owner row', async () => {
    invokeMock.mockResolvedValueOnce([{ uuidHex: '00', kind: 'owner', displayName: null }]);
    const { getByRole, queryByRole, getByText } = render(BlockRecipients, { block });
    await waitFor(() => expect(getByText(/Shared with:/)).toBeTruthy());
    await fireEvent.click(getByRole('button', { name: /shared with/i }));
    expect(queryByRole('button', { name: /Revoke You/i })).toBeNull();
  });

  it('#180 — toggle aria-controls equals the expanded region id (uuid-derived)', async () => {
    invokeMock.mockResolvedValueOnce([{ uuidHex: '00', kind: 'owner', displayName: null }]);
    const { container, getByRole } = render(BlockRecipients, { block });
    const toggle = await waitFor(() => getByRole('button', { name: /shared with/i }));
    const controls = toggle.getAttribute('aria-controls');
    expect(controls).toBe(`recipients-${block.blockUuidHex}`);
    await fireEvent.click(toggle); // expand so the region renders
    const region = container.querySelector(`#${controls}`);
    expect(region).not.toBeNull();
  });
});

describe('BlockRecipients — revoke write-reauth gate', () => {
  beforeEach(() => invokeMock.mockReset());
  afterEach(() => resetReauthGuard());

  it('cancel: guard rejects ReauthCancelled → revoke_block_from NOT called, ConfirmDialog stays open', async () => {
    __setWriteGuardTestSeam({
      readSettings: () => ({ enabled: true, windowMs: 0 }),
      now: () => 0,
      biometricPrefEnabled: () => false,
      tryBiometric: () => Promise.resolve('unavailable' as const),
      prompt: () => Promise.reject(ReauthCancelled)
    });

    invokeMock.mockResolvedValueOnce([
      { uuidHex: '00', kind: 'owner', displayName: null },
      { uuidHex: 'a1', kind: 'contact', displayName: 'Alice' }
    ]); // initial load

    const { getByRole, getByText, container } = render(BlockRecipients, { block });
    await waitFor(() => expect(getByText(/Shared with:/)).toBeTruthy());
    await fireEvent.click(getByRole('button', { name: /shared with/i })); // expand
    await fireEvent.click(getByRole('button', { name: /Revoke Alice/i })); // row ✕
    await fireEvent.click(getByRole('button', { name: 'Revoke' })); // confirm

    // Guard cancelled → revoke_block_from must NOT have been called; dialog stays open.
    // Wait for any async tails to settle, then assert.
    await new Promise((r) => setTimeout(r, 50));
    expect(invokeMock.mock.calls.some(([c]) => c === 'revoke_block_from')).toBe(false);
    // ConfirmDialog must still be present
    expect(container.querySelector('.confirm-dialog__button--danger')).not.toBeNull();
  });

  it('happy: guard resolves → revoke_block_from called once', async () => {
    __setWriteGuardTestSeam({
      readSettings: () => ({ enabled: true, windowMs: 0 }),
      now: () => 0,
      biometricPrefEnabled: () => false,
      tryBiometric: () => Promise.resolve('unavailable' as const),
      prompt: () => Promise.resolve()
    });

    invokeMock
      .mockResolvedValueOnce([
        { uuidHex: '00', kind: 'owner', displayName: null },
        { uuidHex: 'a1', kind: 'contact', displayName: 'Alice' }
      ]) // initial load
      .mockResolvedValueOnce(undefined) // revoke_block_from
      .mockResolvedValueOnce([{ uuidHex: '00', kind: 'owner', displayName: null }]); // reload

    const { getByRole, getByText } = render(BlockRecipients, { block });
    await waitFor(() => expect(getByText(/Shared with:/)).toBeTruthy());
    await fireEvent.click(getByRole('button', { name: /shared with/i })); // expand
    await fireEvent.click(getByRole('button', { name: /Revoke Alice/i })); // row ✕
    await fireEvent.click(getByRole('button', { name: 'Revoke' })); // confirm

    await waitFor(() =>
      expect(invokeMock).toHaveBeenCalledWith('revoke_block_from', {
        blockUuidHex: 'deadbeef',
        recipientUuidHex: 'a1'
      })
    );
  });
});
