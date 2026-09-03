import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import { REVEAL_AUTO_HIDE_MS, CLIPBOARD_CLEAR_MS } from '../src/lib/constants';

// Audit DT-2: copy/clear go through the Rust `copy_secret_text` /
// `clear_clipboard` commands (OS concealment flags), never the webview
// clipboard plugin — so the seam under test is `invoke`. Reveal and copy are
// sequential `invoke` calls, so per-call `mockResolvedValueOnce` ordering is
// reveal first, then copy.
const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));

import FieldRow from '../src/components/FieldRow.svelte';
import type { FieldMetaDto } from '../src/lib/ipc';

const FIELD: FieldMetaDto = { name: 'password', lastModMs: 2, isText: true, isBytes: false };
const BLOCK_HEX = 'ab';
const REC_HEX = 'cd';

const copyCalls = () => invokeMock.mock.calls.filter((c) => c[0] === 'copy_secret_text');
const clearCalls = () => invokeMock.mock.calls.filter((c) => c[0] === 'clear_clipboard');

describe('FieldRow', () => {
  beforeEach(() => {
    invokeMock.mockReset();
  });

  it('is masked initially and reveals plaintext on click', async () => {
    invokeMock.mockResolvedValueOnce({ isText: true, value: 'hunter2' });
    const { getByText, getByLabelText, queryByText } =
      render(FieldRow, { props: { blockUuidHex: BLOCK_HEX, recordUuidHex: REC_HEX, field: FIELD } });
    expect(queryByText('hunter2')).toBeNull();
    await fireEvent.click(getByLabelText(/reveal password/i));
    await waitFor(() => expect(getByText('hunter2')).toBeTruthy());
    expect(invokeMock).toHaveBeenCalledWith('reveal_field',
      { blockUuidHex: BLOCK_HEX, recordUuidHex: REC_HEX, fieldName: 'password' });
  });

  it('re-masks on the mask button', async () => {
    invokeMock.mockResolvedValueOnce({ isText: true, value: 'hunter2' });
    const { getByText, getByLabelText, queryByText } =
      render(FieldRow, { props: { blockUuidHex: BLOCK_HEX, recordUuidHex: REC_HEX, field: FIELD } });
    await fireEvent.click(getByLabelText(/reveal password/i));
    await waitFor(() => expect(getByText('hunter2')).toBeTruthy());
    await fireEvent.click(getByLabelText(/hide password/i));
    expect(queryByText('hunter2')).toBeNull();
  });

  it('copy writes the revealed value through the Rust concealed-clipboard command', async () => {
    invokeMock.mockResolvedValueOnce({ isText: true, value: 'hunter2' });
    const { getByLabelText } =
      render(FieldRow, { props: { blockUuidHex: BLOCK_HEX, recordUuidHex: REC_HEX, field: FIELD } });
    await fireEvent.click(getByLabelText(/reveal password/i));
    await fireEvent.click(getByLabelText(/copy password/i));
    await waitFor(() =>
      expect(invokeMock).toHaveBeenCalledWith('copy_secret_text', { text: 'hunter2' }));
  });

  it('auto-hides the revealed value after REVEAL_AUTO_HIDE_MS', async () => {
    vi.useFakeTimers();
    try {
      invokeMock.mockResolvedValueOnce({ isText: true, value: 'hunter2' });
      const { getByLabelText, queryByText } =
        render(FieldRow, { props: { blockUuidHex: BLOCK_HEX, recordUuidHex: REC_HEX, field: FIELD } });
      await fireEvent.click(getByLabelText(/reveal password/i));
      await vi.advanceTimersByTimeAsync(0); // flush the revealField promise
      expect(queryByText('hunter2')).toBeTruthy();
      await vi.advanceTimersByTimeAsync(REVEAL_AUTO_HIDE_MS);
      expect(queryByText('hunter2')).toBeNull(); // auto-re-masked
    } finally {
      vi.useRealTimers();
    }
  });

  it('clears the clipboard after CLIPBOARD_CLEAR_MS', async () => {
    vi.useFakeTimers();
    try {
      invokeMock.mockResolvedValueOnce({ isText: true, value: 'hunter2' });
      const { getByLabelText } =
        render(FieldRow, { props: { blockUuidHex: BLOCK_HEX, recordUuidHex: REC_HEX, field: FIELD } });
      await fireEvent.click(getByLabelText(/reveal password/i));
      await vi.advanceTimersByTimeAsync(0);
      await fireEvent.click(getByLabelText(/copy password/i));
      await vi.advanceTimersByTimeAsync(0); // flush the copy promise
      expect(copyCalls()).toHaveLength(1);
      expect(clearCalls()).toHaveLength(0);
      await vi.advanceTimersByTimeAsync(CLIPBOARD_CLEAR_MS);
      expect(clearCalls()).toHaveLength(1); // best-effort clear fired
    } finally {
      vi.useRealTimers();
    }
  });

  // Security regression: a copied secret must not outlive the view (spec §7).
  // On unmount (navigate away / vault lock) with a clear still pending, the
  // clipboard must be cleared NOW, not merely have its timer cancelled.
  it('clears the clipboard immediately on unmount when a clear is pending', async () => {
    vi.useFakeTimers();
    try {
      invokeMock.mockResolvedValueOnce({ isText: true, value: 'hunter2' });
      const { getByLabelText, unmount } =
        render(FieldRow, { props: { blockUuidHex: BLOCK_HEX, recordUuidHex: REC_HEX, field: FIELD } });
      await fireEvent.click(getByLabelText(/reveal password/i));
      await vi.advanceTimersByTimeAsync(0); // flush reveal
      await fireEvent.click(getByLabelText(/copy password/i));
      await vi.advanceTimersByTimeAsync(0); // flush copy + schedule clear
      expect(copyCalls()).toHaveLength(1);
      expect(clearCalls()).toHaveLength(0);
      unmount(); // lock/navigate teardown, well before CLIPBOARD_CLEAR_MS elapses
      expect(clearCalls()).toHaveLength(1); // cleared eagerly, not stranded
    } finally {
      vi.useRealTimers();
    }
  });

  it('does not touch the clipboard on unmount when nothing was copied', async () => {
    vi.useFakeTimers();
    try {
      invokeMock.mockResolvedValueOnce({ isText: true, value: 'hunter2' });
      const { getByLabelText, unmount } =
        render(FieldRow, { props: { blockUuidHex: BLOCK_HEX, recordUuidHex: REC_HEX, field: FIELD } });
      await fireEvent.click(getByLabelText(/reveal password/i)); // reveal but never copy
      await vi.advanceTimersByTimeAsync(0);
      unmount();
      expect(copyCalls()).toHaveLength(0);
      expect(clearCalls()).toHaveLength(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it('surfaces a failure and schedules no clear when the clipboard write rejects', async () => {
    vi.useFakeTimers();
    try {
      invokeMock
        .mockResolvedValueOnce({ isText: true, value: 'hunter2' }) // reveal_field
        .mockRejectedValueOnce(new Error('clipboard busy')); // copy_secret_text
      const { getByLabelText, queryByText } =
        render(FieldRow, { props: { blockUuidHex: BLOCK_HEX, recordUuidHex: REC_HEX, field: FIELD } });
      await fireEvent.click(getByLabelText(/reveal password/i));
      await vi.advanceTimersByTimeAsync(0);
      await fireEvent.click(getByLabelText(/copy password/i));
      await vi.advanceTimersByTimeAsync(0); // flush the rejected copy promise
      expect(queryByText(/Couldn't copy/i)).toBeTruthy();
      await vi.advanceTimersByTimeAsync(CLIPBOARD_CLEAR_MS);
      expect(clearCalls()).toHaveLength(0); // failed copy schedules no clear
    } finally {
      vi.useRealTimers();
    }
  });
});
