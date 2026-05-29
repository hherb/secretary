import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import { REVEAL_AUTO_HIDE_MS, CLIPBOARD_CLEAR_MS } from '../src/lib/constants';

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));
const { writeTextMock } = vi.hoisted(() => ({ writeTextMock: vi.fn() }));
vi.mock('@tauri-apps/plugin-clipboard-manager', () => ({ writeText: writeTextMock }));

import FieldRow from '../src/components/FieldRow.svelte';
import type { FieldMetaDto } from '../src/lib/ipc';

const FIELD: FieldMetaDto = { name: 'password', lastModMs: 2, isText: true, isBytes: false };
const BLOCK_HEX = 'ab';
const REC_HEX = 'cd';

describe('FieldRow', () => {
  beforeEach(() => { invokeMock.mockReset(); writeTextMock.mockReset(); });

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

  it('copy writes the revealed value to the clipboard', async () => {
    invokeMock.mockResolvedValueOnce({ isText: true, value: 'hunter2' });
    writeTextMock.mockResolvedValue(undefined);
    const { getByLabelText } =
      render(FieldRow, { props: { blockUuidHex: BLOCK_HEX, recordUuidHex: REC_HEX, field: FIELD } });
    await fireEvent.click(getByLabelText(/reveal password/i));
    await fireEvent.click(getByLabelText(/copy password/i));
    await waitFor(() => expect(writeTextMock).toHaveBeenCalledWith('hunter2'));
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
      writeTextMock.mockResolvedValue(undefined);
      const { getByLabelText } =
        render(FieldRow, { props: { blockUuidHex: BLOCK_HEX, recordUuidHex: REC_HEX, field: FIELD } });
      await fireEvent.click(getByLabelText(/reveal password/i));
      await vi.advanceTimersByTimeAsync(0);
      await fireEvent.click(getByLabelText(/copy password/i));
      await vi.advanceTimersByTimeAsync(0); // flush the writeText(value) promise
      expect(writeTextMock).toHaveBeenCalledWith('hunter2');
      writeTextMock.mockClear();
      await vi.advanceTimersByTimeAsync(CLIPBOARD_CLEAR_MS);
      expect(writeTextMock).toHaveBeenCalledWith(''); // best-effort clear fired
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
      writeTextMock.mockResolvedValue(undefined);
      const { getByLabelText, unmount } =
        render(FieldRow, { props: { blockUuidHex: BLOCK_HEX, recordUuidHex: REC_HEX, field: FIELD } });
      await fireEvent.click(getByLabelText(/reveal password/i));
      await vi.advanceTimersByTimeAsync(0); // flush reveal
      await fireEvent.click(getByLabelText(/copy password/i));
      await vi.advanceTimersByTimeAsync(0); // flush writeText(value) + schedule clear
      expect(writeTextMock).toHaveBeenCalledWith('hunter2');
      writeTextMock.mockClear();
      unmount(); // lock/navigate teardown, well before CLIPBOARD_CLEAR_MS elapses
      expect(writeTextMock).toHaveBeenCalledWith(''); // cleared eagerly, not stranded
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
      expect(writeTextMock).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it('surfaces a failure and schedules no clear when the clipboard write rejects', async () => {
    vi.useFakeTimers();
    try {
      invokeMock.mockResolvedValueOnce({ isText: true, value: 'hunter2' });
      writeTextMock.mockRejectedValue(new Error('clipboard busy'));
      const { getByLabelText, queryByText } =
        render(FieldRow, { props: { blockUuidHex: BLOCK_HEX, recordUuidHex: REC_HEX, field: FIELD } });
      await fireEvent.click(getByLabelText(/reveal password/i));
      await vi.advanceTimersByTimeAsync(0);
      await fireEvent.click(getByLabelText(/copy password/i));
      await vi.advanceTimersByTimeAsync(0); // flush the rejected writeText promise
      expect(queryByText(/Couldn't copy/i)).toBeTruthy();
      writeTextMock.mockClear();
      await vi.advanceTimersByTimeAsync(CLIPBOARD_CLEAR_MS);
      expect(writeTextMock).not.toHaveBeenCalled(); // failed copy schedules no clear
    } finally {
      vi.useRealTimers();
    }
  });
});
