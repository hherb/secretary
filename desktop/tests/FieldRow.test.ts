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
});
