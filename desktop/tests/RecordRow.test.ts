import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import RecordRow from '../src/components/RecordRow.svelte';
import type { RecordDto } from '../src/lib/ipc';

const REC: RecordDto = {
  recordUuidHex: 'cd', recordType: 'login', tags: ['work', 'bank'],
  createdAtMs: 1, lastModMs: 1_700_000_000_000, fieldCount: 4, fields: []
};

describe('RecordRow', () => {
  it('shows record type, field count, and tags', () => {
    const { getByText } = render(RecordRow, { props: { record: REC, onClick: () => {} } });
    expect(getByText('login')).toBeTruthy();
    expect(getByText(/4 fields/)).toBeTruthy();
    expect(getByText('work')).toBeTruthy();
  });

  it('calls onClick with the record', async () => {
    const onClick = vi.fn();
    const { getByRole } = render(RecordRow, { props: { record: REC, onClick } });
    await fireEvent.click(getByRole('button'));
    expect(onClick).toHaveBeenCalledWith(REC);
  });

  it('shows a "no recoverable contents" hint for a contentless tombstone', () => {
    const rec: RecordDto = { ...REC, tombstoned: true, fieldCount: 0 };
    const { getByText, getByRole } = render(RecordRow, { props: { record: rec, onClick: () => {} } });
    expect(getByText(/no recoverable contents/i)).toBeTruthy();
    // The main row button folds the hint into its accessible name.
    expect(getByRole('button', { name: /no recoverable contents/i })).toBeTruthy();
  });

  it('shows no hint for a tombstone that still has fields', () => {
    const rec: RecordDto = { ...REC, tombstoned: true, fieldCount: 4 };
    const { queryByText } = render(RecordRow, { props: { record: rec, onClick: () => {} } });
    expect(queryByText(/no recoverable contents/i)).toBeNull();
  });

  it('shows no hint for a live record', () => {
    const { queryByText } = render(RecordRow, { props: { record: REC, onClick: () => {} } });
    expect(queryByText(/no recoverable contents/i)).toBeNull();
  });
});
