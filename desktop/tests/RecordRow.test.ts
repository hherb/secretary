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
});
