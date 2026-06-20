import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import RecordRow from '../src/components/RecordRow.svelte';

const live = { recordUuidHex: 'r1', recordType: 'login', tags: [], createdAtMs: 1, lastModMs: 1, fieldCount: 1, fields: [], tombstoned: false };
const dead = { ...live, recordUuidHex: 'r2', tombstoned: true };

describe('RecordRow move action', () => {
  it('shows Move on a live row and fires onMove', async () => {
    const onMove = vi.fn();
    const { getByRole } = render(RecordRow, { props: { record: live, onClick: vi.fn(), onMove } });
    await fireEvent.click(getByRole('button', { name: /move record/i }));
    expect(onMove).toHaveBeenCalledWith(live);
  });

  it('omits Move on a tombstoned row', () => {
    const { queryByRole } = render(RecordRow, { props: { record: dead, onClick: vi.fn(), onMove: vi.fn() } });
    expect(queryByRole('button', { name: /move record/i })).toBeNull();
  });
});
