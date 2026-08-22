import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import RecordRow from '../src/components/RecordRow.svelte';
import type { RecordDto } from '../src/lib/ipc';

const REC: RecordDto = {
  recordUuidHex: 'cd', recordType: 'login', title: 'alice@example.test', subtitle: null,
  tags: ['work', 'bank'],
  createdAtMs: 1, lastModMs: 1_700_000_000_000, fieldCount: 4, fields: []
};

describe('RecordRow', () => {
  it('shows record type, field count, and tags', () => {
    // #526: the row's primary visible text is now the derived title, not the
    // record type — record type moved into the accessible name instead.
    //
    // #526 review (GUI pass): the field count is no longer VISIBLE text. It
    // was a flex sibling that took its natural width and squeezed the title
    // down to its ellipsis in a narrow pane, so it moved to the row's `title`
    // tooltip. Still reachable — it stays in the accessible name, and the
    // tooltip becomes the accessible description.
    const { getByText, getByRole } = render(RecordRow, { props: { record: REC, onClick: () => {} } });
    expect(getByRole('button', { name: /login record/ })).toBeTruthy();
    expect(getByRole('button', { name: /4 fields/ })).toBeTruthy();
    expect(getByText('work')).toBeTruthy();
  });

  it('keeps the title as the row’s only unbounded text, with meta in a tooltip', () => {
    // The regression this pins: "Localmail" rendering as "Lo…" because the
    // metadata sat beside it in a horizontal flex row and would not shrink.
    const { getByRole, queryByText } = render(RecordRow, {
      props: { record: REC, onClick: () => {} }
    });
    const row = getByRole('button');
    expect(row.getAttribute('title')).toMatch(/4 fields · modified /);
    // The count must NOT be its own visible text node any more; if it comes
    // back as one, it is competing with the title for width again.
    expect(queryByText(/^4 fields/)).toBeNull();
    expect(queryByText('alice@example.test')).toBeTruthy();
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

describe('RecordRow — derived labels (#526)', () => {
  it('renders the derived title as the primary text', () => {
    const record = { ...REC, title: 'alice@example.test', subtitle: 'url: https://bank.test' };
    const { getByText } = render(RecordRow, { props: { record, onClick: () => {} } });
    expect(getByText('alice@example.test')).toBeTruthy();
  });

  it('renders the subtitle when present', () => {
    const record = { ...REC, title: 'Bank', subtitle: 'username: alice' };
    const { getByText } = render(RecordRow, { props: { record, onClick: () => {} } });
    expect(getByText('username: alice')).toBeTruthy();
  });

  it('renders no subtitle element when the record has none', () => {
    const record = { ...REC, title: 'Bank', subtitle: null };
    const { container } = render(RecordRow, { props: { record, onClick: () => {} } });
    expect(container.querySelector('.record-row__subtitle')).toBeNull();
  });

  it('puts the title in the aria-label so rows are distinguishable by ear', () => {
    const record = { ...REC, title: 'alice@example.test', subtitle: null };
    const { getByRole } = render(RecordRow, { props: { record, onClick: () => {} } });
    expect(getByRole('button', { name: /alice@example\.test/ })).toBeTruthy();
  });
});

describe('RecordRow — selection and freezing (#526)', () => {
  it('sets aria-current when selected', () => {
    const { getByRole } = render(RecordRow, {
      props: { record: REC, onClick: () => {}, selected: true }
    });
    expect(getByRole('button', { name: new RegExp(REC.title) }).getAttribute('aria-current')).toBe('true');
  });

  it('disables the row when frozen', () => {
    const { getByRole } = render(RecordRow, {
      props: { record: REC, onClick: () => {}, frozen: true }
    });
    expect(
      (getByRole('button', { name: new RegExp(REC.title) }) as HTMLButtonElement).disabled
    ).toBe(true);
  });

  it('does not fire onClick when frozen', async () => {
    const onClick = vi.fn();
    const { getByRole } = render(RecordRow, {
      props: { record: REC, onClick, frozen: true }
    });
    await fireEvent.click(getByRole('button', { name: new RegExp(REC.title) }));
    expect(onClick).not.toHaveBeenCalled();
  });

  it('hides the row actions when frozen so an edit cannot be interrupted', () => {
    const { queryByRole } = render(RecordRow, {
      props: { record: REC, onClick: () => {}, onDelete: () => {}, frozen: true }
    });
    expect(queryByRole('button', { name: /delete record/i })).toBeNull();
  });

  it('shows the row actions when not frozen', () => {
    const { getByRole } = render(RecordRow, {
      props: { record: REC, onClick: () => {}, onDelete: () => {}, frozen: false }
    });
    expect(getByRole('button', { name: /delete record/i })).toBeTruthy();
  });
});
