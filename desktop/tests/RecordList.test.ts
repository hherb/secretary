import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, waitFor, fireEvent } from '@testing-library/svelte';
import { get } from 'svelte/store';

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));

import RecordList from '../src/components/RecordList.svelte';
import type { BlockSummaryDto, RecordDto } from '../src/lib/ipc';
import { browseNav, resetBrowse } from '../src/lib/browse';

const BLOCK: BlockSummaryDto = { blockUuidHex: 'ab', blockName: 'Personal logins', createdAtMs: 1, lastModifiedMs: 2 };

/** Answer both IPC calls that RecordList fires on mount: read_block (records)
 *  and block_recipients (banner). Tests that only care about one can pass an
 *  empty override for the other. Unknown commands resolve to null so that
 *  any cleanup-phase stale calls don't throw and pollute the next test.
 *
 *  `records` is typed `RecordDto[]` (not `unknown[]`) deliberately (#526):
 *  an `unknown[]` fixture here previously bypassed RecordDto's required
 *  `title`/`subtitle` fields entirely, so svelte-check stayed green while
 *  a row rendered `aria-label="undefined, login record, 2 fields"` at
 *  runtime. A real type annotation makes the next such drift a
 *  type-checker error instead of a silent `undefined` in the DOM. */
function bothCalls(
  records: RecordDto[],
  recipients: unknown[] = [{ uuidHex: '00', kind: 'owner', displayName: null }]
) {
  invokeMock.mockImplementation((cmd: string) => {
    if (cmd === 'read_block') return Promise.resolve({ records });
    if (cmd === 'block_recipients') return Promise.resolve(recipients);
    return Promise.resolve(null);
  });
}

describe('RecordList', () => {
  beforeEach(() => {
    invokeMock.mockReset();
    resetBrowse();
  });

  it('fetches read_block on mount and renders a row per record', async () => {
    bothCalls([
      {
        recordUuidHex: 'cd', recordType: 'login', title: 'Acme Corp login', subtitle: 'alice@example.test',
        tags: ['work'], createdAtMs: 1, lastModMs: 2, fieldCount: 2, fields: []
      }
    ]);
    const { getByText } = render(RecordList, { props: { block: BLOCK, blockCount: 2 } });
    // Assert on the record's title — RecordRow renders it directly, unlike
    // recordType, which never appears as its own text node (only folded
    // into the row's composed aria-label). A placeholder like 'x' would
    // pass even if the title wiring silently broke, so this uses a
    // realistic title distinct from the block name / record type.
    await waitFor(() => expect(getByText('Acme Corp login')).toBeTruthy());
    expect(invokeMock).toHaveBeenCalledWith('read_block', { blockUuidHex: 'ab', includeDeleted: false });
  });

  it('renders an empty-state when the block has no records', async () => {
    bothCalls([]);
    const { getByText } = render(RecordList, { props: { block: BLOCK, blockCount: 2 } });
    await waitFor(() => expect(getByText(/No records/i)).toBeTruthy());
  });

  it('shows the typed error message when read_block rejects', async () => {
    // Only read_block rejects; block_recipients still resolves so its error
    // doesn't clobber the record-list error we are asserting against.
    invokeMock.mockImplementation((cmd: string) => {
      if (cmd === 'read_block')
        return Promise.reject({ code: 'block_not_found', block_uuid_hex: 'ab' });
      if (cmd === 'block_recipients')
        return Promise.resolve([{ uuidHex: '00', kind: 'owner', displayName: null }]);
      return Promise.resolve(null);
    });
    const { findByRole } = render(RecordList, { props: { block: BLOCK, blockCount: 2 } });
    const alert = await findByRole('alert');
    expect(alert.textContent).toMatch(/Block not found/i);
  });

  it('mounts the Shared-with banner for the block', async () => {
    // readBlock (records) + block_recipients (banner) both fire on mount.
    invokeMock.mockImplementation((cmd: string) => {
      if (cmd === 'read_block') return Promise.resolve({ records: [] });
      if (cmd === 'block_recipients')
        return Promise.resolve([{ uuidHex: '00', kind: 'owner', displayName: null }]);
      return Promise.resolve(null);
    });
    const { getByText } = render(RecordList, {
      block: { blockUuidHex: 'deadbeef', blockName: 'Logins', lastModifiedMs: 0, createdAtMs: 0 },
      blockCount: 2
    });
    await waitFor(() => expect(getByText(/Shared with:/)).toBeTruthy());
    expect(invokeMock).toHaveBeenCalledWith('block_recipients', { blockUuidHex: 'deadbeef' });
  });

  // ---- the freeze contract (#526 review) ----
  //
  // With no dirty-tracking in this frontend, navigating away from an open
  // editor discards the draft silently. `frozen` is what stops a stray click
  // doing that — but only the ROWS were tested, and "+ Add record" (the one
  // control here that navigates, and so the one that can destroy the draft)
  // had the `disabled` attribute alone, with no in-handler guard and no test
  // touching it at all.

  it('disables every control it owns while an editor is open', async () => {
    bothCalls([]);
    const { getByRole, getByLabelText } = render(RecordList, {
      props: { block: BLOCK, blockCount: 2, frozen: true }
    });
    await waitFor(() => expect(getByRole('button', { name: /add record/i })).toBeTruthy());

    // The attribute, asserted separately from behaviour: an in-handler guard
    // alone still leaves the control focusable and activatable by keyboard.
    expect((getByRole('button', { name: /add record/i }) as HTMLButtonElement).disabled).toBe(true);
    expect((getByLabelText(/show deleted/i) as HTMLInputElement).disabled).toBe(true);
    await waitFor(() =>
      expect((getByRole('button', { name: /shared with/i }) as HTMLButtonElement).disabled).toBe(true)
    );
  });

  it('leaves those controls interactive when no editor is open', async () => {
    bothCalls([]);
    const { getByRole, getByLabelText } = render(RecordList, {
      props: { block: BLOCK, blockCount: 2, frozen: false }
    });
    await waitFor(() => expect(getByRole('button', { name: /add record/i })).toBeTruthy());
    expect((getByRole('button', { name: /add record/i }) as HTMLButtonElement).disabled).toBe(false);
    expect((getByLabelText(/show deleted/i) as HTMLInputElement).disabled).toBe(false);
  });

  it('a click on a frozen "+ Add record" does not navigate', async () => {
    // The behavioural half. `disabled` already blocks a real user click, so
    // this pins the in-handler guard that backs it up — the belt-and-braces
    // every sibling frozen control already had.
    bothCalls([]);
    const { getByRole } = render(RecordList, {
      props: { block: BLOCK, blockCount: 2, frozen: true }
    });
    const add = await waitFor(() => getByRole('button', { name: /add record/i }));
    const before = get(browseNav).level;
    await fireEvent.click(add);
    expect(get(browseNav).level).toBe(before);
  });
});
