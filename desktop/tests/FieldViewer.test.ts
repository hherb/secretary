import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));
vi.mock('@tauri-apps/plugin-clipboard-manager', () => ({ writeText: vi.fn() }));

import FieldViewer from '../src/components/FieldViewer.svelte';
import type { BlockSummaryDto, RecordDto } from '../src/lib/ipc';

const BLOCK: BlockSummaryDto = { blockUuidHex: 'ab', blockName: 'B', createdAtMs: 1, lastModifiedMs: 2 };
const RECORD: RecordDto = {
  recordUuidHex: 'cd', recordType: 'login', title: 'alice@example.test', subtitle: null,
  tags: ['work'], createdAtMs: 1, lastModMs: 2, fieldCount: 2,
  fields: [
    { name: 'username', lastModMs: 2, isText: true, isBytes: false },
    { name: 'password', lastModMs: 2, isText: true, isBytes: false }
  ]
};

describe('FieldViewer', () => {
  beforeEach(() => invokeMock.mockReset());

  it('renders a FieldRow per field, all masked', () => {
    const { getByText, getByLabelText } = render(FieldViewer, { props: { block: BLOCK, record: RECORD } });
    expect(getByText('username')).toBeTruthy();
    expect(getByText('password')).toBeTruthy();
    expect(getByLabelText(/reveal username/i)).toBeTruthy();
    expect(getByLabelText(/reveal password/i)).toBeTruthy();
  });
});

describe('FieldViewer — three-pane changes (#526)', () => {
  beforeEach(() => invokeMock.mockReset());

  it('no longer renders a back button', () => {
    // Escape and the sidebar own navigation now; a back button inside a
    // permanently-visible pane has nothing to go back to.
    const { queryByRole } = render(FieldViewer, { props: { block: BLOCK, record: RECORD } });
    expect(queryByRole('button', { name: /←/ })).toBeNull();
  });

  it('still offers Edit', () => {
    const { getByRole } = render(FieldViewer, { props: { block: BLOCK, record: RECORD } });
    expect(getByRole('button', { name: /edit/i })).toBeTruthy();
  });
});

describe('FieldViewer — fresh instance carries no reveal state (#526)', () => {
  // What this test does NOT do: it does not render Vault.svelte, so it
  // cannot observe whether Vault's `{#key panes.detail.record.recordUuidHex}`
  // wrapper actually forces Svelte to allocate a fresh FieldViewer instance
  // on a record-selection change. (An earlier draft of this test rerendered
  // one FieldViewer instance with a different `record` prop and asserted the
  // displayed title changed — that only proves props flow through, which
  // was never in question; it says nothing about whether the *same*
  // component instance was reused, which is the actual security question.
  // The `{#key}` block itself is reviewed by reading the Vault.svelte diff.)
  //
  // What this test DOES prove is the narrower, genuinely testable property
  // the `{#key}` block relies on: reveal state lives inside FieldRow
  // (`revealed`), and a brand-new FieldViewer instance — mounted after a
  // previous instance revealing the same-named field was unmounted — must
  // start masked. If it didn't, the `{#key}` swap Vault performs on every
  // record-selection change would leak a revealed secret from the old
  // record onto the new one.
  beforeEach(() => invokeMock.mockReset());

  const RECORD_A: RecordDto = {
    recordUuidHex: 'aa11', recordType: 'login', title: 'Record A', subtitle: null,
    tags: [], createdAtMs: 1, lastModMs: 2, fieldCount: 1,
    fields: [{ name: 'password', lastModMs: 2, isText: true, isBytes: false }]
  };
  const RECORD_B: RecordDto = {
    recordUuidHex: 'bb22', recordType: 'login', title: 'Record B', subtitle: null,
    tags: [], createdAtMs: 1, lastModMs: 2, fieldCount: 1,
    fields: [{ name: 'password', lastModMs: 2, isText: true, isBytes: false }]
  };

  it('a newly mounted instance starts masked, even after a prior instance revealed the same-named field', async () => {
    invokeMock.mockImplementation((cmd: string) => {
      if (cmd === 'reveal_field') return Promise.resolve({ isText: true, value: 'hunter2' });
      return Promise.resolve(null);
    });

    const instanceA = render(FieldViewer, { props: { block: BLOCK, record: RECORD_A } });
    await fireEvent.click(instanceA.getByLabelText(/reveal password/i));
    await waitFor(() => expect(instanceA.getByText('hunter2')).toBeTruthy());
    // Simulates what the {#key} block does on a record-selection change:
    // tear down the old instance entirely rather than reusing it.
    instanceA.unmount();

    const instanceB = render(FieldViewer, { props: { block: BLOCK, record: RECORD_B } });
    expect(instanceB.queryByText('hunter2')).toBeNull();
    expect(instanceB.getByLabelText(/reveal password/i)).toBeTruthy();
  });
});
