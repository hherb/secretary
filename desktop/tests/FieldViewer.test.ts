import { describe, it, expect, vi } from 'vitest';
import { render } from '@testing-library/svelte';
vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }));
vi.mock('@tauri-apps/plugin-clipboard-manager', () => ({ writeText: vi.fn() }));

import FieldViewer from '../src/components/FieldViewer.svelte';
import type { BlockSummaryDto, RecordDto } from '../src/lib/ipc';

const BLOCK: BlockSummaryDto = { blockUuidHex: 'ab', blockName: 'B', createdAtMs: 1, lastModifiedMs: 2 };
const RECORD: RecordDto = {
  recordUuidHex: 'cd', recordType: 'login', tags: ['work'], createdAtMs: 1, lastModMs: 2, fieldCount: 2,
  fields: [
    { name: 'username', lastModMs: 2, isText: true, isBytes: false },
    { name: 'password', lastModMs: 2, isText: true, isBytes: false }
  ]
};

describe('FieldViewer', () => {
  it('renders a FieldRow per field, all masked', () => {
    const { getByText, getByLabelText } = render(FieldViewer, { props: { block: BLOCK, record: RECORD } });
    expect(getByText('username')).toBeTruthy();
    expect(getByText('password')).toBeTruthy();
    expect(getByLabelText(/reveal username/i)).toBeTruthy();
    expect(getByLabelText(/reveal password/i)).toBeTruthy();
  });
});
