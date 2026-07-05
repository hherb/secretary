// Component-level tests for RepairConsentDialog.svelte (#374 Task 10) — the
// informed-consent modal shown when `previewRepair` finds recipient
// widenings that would otherwise be silently discarded by the fail-closed
// repair path. Mirrors ConfirmDialog.test.ts's pattern (native <dialog>,
// callback props, JSDOM showModal polyfill from tests/setup.ts).
//
// Contract pinned here:
//   - Renders the spec's exact title + body copy (security copy, not
//     paraphrased).
//   - Renders each widened block's name, and each added recipient's
//     display name + card fingerprint grouped in 4-char chunks via the
//     exported `groupHex` helper.
//   - Cancel is the safe default: it has initial focus.
//   - Grant/Cancel fire their respective callbacks and only those.

import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import RepairConsentDialog, { groupHex } from '../src/components/RepairConsentDialog.svelte';
import type { WideningReportDto } from '../src/lib/ipc';

const WIDENING: WideningReportDto = {
  blockUuidHex: 'aaaaaaaa-0000-0000-0000-000000000001',
  blockName: 'Family Passwords',
  fileFingerprintHex: 'bbbbbbbb-0000-0000-0000-000000000002',
  added: [
    {
      uuidHex: 'cccccccc-0000-0000-0000-000000000003',
      displayName: 'Cee',
      cardFingerprintHex: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4'
    }
  ]
};

function renderDialog(overrides: Record<string, unknown> = {}) {
  const onCancel = vi.fn();
  const onGrant = vi.fn();
  const utils = render(RepairConsentDialog, {
    props: {
      widenings: [WIDENING],
      onCancel,
      onGrant,
      ...overrides
    }
  });
  return { ...utils, onCancel, onGrant };
}

describe('groupHex', () => {
  it('groups a hex string into space-separated 4-char chunks', () => {
    expect(groupHex('a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4')).toBe(
      'a1b2 c3d4 e5f6 a1b2 c3d4 e5f6 a1b2 c3d4'
    );
  });

  it('leaves a short final chunk when length is not a multiple of 4', () => {
    expect(groupHex('abcdef')).toBe('abcd ef');
  });

  it('returns the empty string for the empty string', () => {
    expect(groupHex('')).toBe('');
  });
});

describe('RepairConsentDialog.svelte', () => {
  it('renders the spec title and body copy verbatim', () => {
    const { getByText } = renderDialog();
    expect(getByText('An interrupted share was found.')).toBeTruthy();
    expect(
      getByText(
        "Adopting this repair will give these contacts access to this block. If you don't recognize this, choose Cancel — the vault stays unchanged."
      )
    ).toBeTruthy();
  });

  it('renders the widened block name', () => {
    const { getByText } = renderDialog();
    expect(getByText('Family Passwords')).toBeTruthy();
  });

  it("renders each added recipient's display name and grouped fingerprint", () => {
    const { getByText } = renderDialog();
    expect(getByText('Cee')).toBeTruthy();
    expect(getByText(groupHex(WIDENING.added[0].cardFingerprintHex))).toBeTruthy();
  });

  it('renders multiple widenings, each with its own block + recipients', () => {
    const second: WideningReportDto = {
      blockUuidHex: 'dddddddd-0000-0000-0000-000000000004',
      blockName: 'Work Logins',
      fileFingerprintHex: 'eeeeeeee-0000-0000-0000-000000000005',
      added: [
        {
          uuidHex: 'ffffffff-0000-0000-0000-000000000006',
          displayName: 'Dee',
          cardFingerprintHex: '11223344556677889900aabbccddeeff'.slice(0, 32)
        }
      ]
    };
    const { getByText } = renderDialog({ widenings: [WIDENING, second] });
    expect(getByText('Family Passwords')).toBeTruthy();
    expect(getByText('Work Logins')).toBeTruthy();
    expect(getByText('Cee')).toBeTruthy();
    expect(getByText('Dee')).toBeTruthy();
  });

  it('opens the dialog (showModal) on mount', async () => {
    const { container } = renderDialog();
    await waitFor(() => {
      const dialog = container.querySelector('dialog') as HTMLDialogElement;
      expect(dialog.hasAttribute('open')).toBe(true);
    });
  });

  it('Cancel has initial focus (the safe default)', async () => {
    const { getByRole } = renderDialog();
    const cancelBtn = getByRole('button', { name: 'Cancel' });
    await waitFor(() => expect(document.activeElement).toBe(cancelBtn));
  });

  it('clicking "Grant access and repair" fires onGrant, not onCancel', async () => {
    const { getByRole, onGrant, onCancel } = renderDialog();
    await fireEvent.click(getByRole('button', { name: 'Grant access and repair' }));
    expect(onGrant).toHaveBeenCalledTimes(1);
    expect(onCancel).not.toHaveBeenCalled();
  });

  it('clicking Cancel fires onCancel, not onGrant', async () => {
    const { getByRole, onGrant, onCancel } = renderDialog();
    await fireEvent.click(getByRole('button', { name: 'Cancel' }));
    expect(onCancel).toHaveBeenCalledTimes(1);
    expect(onGrant).not.toHaveBeenCalled();
  });

  it('buttons are type="button" (never form-submit)', () => {
    const { getByRole } = renderDialog();
    expect(getByRole('button', { name: 'Cancel' }).getAttribute('type')).toBe('button');
    expect(getByRole('button', { name: 'Grant access and repair' }).getAttribute('type')).toBe(
      'button'
    );
  });
});
