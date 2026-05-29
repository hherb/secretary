import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import CreateVault from '../src/routes/CreateVault.svelte';
import { _resetRouteForTest, openCreateWizard } from '../src/lib/route';

vi.mock('../src/lib/ipc', () => ({
  createVault: vi.fn(),
  probeCreateTarget: vi.fn().mockResolvedValue({ exists: true, isEmpty: true })
}));
import { createVault, probeCreateTarget } from '../src/lib/ipc';
vi.mock('@tauri-apps/plugin-dialog', () => ({ open: vi.fn() }));
vi.mock('@tauri-apps/plugin-clipboard-manager', () => ({
  writeText: vi.fn().mockResolvedValue(undefined)
}));

const PHRASE = Array.from({ length: 24 }, (_, i) => `word${i + 1}`).join(' ');

// NOTE on folder-pick adaptation: CreateVault.svelte seeds the FolderStep via
// `createSeedPath`, which is empty after `_resetRouteForTest()`. An empty seed
// leaves `picked === ''` → `probed === null` → Continue disabled, so the test
// cannot click Continue directly. Instead each test calls
// `openCreateWizard('/tmp/v')` before render to seed the picker with a path
// that resolves via the probeCreateTarget mock as `{ exists: true, isEmpty: true }`,
// enabling Continue without any folder-picker interaction.

describe('CreateVault host', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    _resetRouteForTest();
    (probeCreateTarget as ReturnType<typeof vi.fn>).mockResolvedValue({
      exists: true,
      isEmpty: true
    });
  });

  it('advances folder -> credentials -> mnemonic on a successful create', async () => {
    (createVault as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ mnemonic: PHRASE });
    // Seed the picker so the FolderStep Continue button is enabled.
    openCreateWizard('/tmp/v');
    const { findByRole, getByLabelText, getByRole, findAllByTestId } = render(CreateVault);

    // Folder step: probe resolves empty -> Continue enabled.
    await fireEvent.click(await findByRole('button', { name: /continue/i }));

    // Credentials step.
    await fireEvent.input(getByLabelText(/display name/i), { target: { value: 'Me' } });
    await fireEvent.input(getByLabelText(/^password/i), { target: { value: 'pw' } });
    await fireEvent.input(getByLabelText(/confirm/i), { target: { value: 'pw' } });
    await fireEvent.click(getByRole('button', { name: /create vault/i }));

    // Mnemonic step renders the 24 words.
    expect(await findAllByTestId('mnemonic-word')).toHaveLength(24);
    expect(createVault).toHaveBeenCalledTimes(1);
  });

  it('renders an error and stays put when create rejects', async () => {
    (createVault as ReturnType<typeof vi.fn>).mockRejectedValueOnce({
      code: 'vault_create_failed'
    });
    // Seed the picker so the FolderStep Continue button is enabled.
    openCreateWizard('/tmp/v');
    const { findByRole, getByLabelText, getByRole, findByText } = render(CreateVault);

    await fireEvent.click(await findByRole('button', { name: /continue/i }));
    await fireEvent.input(getByLabelText(/display name/i), { target: { value: 'Me' } });
    await fireEvent.input(getByLabelText(/^password/i), { target: { value: 'pw' } });
    await fireEvent.input(getByLabelText(/confirm/i), { target: { value: 'pw' } });
    await fireEvent.click(getByRole('button', { name: /create vault/i }));

    // userMessageFor({ code: 'vault_create_failed' }).title === "Couldn't create the vault"
    expect(await findByText(/couldn.t create the vault/i)).toBeTruthy();
  });
});
