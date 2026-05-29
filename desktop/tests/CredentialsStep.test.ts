import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import CredentialsStep from '../src/components/create/CredentialsStep.svelte';

describe('CredentialsStep', () => {
  it('disables Create until name + matching passwords are present', async () => {
    const onCreate = vi.fn();
    const { getByLabelText, getByRole } = render(CredentialsStep, {
      props: { folder: '/v', submitting: false, onCreate, onBack: vi.fn() }
    });
    const create = getByRole('button', { name: /create vault/i }) as HTMLButtonElement;
    expect(create.disabled).toBe(true);

    await fireEvent.input(getByLabelText(/display name/i), { target: { value: 'Me' } });
    await fireEvent.input(getByLabelText(/^password/i), { target: { value: 'hunter2' } });
    await fireEvent.input(getByLabelText(/confirm/i), { target: { value: 'hunter2' } });
    expect(create.disabled).toBe(false);

    await fireEvent.click(create);
    expect(onCreate).toHaveBeenCalledWith('Me', 'hunter2');
  });

  it('shows a mismatch message and keeps Create disabled', async () => {
    const { getByLabelText, getByRole, getByText } = render(CredentialsStep, {
      props: { folder: '/v', submitting: false, onCreate: vi.fn(), onBack: vi.fn() }
    });
    await fireEvent.input(getByLabelText(/display name/i), { target: { value: 'Me' } });
    await fireEvent.input(getByLabelText(/^password/i), { target: { value: 'hunter2' } });
    await fireEvent.input(getByLabelText(/confirm/i), { target: { value: 'hunterX' } });
    expect(getByText(/don.t match/i)).toBeTruthy();
    expect((getByRole('button', { name: /create vault/i }) as HTMLButtonElement).disabled).toBe(true);
  });
});
