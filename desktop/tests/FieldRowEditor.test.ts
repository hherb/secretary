import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import FieldRowEditor from '../src/components/edit/FieldRowEditor.svelte';

describe('FieldRowEditor', () => {
  it('reports name/kind/value changes and remove', async () => {
    const onChange = vi.fn();
    const onRemove = vi.fn();
    const { getByLabelText, getByRole } = render(FieldRowEditor, {
      props: { field: { name: '', kind: 'text', value: '' }, error: undefined, onChange, onRemove }
    });
    await fireEvent.input(getByLabelText(/field name/i), { target: { value: 'user' } });
    expect(onChange).toHaveBeenLastCalledWith({ name: 'user', kind: 'text', value: '' });
    await fireEvent.click(getByRole('button', { name: /remove field/i }));
    expect(onRemove).toHaveBeenCalled();
  });

  it('shows the inline error when present', () => {
    const { getByRole } = render(FieldRowEditor, {
      props: { field: { name: 'seed', kind: 'bytes', value: 'x!' }, error: 'Value must be valid base64.', onChange: vi.fn(), onRemove: vi.fn() }
    });
    expect(getByRole('alert').textContent).toMatch(/base64/i);
  });
});
