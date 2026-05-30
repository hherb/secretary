import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import TagsEditor from '../src/components/edit/TagsEditor.svelte';

describe('TagsEditor', () => {
  it('adds a tag and reports via onChange; dedups', async () => {
    const onChange = vi.fn();
    const { getByLabelText, getByRole } = render(TagsEditor, { props: { tags: [], onChange } });
    await fireEvent.input(getByLabelText(/add tag/i), { target: { value: 'work' } });
    await fireEvent.click(getByRole('button', { name: /add tag/i }));
    expect(onChange).toHaveBeenLastCalledWith(['work']);
  });
});
