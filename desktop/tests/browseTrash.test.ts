import { describe, it, expect, beforeEach } from 'vitest';
import { get } from 'svelte/store';
import { browseNav, openTrash, back, resetBrowse } from '../src/lib/browse';

describe('browse trash transitions', () => {
  beforeEach(() => resetBrowse());

  it('openTrash sets level trash', () => {
    openTrash();
    expect(get(browseNav)).toEqual({ level: 'trash' });
  });

  it('back from trash pops to blocks', () => {
    openTrash();
    back();
    expect(get(browseNav)).toEqual({ level: 'blocks' });
  });
});
