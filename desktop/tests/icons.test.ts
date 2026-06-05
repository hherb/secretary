// Render contract for the vendored Lucide icon components (#154). Each is a
// presentational SVG: aria-hidden, currentColor stroke, square, sized by the
// `size` prop (default 20). We assert the contract on a representative pair
// (Lock = default size; LockKeyhole = the hero override) and smoke-render the
// rest so a malformed SVG fails the suite.
import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/svelte';
import Lock from '../src/components/icons/Lock.svelte';
import LockKeyhole from '../src/components/icons/LockKeyhole.svelte';
import Eye from '../src/components/icons/Eye.svelte';
import EyeOff from '../src/components/icons/EyeOff.svelte';
import Link from '../src/components/icons/Link.svelte';
import Trash from '../src/components/icons/Trash.svelte';
import Users from '../src/components/icons/Users.svelte';
import Settings from '../src/components/icons/Settings.svelte';

describe('icons — render contract', () => {
  it('Lock renders a decorative, currentColor SVG at the default size (20)', () => {
    const { container } = render(Lock);
    const svg = container.querySelector('svg');
    expect(svg).not.toBeNull();
    expect(svg!.getAttribute('aria-hidden')).toBe('true');
    expect(svg!.getAttribute('stroke')).toBe('currentColor');
    expect(svg!.getAttribute('width')).toBe('20');
    expect(svg!.getAttribute('height')).toBe('20');
    expect(svg!.classList.contains('icon')).toBe(true);
  });

  it('honours the size prop (hero override)', () => {
    const { container } = render(LockKeyhole, { props: { size: 48 } });
    const svg = container.querySelector('svg');
    expect(svg!.getAttribute('width')).toBe('48');
    expect(svg!.getAttribute('height')).toBe('48');
  });

  it('every icon renders a non-empty SVG', () => {
    for (const Icon of [Eye, EyeOff, Link, Trash, Users, Settings]) {
      const { container } = render(Icon);
      const svg = container.querySelector('svg');
      expect(svg).not.toBeNull();
      expect(svg!.innerHTML.length).toBeGreaterThan(0);
    }
  });
});
