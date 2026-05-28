import { defineConfig } from 'vitest/config';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { svelteTesting } from '@testing-library/svelte/vite';

// Pure-module + component-rendering harness for the desktop frontend.
//
// `svelte()` lets Vitest compile `.svelte` files so component tests can
// import them. `svelteTesting()` is the recommended companion from
// `@testing-library/svelte` v5 — it adds the `browser` resolve
// condition (so testing-library's runes-mode `.svelte.js` files resolve
// to their compiled browser bundle rather than raw source), wires the
// auto-cleanup setup file, and adds the testing-library packages to
// `ssr.noExternal` so they go through the Svelte plugin's compile pass.
//
// `environment: 'jsdom'` is required by both `auto_lock.test.ts` (which
// dispatches MouseEvent / KeyboardEvent on `document`) and the component
// tests (which need a DOM to mount into).

export default defineConfig({
  plugins: [svelte({ hot: false }), svelteTesting()],
  test: {
    environment: 'jsdom',
    include: ['tests/**/*.test.ts'],
    globals: false
  }
});
