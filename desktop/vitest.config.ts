import { defineConfig } from 'vitest/config';
import { svelte } from '@sveltejs/vite-plugin-svelte';

// Pure-module + DOM-mock harness for the desktop frontend's TS layer.
// Loads the svelte plugin so future component tests can import .svelte
// files without further config; current tests are TS-only.
//
// `environment: 'jsdom'` is required by auto_lock.test.ts which dispatches
// MouseEvent / KeyboardEvent on the document. The other suites would run
// fine under 'node' but a single environment is simpler than per-file
// overrides.

export default defineConfig({
  plugins: [svelte({ hot: false })],
  test: {
    environment: 'jsdom',
    include: ['tests/**/*.test.ts'],
    globals: false
  }
});
