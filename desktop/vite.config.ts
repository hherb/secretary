import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

// Tauri-canonical Vite config: fixed dev port 1420, skip env vars Tauri owns,
// disable HMR overlay (Tauri's window has its own dev menu).
export default defineConfig({
  plugins: [svelte()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: false,
    hmr: { protocol: 'ws', host: 'localhost', port: 1421 },
    watch: { ignored: ['**/src-tauri/**'] }
  }
});
