import { defineConfig } from "vitest/config";

// Headless unit tests for the extension's message logic (`src/messaging.ts`).
// Node environment — the tests inject a fake `RuntimeLike`/`PageLocation`, so no
// jsdom or browser is needed.
export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
  },
});
