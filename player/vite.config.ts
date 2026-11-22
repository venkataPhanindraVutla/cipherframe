import { defineConfig } from "vitest/config";

// Library build (ESM only, hls.js bundled so the element works from one file) and the unit tests.
export default defineConfig({
  build: {
    lib: { entry: "src/index.ts", formats: ["es"], fileName: "cipherframe-player" },
    sourcemap: true,
  },
  test: { environment: "jsdom", include: ["test/**/*.test.ts"] },
});
