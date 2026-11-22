import { defineConfig } from "vite";

// The demo page (index.html) that the end-to-end test opens. Output goes to dist-demo.
export default defineConfig({ build: { outDir: "dist-demo" } });
