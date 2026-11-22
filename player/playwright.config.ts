import { defineConfig, devices } from "@playwright/test";

// Serves the built demo page on 4173 (the origin the test adds to the tenant's allowed_origins).
export default defineConfig({
  testDir: "e2e",
  timeout: 120_000,
  retries: 0,
  reporter: [["list"]],
  use: { baseURL: "http://localhost:4173", trace: "retain-on-failure", ...devices["Desktop Chrome"] },
  projects: [{ name: "chromium", use: { browserName: "chromium", launchOptions: { args: ["--autoplay-policy=no-user-gesture-required"] } } }],
  webServer: {
    command: "pnpm build:demo && pnpm preview:demo",
    url: "http://localhost:4173",
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
