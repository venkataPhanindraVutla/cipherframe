import { expect, test, type Page } from "@playwright/test";

// Runs against the development stack (deploy/compose). Environment, none of it printed:
//   CIPHERFRAME_API_KEY   API key with admin, assets and sessions scopes
//   CIPHERFRAME_ASSET_ID  a ready asset (e2e/prepare-asset.sh)
//   CIPHERFRAME_API_URL   default http://127.0.0.1:8080
const api = process.env.CIPHERFRAME_API_URL ?? "http://127.0.0.1:8080";
const key = process.env.CIPHERFRAME_API_KEY;
const asset = process.env.CIPHERFRAME_ASSET_ID;
const ORIGIN = "http://localhost:4173";

async function call(method: string, path: string, body?: unknown): Promise<Response> {
  const res = await fetch(api + path, {
    method,
    headers: { Authorization: `Bearer ${key}`, ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`${method} ${path} -> ${res.status}`);
  return res;
}

interface Session {
  session_id: string;
  token: string;
  manifest_url: string;
  [k: string]: unknown;
}

test.beforeAll(async () => {
  test.skip(!key || !asset, "needs CIPHERFRAME_API_KEY and CIPHERFRAME_ASSET_ID");
  // Short lifetimes: a 60 second token and a 10 second heartbeat, so the run crosses several refreshes.
  const settings = (await (await call("GET", "/v1/playback-settings")).json()) as Record<string, unknown>;
  delete settings.updated_at;
  await call("PUT", "/v1/playback-settings", {
    ...settings,
    token_ttl_seconds: 60,
    heartbeat_interval_seconds: 10,
    allowed_origins: [ORIGIN],
    token_in_url: false,
  });
  const overlay = (await (await call("GET", "/v1/overlay-settings")).json()) as Record<string, unknown>;
  delete overlay.updated_at;
  await call("PUT", "/v1/overlay-settings", { ...overlay, enabled: true });
});

async function open(page: Page) {
  const session = (await (await call("POST", "/v1/playback-sessions", { asset_id: asset, viewer_id: `e2e-${Date.now()}` })).json()) as Session;
  const keyRequests: { auth: string | undefined }[] = [];
  const heartbeats: { auth: string | undefined }[] = [];
  page.on("request", (r) => {
    if (r.url().endsWith("/key")) keyRequests.push({ auth: r.headers().authorization });
    if (r.url().endsWith("/heartbeat")) heartbeats.push({ auth: r.headers().authorization });
  });
  await page.goto("/");
  await page.evaluate((s) => document.querySelector("cipherframe-player")!.load(s), session as never);
  return { session, keyRequests, heartbeats };
}

const time = (page: Page) => page.evaluate(() => document.querySelector("cipherframe-player")!.video.currentTime);
const state = (page: Page) => page.evaluate(() => document.querySelector("cipherframe-player")!.state);

test("plays with the token on the key request, survives refreshes, stops when revoked", async ({ page }) => {
  const { session, keyRequests, heartbeats } = await open(page);

  // Plays: currentTime advances (muted autoplay is allowed; start it like a viewer would).
  await page.locator("cipherframe-player").getByRole("button", { name: "Play" }).click();
  await expect.poll(() => time(page), { timeout: 30_000 }).toBeGreaterThan(2);
  expect(await state(page)).toBe("playing");

  // The key route was requested with the token (and the token is not in any URL).
  expect(keyRequests.length).toBeGreaterThan(0);
  expect(keyRequests[0]?.auth).toBe(`Bearer ${session.token}`);

  // Overlay is drawn inside the video box, as text.
  const overlay = page.locator("cipherframe-player").locator(".overlay span");
  await expect(overlay).toContainText(/UTC$/);

  // Survives a token refresh: after a heartbeat, requests carry a different token and playback goes on.
  await expect.poll(() => heartbeats.length, { timeout: 30_000 }).toBeGreaterThan(0);
  expect(heartbeats[0]?.auth).toBe(`Bearer ${session.token}`);
  await expect.poll(() => heartbeats.length, { timeout: 30_000 }).toBeGreaterThan(1);
  expect(heartbeats[1]?.auth).toMatch(/^Bearer /);
  expect(heartbeats[1]?.auth).not.toBe(heartbeats[0]?.auth); // the second beat carries the refreshed token
  const before = await time(page);
  await expect.poll(() => time(page), { timeout: 30_000 }).toBeGreaterThan(before + 3);
  expect(await state(page)).toBe("playing");

  // Revoke through the API: the next heartbeat (or key or playlist request) gets 401 and playback stops.
  await call("POST", `/v1/playback-sessions/${session.session_id}/revoke`, {});
  await expect.poll(() => state(page), { timeout: 40_000 }).toBe("revoked");
  await expect(page.locator("cipherframe-player").locator(".status")).toContainText("revoked");
});
