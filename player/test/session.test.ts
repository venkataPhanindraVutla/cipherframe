import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SessionController, isUrlMode, siblingUrl } from "../src/session";
import type { PlaybackSession, StopReason } from "../src/types";

const BASE = "https://media.example.test/v1/play/ses_x";
const session = (over: Partial<PlaybackSession> = {}): PlaybackSession => ({
  token: "test-fixture-token-1",
  token_expires_at: new Date(Date.now() + 600_000).toISOString(),
  heartbeat_interval_seconds: 60,
  manifest_url: `${BASE}/master.m3u8`,
  ...over,
});
const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers });

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

describe("token on every request", () => {
  it("goes in the Authorization header for the session's playlists, key and segments", () => {
    const c = new SessionController(session());
    for (const p of ["master.m3u8", "v720/media.m3u8", "key", "v720/seg-1.m4s", "subtitles/sub_1/media.m3u8"]) {
      expect(c.authorize(`${BASE}/${p}`)).toEqual({ url: `${BASE}/${p}`, headers: { Authorization: "Bearer test-fixture-token-1" } });
    }
  });

  it("is never sent to presigned storage or another origin", () => {
    const c = new SessionController(session());
    expect(c.authorize("https://s3.example.test/bucket/seg-1.m4s?X-Amz-Signature=abc").headers).toEqual({});
    expect(c.authorize("https://media.example.test/v1/play/ses_other/key").headers).toEqual({});
  });

  it("goes in ?t= when the edge hands out token URLs, and a refreshed token replaces the old one", () => {
    const manifest = `${BASE}/master.m3u8?t=test-fixture-token-1`;
    expect(isUrlMode(manifest)).toBe(true);
    const c = new SessionController(session({ manifest_url: manifest }));
    expect(c.authorize(`${BASE}/v720/media.m3u8?t=test-fixture-token-1`)).toEqual({
      url: `${BASE}/v720/media.m3u8?t=test-fixture-token-1`,
      headers: {},
    });
    expect(isUrlMode(`${BASE}/master.m3u8`)).toBe(false);
  });

  it("builds sibling URLs without the query", () => {
    expect(siblingUrl(`${BASE}/master.m3u8?t=x`, "poster.jpg")).toBe(`${BASE}/poster.jpg`);
  });
});

describe("heartbeat and refresh", () => {
  it("beats on the interval and the next request carries the new token", async () => {
    const fetchMock = vi.fn(async (_url: string, _init: RequestInit) =>
      json({ token: "test-fixture-token-2", token_expires_at: new Date(Date.now() + 600_000).toISOString(), heartbeat_interval_seconds: 60, session_expires_at: "2099-01-01T00:00:00Z" }),
    );
    const refreshed: string[] = [];
    const c = new SessionController(session(), { fetch: fetchMock as unknown as typeof fetch, onTokenRefresh: (e) => refreshed.push(e) });
    c.start();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(`${BASE}/heartbeat`);
    expect(init.method).toBe("POST");
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer test-fixture-token-1");
    expect(refreshed).toHaveLength(1);
    expect(c.token).toBe("test-fixture-token-2");
    expect(c.authorize(`${BASE}/key`).headers.Authorization).toBe("Bearer test-fixture-token-2");
    await vi.advanceTimersByTimeAsync(60_000);
    const second = fetchMock.mock.calls[1] as unknown as [string, RequestInit];
    expect((second[1].headers as Record<string, string>).Authorization).toBe("Bearer test-fixture-token-2");
    c.close();
  });

  it("beats before a short-lived token runs out", async () => {
    const fetchMock = vi.fn(async () => json({ token: "t2", token_expires_at: new Date(Date.now() + 10_000).toISOString(), heartbeat_interval_seconds: 600 }));
    const c = new SessionController(session({ token_expires_at: new Date(Date.now() + 10_000).toISOString(), heartbeat_interval_seconds: 600 }), {
      fetch: fetchMock as unknown as typeof fetch,
    });
    c.start();
    await vi.advanceTimersByTimeAsync(8_000);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    c.close();
  });

  it("waits Retry-After after a 429 and keeps the old token", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(json({}, 429, { "Retry-After": "7" }))
      .mockResolvedValue(json({ token: "t2", token_expires_at: new Date(Date.now() + 600_000).toISOString(), heartbeat_interval_seconds: 60 }));
    const c = new SessionController(session(), { fetch: fetchMock as unknown as typeof fetch });
    await c.heartbeat();
    expect(c.token).toBe("test-fixture-token-1");
    await vi.advanceTimersByTimeAsync(6_900);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    c.close();
  });
});

describe("stop", () => {
  for (const status of [401, 403]) {
    it(`stops as revoked on a ${status} to a heartbeat`, async () => {
      const stops: StopReason[] = [];
      const fetchMock = vi.fn(async () => json({}, status));
      const c = new SessionController(session(), { fetch: fetchMock as unknown as typeof fetch, onStop: (r) => stops.push(r) });
      await c.heartbeat();
      expect(stops).toEqual(["revoked"]);
      await vi.advanceTimersByTimeAsync(300_000);
      expect(fetchMock).toHaveBeenCalledTimes(1); // no more heartbeats after the stop
    });
  }

  it("calls a denial after the token's expiry 'expired'", () => {
    const stops: StopReason[] = [];
    const c = new SessionController(session({ token_expires_at: new Date(Date.now() + 1000).toISOString() }), { onStop: (r) => stops.push(r) });
    vi.setSystemTime(Date.now() + 2000);
    c.deny();
    expect(stops).toEqual(["expired"]);
  });

  it("stops at the session's maximum age", async () => {
    const stops: StopReason[] = [];
    const c = new SessionController(session({ session_expires_at: new Date(Date.now() + 5000).toISOString() }), {
      fetch: (async () => json({ token: "t", token_expires_at: new Date(Date.now() + 600_000).toISOString(), heartbeat_interval_seconds: 60 })) as typeof fetch,
      onStop: (r) => stops.push(r),
    });
    c.start();
    await vi.advanceTimersByTimeAsync(5000);
    expect(stops).toEqual(["expired"]);
  });

  it("end() posts to the end route once and stops", async () => {
    const fetchMock = vi.fn(async () => new Response(null, { status: 204 }));
    const stops: StopReason[] = [];
    const c = new SessionController(session(), { fetch: fetchMock as unknown as typeof fetch, onStop: (r) => stops.push(r) });
    await c.end();
    await c.end();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(`${BASE}/end`);
    expect(init.keepalive).toBe(true);
    expect(stops).toEqual(["ended"]);
  });

  it("close() is silent", () => {
    const stops: StopReason[] = [];
    const c = new SessionController(session(), { onStop: (r) => stops.push(r) });
    c.close();
    expect(stops).toEqual([]);
  });
});
