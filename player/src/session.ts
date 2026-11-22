import type { PlaybackSession, StopReason } from "./types";

/** The token travels as `?t=` when the URLs the edge hands out carry it (tenant `token_in_url`, ADR 0030). */
export function isUrlMode(manifestUrl: string): boolean {
  return new URL(manifestUrl).searchParams.has("t");
}

/** A URL next to master.m3u8 (heartbeat, end, poster.jpg, ...), without the query. */
export function siblingUrl(manifestUrl: string, name: string): string {
  const u = new URL(manifestUrl);
  u.search = "";
  u.pathname = u.pathname.slice(0, u.pathname.lastIndexOf("/") + 1) + name;
  return u.toString();
}

export interface SessionOptions {
  fetch?: typeof fetch;
  now?: () => number;
  onTokenRefresh?: (expiresAt: string) => void;
  onStop?: (reason: StopReason) => void;
}

/**
 * Holds the current token and keeps the session alive. Every request to the edge goes through
 * `authorize`, so a request that starts after a refresh carries the new token (pitfall 5).
 * The heartbeat response is the token refresh (spec/openapi.yaml, heartbeatPlayback).
 */
export class SessionController {
  readonly urlMode: boolean;
  private tokenValue: string;
  private tokenExpiresMs: number;
  private intervalMs: number;
  private readonly sessionExpiresMs: number | undefined;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private expiryTimer: ReturnType<typeof setTimeout> | undefined;
  private stopped: StopReason | undefined;
  private readonly dir: string;
  private readonly origin: string;
  private readonly fetchFn: typeof fetch;
  private readonly now: () => number;

  constructor(
    private readonly session: PlaybackSession,
    private readonly opts: SessionOptions = {},
  ) {
    const m = new URL(session.manifest_url);
    this.origin = m.origin;
    this.dir = m.pathname.slice(0, m.pathname.lastIndexOf("/") + 1);
    this.urlMode = isUrlMode(session.manifest_url);
    this.tokenValue = session.token;
    this.tokenExpiresMs = Date.parse(session.token_expires_at);
    this.intervalMs = Math.max(1, session.heartbeat_interval_seconds) * 1000;
    this.sessionExpiresMs = session.session_expires_at ? Date.parse(session.session_expires_at) : undefined;
    this.fetchFn = opts.fetch ?? ((...a) => fetch(...a));
    this.now = opts.now ?? Date.now;
  }

  get token(): string {
    return this.tokenValue;
  }

  get stoppedReason(): StopReason | undefined {
    return this.stopped;
  }

  /** True only for the session's own edge URLs, so the token never reaches presigned storage URLs (ADR 0032). */
  isEdgeUrl(url: string): boolean {
    try {
      const u = new URL(url, this.session.manifest_url);
      return u.origin === this.origin && u.pathname.startsWith(this.dir);
    } catch {
      return false;
    }
  }

  /** The request to make for `url`: the token in `t` (url mode) or in the Authorization header. */
  authorize(url: string): { url: string; headers: Record<string, string> } {
    if (!this.isEdgeUrl(url)) return { url, headers: {} };
    if (this.urlMode) {
      const u = new URL(url, this.session.manifest_url);
      u.searchParams.set("t", this.tokenValue);
      return { url: u.toString(), headers: {} };
    }
    return { url, headers: { Authorization: `Bearer ${this.tokenValue}` } };
  }

  /** fetch() of a route next to master.m3u8, with the current token. */
  fetchEdge(name: string, init: RequestInit = {}): Promise<Response> {
    const a = this.authorize(siblingUrl(this.session.manifest_url, name));
    return this.fetchFn(a.url, { ...init, headers: { ...a.headers }, cache: "no-store", credentials: "omit" });
  }

  start(): void {
    this.schedule();
    if (this.sessionExpiresMs !== undefined) {
      this.expiryTimer = setTimeout(() => this.stop("expired"), Math.max(0, this.sessionExpiresMs - this.now()));
    }
  }

  private schedule(delayMs?: number): void {
    clearTimeout(this.timer);
    if (this.stopped) return;
    // Refresh well before the token runs out even when the interval is longer than its lifetime.
    const untilExpiry = this.tokenExpiresMs - this.now();
    const d = delayMs ?? Math.max(1000, Math.min(this.intervalMs, untilExpiry * 0.8));
    this.timer = setTimeout(() => void this.heartbeat(), d);
  }

  /** One heartbeat; the answer carries the next token. Safe to call at any time (resume, 401). */
  async heartbeat(): Promise<void> {
    if (this.stopped) return;
    let res: Response;
    try {
      res = await this.fetchEdge("heartbeat", { method: "POST" });
    } catch {
      // Network trouble: try again soon, and give up when the token has certainly run out.
      if (this.now() >= this.tokenExpiresMs) this.stop("expired");
      else this.schedule(5000);
      return;
    }
    if (this.stopped) return;
    if (res.status === 401 || res.status === 403) {
      this.deny();
    } else if (res.status === 429) {
      this.schedule(Math.max(1, Number(res.headers.get("Retry-After")) || 5) * 1000);
    } else if (!res.ok) {
      this.schedule(5000);
    } else {
      const b = (await res.json()) as {
        token: string;
        token_expires_at: string;
        heartbeat_interval_seconds: number;
      };
      this.tokenValue = b.token;
      this.tokenExpiresMs = Date.parse(b.token_expires_at);
      this.intervalMs = Math.max(1, b.heartbeat_interval_seconds) * 1000;
      this.opts.onTokenRefresh?.(b.token_expires_at);
      this.schedule();
    }
  }

  /** The edge refused the session (401 or 403). The answer does not say why, so the clock decides the label. */
  deny(): void {
    this.stop(this.now() >= this.tokenExpiresMs ? "expired" : "revoked");
  }

  /** Ends the session at the edge (idempotent) and stops. `keepalive` lets it finish while the page unloads. */
  async end(): Promise<void> {
    if (this.stopped) return;
    const p = this.fetchEdge("end", { method: "POST", keepalive: true }).catch(() => undefined);
    this.stop("ended");
    await p;
  }

  stop(reason: StopReason): void {
    if (this.stopped) return;
    this.stopped = reason;
    clearTimeout(this.timer);
    clearTimeout(this.expiryTimer);
    this.opts.onStop?.(reason);
  }

  /** Stops the timers without telling anyone (the player is loading another session). */
  close(): void {
    this.stopped ??= "ended";
    clearTimeout(this.timer);
    clearTimeout(this.expiryTimer);
  }
}
