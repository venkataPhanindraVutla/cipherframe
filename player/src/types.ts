/** A playback session exactly as `POST /v1/playback-sessions` returns it (extra members are ignored). */
export interface PlaybackSession {
  session_id?: string;
  token: string;
  token_expires_at: string;
  heartbeat_interval_seconds: number;
  session_expires_at?: string;
  manifest_url: string;
  token_transport?: "header" | "url";
  variant?: string;
  overlay?: OverlayConfig;
}

export interface OverlayConfig {
  template: string;
  session_code?: string;
  style: { opacity: number; font_size_fraction: number; color: string };
  drift: { algorithm: string; seed: string; period_seconds: number; margin: number };
}

/** Why the player stopped loading. */
export type StopReason = "ended" | "expired" | "revoked";

/** The element's `state` attribute. */
export type PlayerState = "idle" | "loading" | "playing" | "paused" | "ended" | "expired" | "revoked" | "error";

/** Events the element dispatches (all bubble and are composed). */
export interface PlayerEventMap {
  "cipherframe:ready": CustomEvent<{ levels: number; subtitles: number }>;
  "cipherframe:tokenrefresh": CustomEvent<{ expiresAt: string }>;
  "cipherframe:stop": CustomEvent<{ reason: StopReason }>;
  "cipherframe:error": CustomEvent<{ message: string }>;
}
