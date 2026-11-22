import { CipherframePlayer } from "./element";

if (!customElements.get("cipherframe-player")) customElements.define("cipherframe-player", CipherframePlayer);

export { CipherframePlayer };
export { SessionController, isUrlMode, siblingUrl } from "./session";
export { deriveParams, placement, position } from "./drift";
export { renderTemplate } from "./overlay";
export type { OverlayConfig, PlaybackSession, PlayerEventMap, PlayerState, StopReason } from "./types";
