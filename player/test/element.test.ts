import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// A minimal stand-in for hls.js: records what the player configures and lets a test fire events.
const h = vi.hoisted(() => {
  const handlers = new Map<string, (e: string, d: unknown) => void>();
  const inst = {
    config: undefined as undefined | { xhrSetup?: (x: XhrLike, u: string) => void },
    levels: [{ height: 360, bitrate: 500_000 }, { height: 720, bitrate: 2_000_000 }],
    subtitleTracks: [{ name: "English", lang: "en" }, { name: "", lang: "de" }],
    currentLevel: -1,
    autoLevelEnabled: true,
    subtitleTrack: -1,
    subtitleDisplay: false,
    on: (ev: string, cb: (e: string, d: unknown) => void) => void handlers.set(ev, cb),
    attachMedia: () => undefined,
    loadSource: () => undefined,
    startLoad: () => undefined,
    recoverMediaError: () => undefined,
    destroy: vi.fn(),
  };
  interface XhrLike {
    setRequestHeader(k: string, v: string): void;
  }
  return { handlers, inst };
});

vi.mock("hls.js", () => {
  class FakeHls {
    static isSupported = () => true;
    static DefaultConfig = { loader: class {} };
    static Events = { MANIFEST_PARSED: "manifestParsed", SUBTITLE_TRACKS_UPDATED: "subtitleTracksUpdated", ERROR: "hlsError" };
    static ErrorTypes = { NETWORK_ERROR: "networkError", MEDIA_ERROR: "mediaError" };
    constructor(config: never) {
      h.inst.config = config;
      return h.inst as unknown as FakeHls;
    }
  }
  return { default: FakeHls };
});

import "../src/index";
import type { CipherframePlayer } from "../src/element";

const BASE = "https://media.example.test/v1/play/ses_x";
const session = {
  token: "test-fixture-token-1",
  token_expires_at: new Date(Date.now() + 600_000).toISOString(),
  heartbeat_interval_seconds: 60,
  manifest_url: `${BASE}/master.m3u8`,
};

let el: CipherframePlayer;
beforeEach(() => {
  HTMLMediaElement.prototype.pause = () => undefined;
  h.handlers.clear();
  h.inst.destroy.mockClear();
  vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 404 })));
  vi.stubGlobal("URL", Object.assign(URL, { createObjectURL: () => "blob:x", revokeObjectURL: () => undefined }));
  el = document.createElement("cipherframe-player");
  document.body.append(el);
});
afterEach(() => {
  el.remove();
  vi.unstubAllGlobals();
});

const sel = (name: string) => el.shadowRoot?.querySelector(name) as HTMLSelectElement;
const fire = (ev: string, data: unknown = {}) => h.handlers.get(ev)?.(ev, data);

describe("<cipherframe-player>", () => {
  it("attaches the current token to hls requests to the edge only", () => {
    el.load(session);
    const calls: [string, string][] = [];
    const xhr = { setRequestHeader: (k: string, v: string) => calls.push([k, v]) };
    h.inst.config?.xhrSetup?.(xhr, `${BASE}/key`);
    h.inst.config?.xhrSetup?.(xhr, "https://s3.example.test/seg-1.m4s?X-Amz-Signature=a");
    expect(calls).toEqual([["Authorization", "Bearer test-fixture-token-1"]]);
  });

  it("fills the quality menu from the levels and sets the level", () => {
    el.load(session);
    fire("manifestParsed");
    expect([...sel(".quality").options].map((o) => o.textContent)).toEqual(["Auto", "360p", "720p"]);
    sel(".quality").value = "1";
    sel(".quality").dispatchEvent(new Event("change"));
    expect(h.inst.currentLevel).toBe(1);
  });

  it("fills the subtitle menu from the tracks and switches them on and off", () => {
    el.load(session);
    expect(sel(".subtitles").disabled).toBe(true);
    fire("manifestParsed");
    expect(sel(".subtitles").disabled).toBe(false);
    expect([...sel(".subtitles").options].map((o) => o.textContent)).toEqual(["Off", "English", "de"]);
    sel(".subtitles").value = "0";
    sel(".subtitles").dispatchEvent(new Event("change"));
    expect(h.inst.subtitleTrack).toBe(0);
    expect(h.inst.subtitleDisplay).toBe(true);
    sel(".subtitles").value = "-1";
    sel(".subtitles").dispatchEvent(new Event("change"));
    expect(h.inst.subtitleDisplay).toBe(false);
  });

  for (const code of [401, 403]) {
    it(`stops with the revoked state on a ${code} from the edge`, () => {
      const stops: unknown[] = [];
      el.addEventListener("cipherframe:stop", (e) => stops.push((e as CustomEvent).detail));
      el.load(session);
      fire("hlsError", { fatal: false, type: "networkError", details: "keyLoadError", response: { code } });
      expect(el.state).toBe("revoked");
      expect(stops).toEqual([{ reason: "revoked" }]);
      expect(h.inst.destroy).toHaveBeenCalled();
      expect(el.shadowRoot?.querySelector(".status")?.textContent).toMatch(/revoked/);
      expect(sel(".play").disabled).toBe(true);
    });
  }

  it("a fatal non-auth error becomes the error state after retries", () => {
    el.load(session);
    for (let i = 0; i < 5; i++) fire("hlsError", { fatal: true, type: "networkError", details: "manifestLoadError", response: { code: 500 } });
    expect(el.state).toBe("error");
  });

  it("rejects a session without a manifest_url or token", () => {
    expect(() => el.load({} as never)).toThrow(TypeError);
  });

  it("has labelled controls", () => {
    for (const s of [".play", ".seek", ".speed", ".quality", ".subtitles", ".fs"]) {
      expect(sel(s).getAttribute("aria-label"), s).toBeTruthy();
    }
  });
});
