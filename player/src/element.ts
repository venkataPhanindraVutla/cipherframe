import Hls from "hls.js";
import { Overlay, containRect } from "./overlay";
import { SessionController } from "./session";
import { css } from "./styles";
import { cueAt, parseThumbnails, type ThumbCue } from "./thumbs";
import type { PlaybackSession, PlayerState, StopReason } from "./types";

const SPEEDS = [0.5, 0.75, 1, 1.25, 1.5, 2];

const MESSAGES: Record<string, string> = {
  expired: "This session has expired. Start a new one to keep watching.",
  revoked: "This session was revoked. Playback has stopped.",
  ended: "This session has ended.",
  error: "Playback failed.",
};

const fmt = (s: number) => {
  if (!Number.isFinite(s)) return "0:00";
  const t = Math.floor(s);
  const h = Math.floor(t / 3600);
  const mm = String(Math.floor((t % 3600) / 60)).padStart(h ? 2 : 1, "0");
  return `${h ? `${h}:` : ""}${mm}:${String(t % 60).padStart(2, "0")}`;
};

/** Replaces a select's options. `current` stays selected. */
export function fillSelect(select: HTMLSelectElement, options: { value: string; label: string }[], current: string) {
  select.replaceChildren(
    ...options.map((o) => {
      const el = document.createElement("option");
      el.value = o.value;
      el.textContent = o.label;
      return el;
    }),
  );
  select.value = current;
}

const TEMPLATE = `
<style>${css}</style>
<div class="wrap" part="container">
  <video part="video" playsinline tabindex="0" aria-label="Video"></video>
  <div class="overlay" part="overlay"></div>
  <div class="status" part="status" role="status" aria-live="polite"></div>
  <div class="controls" part="controls" role="group" aria-label="Player controls">
    <button type="button" part="play" class="play" aria-label="Play">Play</button>
    <span class="time" part="time" aria-hidden="true">0:00 / 0:00</span>
    <div class="seekwrap">
      <input type="range" part="seek" class="seek" min="0" max="0" step="0.1" value="0" aria-label="Seek" disabled>
      <div class="preview" part="preview"><span></span></div>
    </div>
    <select part="speed" class="speed" aria-label="Playback speed"></select>
    <select part="quality" class="quality" aria-label="Quality"></select>
    <select part="subtitles" class="subtitles" aria-label="Subtitles"></select>
    <button type="button" part="fullscreen" class="fs" aria-label="Fullscreen" aria-pressed="false">Fullscreen</button>
  </div>
</div>`;

/**
 * `<cipherframe-player>`: plays one playback session. The host's backend creates the session (the API
 * key never reaches the browser) and hands the response to `load(session)` or the `session` property.
 */
export class CipherframePlayer extends HTMLElement {
  private readonly $ = <T extends Element = HTMLElement>(sel: string) => this.shadowRoot?.querySelector(sel) as T;
  private ctrl: SessionController | undefined;
  private hls: Hls | undefined;
  private overlay: Overlay | undefined;
  private tick: ReturnType<typeof setInterval> | undefined;
  private objectUrls: string[] = [];
  private cues: ThumbCue[] = [];
  private spriteUrl = "";
  private resizeObs: ResizeObserver | undefined;
  private netRetries = 0;
  private generation = 0;

  private readonly onPageHide = () => void this.end();
  private readonly onVisible = () => {
    if (document.visibilityState === "visible") void this.ctrl?.heartbeat();
  };
  private readonly onFsChange = () => {
    const on = this.shadowRoot?.fullscreenElement === this.$(".wrap") || document.fullscreenElement === this;
    this.$(".fs").setAttribute("aria-pressed", String(on));
  };

  constructor() {
    super();
    this.attachShadow({ mode: "open" }).innerHTML = TEMPLATE;
    this.wire();
  }

  get state(): PlayerState {
    return (this.getAttribute("state") ?? "idle") as PlayerState;
  }

  /** Assigning a session is the same as `load(session)`. */
  set session(s: PlaybackSession) {
    this.load(s);
  }

  /** The video element, for hosts that need `currentTime` and friends. */
  get video(): HTMLVideoElement {
    return this.$<HTMLVideoElement>("video");
  }

  connectedCallback() {
    if (!this.hasAttribute("state")) this.setAttribute("state", "idle"); // not in the constructor: the spec forbids it
    addEventListener("pagehide", this.onPageHide);
    document.addEventListener("visibilitychange", this.onVisible);
    document.addEventListener("fullscreenchange", this.onFsChange);
  }

  disconnectedCallback() {
    removeEventListener("pagehide", this.onPageHide);
    document.removeEventListener("visibilitychange", this.onVisible);
    document.removeEventListener("fullscreenchange", this.onFsChange);
    // Moving the element in the DOM disconnects and reconnects it; only a real removal ends the session.
    queueMicrotask(() => {
      if (!this.isConnected) void this.end();
    });
  }

  /** Starts playing a session exactly as `POST /v1/playback-sessions` returned it. */
  load(session: PlaybackSession): void {
    if (!session || typeof session.manifest_url !== "string" || typeof session.token !== "string") {
      throw new TypeError("load() needs the session response: manifest_url and token are required");
    }
    this.teardown();
    const gen = this.generation;
    this.setControlsDisabled(false);
    this.setState("loading");
    const ctrl = new SessionController(session, {
      onTokenRefresh: (expiresAt) => this.emit("cipherframe:tokenrefresh", { expiresAt }),
      onStop: (reason) => this.onStop(reason),
    });
    this.ctrl = ctrl;
    const video = this.video;

    if (Hls.isSupported()) {
      const Base = Hls.DefaultConfig.loader;
      type LoadArgs = Parameters<InstanceType<typeof Base>["load"]>;
      // In url mode the playlists carry the token they were issued with; swap in the current one.
      class TokenLoader extends Base {
        override load(...[context, config, callbacks]: LoadArgs) {
          context.url = ctrl.authorize(context.url).url;
          super.load(context, config, callbacks);
        }
      }
      const hls = new Hls({
        xhrSetup: (xhr, url) => {
          const { headers } = ctrl.authorize(url);
          for (const [k, v] of Object.entries(headers)) xhr.setRequestHeader(k, v);
        },
        ...(ctrl.urlMode ? { loader: TokenLoader } : {}),
      });
      this.hls = hls;
      this.bindHls(hls, ctrl);
      hls.attachMedia(video);
      hls.loadSource(session.manifest_url);
    } else if (ctrl.urlMode && video.canPlayType("application/vnd.apple.mpegurl")) {
      // Safari without Media Source Extensions: native HLS cannot set headers, so only url mode works (ADR 0050).
      video.src = session.manifest_url;
    } else {
      this.fail("This browser cannot play protected streams (needs Media Source Extensions, or token_in_url).");
      return;
    }

    if (session.overlay) {
      try {
        this.overlay = new Overlay(this.$(".overlay"), session.overlay);
      } catch {
        this.emit("cipherframe:error", { message: "overlay configuration is invalid; overlay not drawn" });
      }
    }
    this.layoutOverlay();
    this.tick = setInterval(() => this.overlay?.update(), 1000);
    ctrl.start();
    void this.loadImages(ctrl, gen);
  }

  /** Ends the session at the edge and stops. Idempotent. */
  async end(): Promise<void> {
    await this.ctrl?.end();
  }

  private emit<K extends string>(name: K, detail: unknown) {
    this.dispatchEvent(new CustomEvent(name, { detail, bubbles: true, composed: true }));
  }

  private setState(s: PlayerState) {
    this.setAttribute("state", s);
    this.$(".status").textContent = MESSAGES[s] ?? "";
    if (s in MESSAGES) this.setControlsDisabled(true);
  }

  private setControlsDisabled(disabled: boolean) {
    for (const el of this.shadowRoot?.querySelectorAll<HTMLButtonElement>("button, select, input") ?? []) el.disabled = disabled;
    if (!disabled) {
      this.$<HTMLInputElement>(".seek").disabled = !Number.isFinite(this.video.duration);
      this.$<HTMLSelectElement>(".subtitles").disabled = this.$<HTMLSelectElement>(".subtitles").options.length < 2;
    }
  }

  private fail(message: string) {
    this.setState("error");
    this.$(".status").textContent = message;
    this.emit("cipherframe:error", { message });
  }

  private onStop(reason: StopReason) {
    this.hls?.destroy();
    this.hls = undefined;
    this.video.pause();
    this.setState(reason);
    this.emit("cipherframe:stop", { reason });
  }

  private teardown() {
    this.ctrl?.close();
    this.hls?.destroy();
    this.hls = undefined;
    this.overlay?.remove();
    this.overlay = undefined;
    clearInterval(this.tick);
    for (const u of this.objectUrls) URL.revokeObjectURL(u);
    this.objectUrls = [];
    this.cues = [];
    this.spriteUrl = "";
    this.netRetries = 0;
    this.video.removeAttribute("poster");
    this.video.removeAttribute("src");
    this.generation++;
  }

  private bindHls(hls: Hls, ctrl: SessionController) {
    const E = Hls.Events;
    hls.on(E.MANIFEST_PARSED, () => {
      this.fillQuality(hls);
      this.fillSubtitles(hls);
      this.emit("cipherframe:ready", { levels: hls.levels.length, subtitles: hls.subtitleTracks.length });
    });
    hls.on(E.SUBTITLE_TRACKS_UPDATED, () => this.fillSubtitles(hls));
    hls.on(E.ERROR, (_e, data) => {
      const code = data.response?.code;
      if (code === 401 || code === 403) return ctrl.deny(); // the edge refuses the session: stop at once
      if (!data.fatal) return;
      if (data.type === Hls.ErrorTypes.NETWORK_ERROR && this.netRetries++ < 3) return hls.startLoad();
      if (data.type === Hls.ErrorTypes.MEDIA_ERROR && this.netRetries++ < 3) return hls.recoverMediaError();
      hls.destroy();
      this.hls = undefined;
      this.fail(`Playback failed (${data.details}).`);
    });
  }

  private fillQuality(hls: Hls) {
    const opts = [{ value: "-1", label: "Auto" }];
    hls.levels.forEach((l, i) => opts.push({ value: String(i), label: l.height ? `${l.height}p` : `${Math.round(l.bitrate / 1000)} kbps` }));
    fillSelect(this.$(".quality"), opts, String(hls.currentLevel === undefined ? -1 : hls.autoLevelEnabled ? -1 : hls.currentLevel));
  }

  private fillSubtitles(hls: Hls) {
    const opts = [{ value: "-1", label: "Off" }];
    hls.subtitleTracks.forEach((t, i) => opts.push({ value: String(i), label: t.name || t.lang || `Track ${i + 1}` }));
    fillSelect(this.$(".subtitles"), opts, String(hls.subtitleTrack ?? -1));
    this.$<HTMLSelectElement>(".subtitles").disabled = opts.length === 1;
  }

  private async loadImages(ctrl: SessionController, gen: number) {
    const get = async (name: string) => {
      try {
        const r = await ctrl.fetchEdge(name);
        return r.ok ? r : undefined; // older assets have no thumbnails (ADR 0046)
      } catch {
        return undefined;
      }
    };
    const blobUrl = async (r: Response) => {
      const u = URL.createObjectURL(await r.blob());
      if (gen !== this.generation) URL.revokeObjectURL(u);
      else this.objectUrls.push(u);
      return u;
    };
    const poster = await get("poster.jpg");
    if (poster && gen === this.generation) this.video.poster = await blobUrl(poster);
    const vtt = await get("thumbnails.vtt");
    const sprite = vtt && (await get("sprite.jpg"));
    if (vtt && sprite && gen === this.generation) {
      this.cues = parseThumbnails(await vtt.text());
      this.spriteUrl = await blobUrl(sprite);
    }
  }

  private layoutOverlay() {
    const v = this.video;
    const r = containRect(v.clientWidth, v.clientHeight, v.videoWidth, v.videoHeight);
    Object.assign(this.$(".overlay").style, { left: `${r.left}px`, top: `${r.top}px`, width: `${r.width}px`, height: `${r.height}px` });
    this.overlay?.update();
  }

  private wire() {
    const v = this.video;
    const play = this.$<HTMLButtonElement>(".play");
    const seek = this.$<HTMLInputElement>(".seek");
    const time = this.$(".time");
    const toggle = () => (v.paused ? void v.play().catch(() => undefined) : v.pause());
    const refreshTime = () => {
      const d = Number.isFinite(v.duration) ? v.duration : 0;
      time.textContent = `${fmt(v.currentTime)} / ${fmt(d)}`;
      seek.max = String(d);
      seek.value = String(v.currentTime);
      seek.setAttribute("aria-valuetext", `${fmt(v.currentTime)} of ${fmt(d)}`);
    };

    play.addEventListener("click", toggle);
    v.addEventListener("click", toggle);
    v.addEventListener("keydown", (e) => {
      if (e.key === " " || e.key === "k") (e.preventDefault(), toggle());
      else if (e.key === "ArrowLeft") v.currentTime = Math.max(0, v.currentTime - 5);
      else if (e.key === "ArrowRight") v.currentTime += 5;
    });
    v.addEventListener("play", () => {
      play.setAttribute("aria-label", "Pause");
      play.textContent = "Pause";
    });
    v.addEventListener("pause", () => {
      play.setAttribute("aria-label", "Play");
      play.textContent = "Play";
      if (!this.ctrl?.stoppedReason && !v.ended) this.setState("paused");
    });
    v.addEventListener("playing", () => this.setState("playing"));
    v.addEventListener("ended", () => this.setState("paused"));
    v.addEventListener("timeupdate", refreshTime);
    v.addEventListener("durationchange", () => {
      seek.disabled = !Number.isFinite(v.duration) || !!this.ctrl?.stoppedReason;
      refreshTime();
    });
    v.addEventListener("loadedmetadata", () => this.layoutOverlay());
    if (typeof ResizeObserver !== "undefined") {
      this.resizeObs = new ResizeObserver(() => this.layoutOverlay());
      this.resizeObs.observe(v);
    }
    seek.addEventListener("input", () => (v.currentTime = Number(seek.value)));

    const preview = this.$<HTMLElement>(".preview");
    seek.addEventListener("pointermove", (e) => {
      const rect = seek.getBoundingClientRect();
      const t = Math.min(1, Math.max(0, (e.clientX - rect.left) / (rect.width || 1))) * (Number.isFinite(v.duration) ? v.duration : 0);
      const cue = cueAt(this.cues, t);
      preview.firstElementChild!.textContent = fmt(t);
      if (cue && this.spriteUrl) {
        Object.assign(preview.style, {
          display: "block",
          width: `${cue.w}px`,
          height: `${cue.h}px`,
          backgroundImage: `url("${this.spriteUrl}")`,
          backgroundPosition: `-${cue.x}px -${cue.y}px`,
          left: `${Math.min(Math.max(0, e.clientX - rect.left - cue.w / 2), rect.width - cue.w)}px`,
        });
      }
    });
    seek.addEventListener("pointerleave", () => (preview.style.display = "none"));

    const speed = this.$<HTMLSelectElement>(".speed");
    fillSelect(speed, SPEEDS.map((s) => ({ value: String(s), label: `${s}x` })), "1");
    speed.addEventListener("change", () => (v.playbackRate = Number(speed.value)));

    this.$<HTMLSelectElement>(".quality").addEventListener("change", (e) => {
      if (this.hls) this.hls.currentLevel = Number((e.target as HTMLSelectElement).value);
    });
    this.$<HTMLSelectElement>(".subtitles").addEventListener("change", (e) => {
      if (!this.hls) return;
      this.hls.subtitleTrack = Number((e.target as HTMLSelectElement).value);
      this.hls.subtitleDisplay = this.hls.subtitleTrack >= 0;
    });
    fillSelect(this.$(".quality"), [{ value: "-1", label: "Auto" }], "-1");
    fillSelect(this.$(".subtitles"), [{ value: "-1", label: "Off" }], "-1");
    this.$<HTMLSelectElement>(".subtitles").disabled = true;

    // The wrapper goes fullscreen, not the video, so the overlay stays in the picture.
    this.$(".fs").addEventListener("click", () => {
      if (document.fullscreenElement) void document.exitFullscreen();
      else void this.requestFullscreen?.().catch(() => undefined);
    });
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "cipherframe-player": CipherframePlayer;
  }
}
