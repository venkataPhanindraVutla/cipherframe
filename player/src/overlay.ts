import { deriveParams, placement, position, type DriftParams } from "./drift";
import type { OverlayConfig } from "./types";

const pad = (n: number) => String(n).padStart(2, "0");

/** Fills {date} (YYYY-MM-DD) and {time} (HH:MM:SS) in UTC. The result is only ever used as text. */
export function renderTemplate(template: string, now: Date): string {
  const date = `${now.getUTCFullYear()}-${pad(now.getUTCMonth() + 1)}-${pad(now.getUTCDate())}`;
  const time = `${pad(now.getUTCHours())}:${pad(now.getUTCMinutes())}:${pad(now.getUTCSeconds())}`;
  return template.replaceAll("{date}", date).replaceAll("{time}", time);
}

/** The rectangle the picture covers inside an `object-fit: contain` box. */
export function containRect(boxW: number, boxH: number, videoW: number, videoH: number) {
  if (!videoW || !videoH) return { left: 0, top: 0, width: boxW, height: boxH };
  const scale = Math.min(boxW / videoW, boxH / videoH);
  const width = videoW * scale;
  const height = videoH * scale;
  return { left: (boxW - width) / 2, top: (boxH - height) / 2, width, height };
}

/** The drifting text. `layer` is positioned over the picture; call `update` once per second and on resize. */
export class Overlay {
  private readonly params: DriftParams;
  private readonly span = document.createElement("span");
  private readonly started = performance.now();

  constructor(
    private readonly layer: HTMLElement,
    private readonly config: OverlayConfig,
  ) {
    this.params = deriveParams(config.drift.seed);
    const color = /^#[0-9A-Fa-f]{6}$/.test(config.style.color) ? config.style.color : "#FFFFFF";
    Object.assign(this.span.style, {
      position: "absolute",
      whiteSpace: "nowrap",
      color,
      opacity: String(Math.min(0.8, Math.max(0.05, config.style.opacity))),
      textShadow: "0 0 2px rgba(0,0,0,.6)",
      pointerEvents: "none",
      userSelect: "none",
    });
    this.span.setAttribute("part", "overlay-text");
    this.span.setAttribute("aria-hidden", "true");
    layer.append(this.span);
  }

  update(now = new Date()): void {
    const w = this.layer.clientWidth;
    const h = this.layer.clientHeight;
    if (!w || !h) return;
    this.span.textContent = renderTemplate(this.config.template, now); // text, never HTML
    this.span.style.fontSize = `${this.config.style.font_size_fraction * h}px`;
    const t = (performance.now() - this.started) / 1000;
    const { u, v } = position(this.params, t, this.config.drift.period_seconds);
    const boxW = this.span.offsetWidth / w;
    const boxH = this.span.offsetHeight / h;
    const p = placement(u, v, boxW, boxH, this.config.drift.margin);
    this.span.style.left = `${p.x * 100}%`;
    this.span.style.top = `${p.y * 100}%`;
  }

  remove(): void {
    this.span.remove();
  }
}
