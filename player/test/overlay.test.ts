import { describe, expect, it } from "vitest";
import { Overlay, containRect, renderTemplate } from "../src/overlay";
import type { OverlayConfig } from "../src/types";

const cfg = (template: string): OverlayConfig => ({
  template,
  style: { opacity: 0.25, font_size_fraction: 0.03, color: "#FFFFFF" },
  drift: { algorithm: "lissajous-v1", seed: "0123456789abcdef", period_seconds: 240, margin: 0.02 },
});

describe("renderTemplate", () => {
  it("fills date and time in UTC", () => {
    const now = new Date("2026-03-04T23:59:07Z");
    expect(renderTemplate("K7QH2M9X {date} {time} UTC", now)).toBe("K7QH2M9X 2026-03-04 23:59:07 UTC");
    expect(renderTemplate("{time} {time}", now)).toBe("23:59:07 23:59:07");
  });

  it("does not change other text", () => {
    expect(renderTemplate("<b>{date}</b>", new Date("2026-01-02T00:00:00Z"))).toBe("<b>2026-01-02</b>");
  });
});

describe("Overlay", () => {
  it("draws the template as text, never as markup", () => {
    const layer = document.createElement("div");
    document.body.append(layer);
    Object.defineProperty(layer, "clientWidth", { value: 640 });
    Object.defineProperty(layer, "clientHeight", { value: 360 });
    new Overlay(layer, cfg('<img src=x onerror="alert(1)"> {time}')).update(new Date("2026-01-01T10:20:30Z"));
    expect(layer.querySelector("img")).toBeNull();
    expect(layer.textContent).toBe('<img src=x onerror="alert(1)"> 10:20:30');
    expect(layer.querySelector("span")?.style.left).toMatch(/%$/);
  });
});

describe("containRect", () => {
  it("letterboxes a 16:9 picture in a square box", () => {
    expect(containRect(100, 100, 1600, 900)).toEqual({ left: 0, top: 21.875, width: 100, height: 56.25 });
  });
  it("fills the box before the size is known", () => {
    expect(containRect(100, 50, 0, 0)).toEqual({ left: 0, top: 0, width: 100, height: 50 });
  });
});
