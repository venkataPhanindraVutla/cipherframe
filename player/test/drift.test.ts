import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { deriveParams, placement, position } from "../src/drift";

interface Vectors {
  period_seconds: number;
  tolerance: number;
  vectors: { seed: string; kx: number; ky: number; phase_x: number; phase_y: number; positions: { t: number; u: number; v: number }[] }[];
  placements: { u: number; box: number; offset: number }[];
}

const d = JSON.parse(readFileSync(resolve(process.cwd(), "../spec/test-vectors/overlay/drift.json"), "utf8")) as Vectors;

describe("lissajous-v1 conformance vectors", () => {
  for (const v of d.vectors) {
    it(`seed ${v.seed}`, () => {
      const p = deriveParams(v.seed);
      expect(p.kx).toBe(v.kx);
      expect(p.ky).toBe(v.ky);
      expect(Math.abs(p.phaseX - v.phase_x)).toBeLessThanOrEqual(d.tolerance);
      expect(Math.abs(p.phaseY - v.phase_y)).toBeLessThanOrEqual(d.tolerance);
      for (const pos of v.positions) {
        const got = position(p, pos.t, d.period_seconds);
        expect(Math.abs(got.u - pos.u), `u at t=${pos.t}`).toBeLessThanOrEqual(d.tolerance);
        expect(Math.abs(got.v - pos.v), `v at t=${pos.t}`).toBeLessThanOrEqual(d.tolerance);
      }
    });
  }

  it("placements", () => {
    expect(d.placements.length).toBeGreaterThan(0);
    for (const pl of d.placements) {
      const got = placement(pl.u, 0, pl.box, 0.1, 0.02);
      expect(Math.abs(got.x - pl.offset)).toBeLessThanOrEqual(d.tolerance);
    }
  });

  it("rejects a malformed seed", () => {
    expect(() => deriveParams("xyz")).toThrow();
    expect(() => deriveParams("0123456789ABCDEF")).toThrow();
  });
});
