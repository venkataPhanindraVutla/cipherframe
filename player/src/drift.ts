// lissajous-v1 (ADR 0048, spec/test-vectors/overlay/README.md). Never change the maths: add a new
// algorithm name instead.

const FREQUENCIES: readonly (readonly [number, number])[] = [
  [1, 2],
  [2, 1],
  [1, 3],
  [3, 1],
  [2, 3],
  [3, 2],
];

export interface DriftParams {
  kx: number;
  ky: number;
  phaseX: number;
  phaseY: number;
}

/** Derives the path parameters from the response's 16 hexadecimal character seed. */
export function deriveParams(seed: string): DriftParams {
  if (!/^[0-9a-f]{16}$/.test(seed)) throw new Error("overlay drift seed must be 16 lower-case hex characters");
  const b = Array.from({ length: 8 }, (_, i) => parseInt(seed.slice(i * 2, i * 2 + 2), 16));
  const [kx, ky] = FREQUENCIES[(b[0] as number) % FREQUENCIES.length] as readonly [number, number];
  const u16 = (hi: number, lo: number) => ((b[hi] as number) << 8) | (b[lo] as number);
  return {
    kx,
    ky,
    phaseX: (2 * Math.PI * u16(1, 2)) / 65536,
    phaseY: (2 * Math.PI * u16(3, 4)) / 65536,
  };
}

/** Position as fractions of the room the text moves in, `t` seconds after the session arrived. */
export function position(p: DriftParams, t: number, periodSeconds = 240): { u: number; v: number } {
  const w = (2 * Math.PI * t) / periodSeconds;
  return {
    u: 0.5 + 0.5 * Math.sin(p.kx * w + p.phaseX),
    v: 0.5 + 0.5 * Math.sin(p.ky * w + p.phaseY),
  };
}

/** Top-left corner of the text box, as fractions of the frame; the box keeps `margin` from every edge. */
export function placement(
  u: number,
  v: number,
  boxW: number,
  boxH: number,
  margin: number,
): { x: number; y: number } {
  return {
    x: margin + u * Math.max(0, 1 - boxW - 2 * margin),
    y: margin + v * Math.max(0, 1 - boxH - 2 * margin),
  };
}
