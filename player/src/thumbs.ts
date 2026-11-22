export interface ThumbCue {
  start: number;
  end: number;
  x: number;
  y: number;
  w: number;
  h: number;
}

function seconds(ts: string): number {
  const parts = ts.trim().split(":").map(Number);
  return parts.reduce((acc, p) => acc * 60 + p, 0);
}

/** Parses thumbnails.vtt: cues whose payload is `sprite.jpg#xywh=x,y,w,h` (ADR 0046). Other cues are skipped. */
export function parseThumbnails(vtt: string): ThumbCue[] {
  const cues: ThumbCue[] = [];
  const lines = vtt.replace(/\r/g, "").split("\n");
  for (let i = 0; i < lines.length; i++) {
    const m = /^([\d:.]+)\s+-->\s+([\d:.]+)/.exec(lines[i] ?? "");
    const xywh = /#xywh=(\d+),(\d+),(\d+),(\d+)/.exec(lines[i + 1] ?? "");
    if (!m || !xywh) continue;
    const [x, y, w, h] = xywh.slice(1).map(Number) as [number, number, number, number];
    cues.push({ start: seconds(m[1] as string), end: seconds(m[2] as string), x, y, w, h });
  }
  return cues;
}

/** The cue showing at `t` (the last cue for a time past the end). */
export function cueAt(cues: ThumbCue[], t: number): ThumbCue | undefined {
  return cues.find((c) => t >= c.start && t < c.end) ?? (t >= (cues.at(-1)?.end ?? Infinity) ? cues.at(-1) : undefined);
}
