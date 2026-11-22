import { describe, expect, it } from "vitest";
import { cueAt, parseThumbnails } from "../src/thumbs";

const vtt = `WEBVTT

00:00:00.000 --> 00:00:10.000
sprite.jpg#xywh=0,0,160,90

00:00:10.000 --> 00:01:05.500
sprite.jpg#xywh=160,0,160,90
`;

describe("thumbnails.vtt", () => {
  it("parses the cues", () => {
    expect(parseThumbnails(vtt)).toEqual([
      { start: 0, end: 10, x: 0, y: 0, w: 160, h: 90 },
      { start: 10, end: 65.5, x: 160, y: 0, w: 160, h: 90 },
    ]);
  });
  it("finds the cue for a time, and the last one past the end", () => {
    const cues = parseThumbnails(vtt);
    expect(cueAt(cues, 3)?.x).toBe(0);
    expect(cueAt(cues, 10)?.x).toBe(160);
    expect(cueAt(cues, 999)?.x).toBe(160);
    expect(cueAt([], 1)).toBeUndefined();
  });
});
