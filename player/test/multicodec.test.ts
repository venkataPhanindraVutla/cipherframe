import { readFileSync } from "node:fs";
import { join } from "node:path";
import Hls, { type ManifestParsedData } from "hls.js";
import { afterEach, describe, expect, it, vi } from "vitest";

// The real hls.js (not the stand-in of element.test.ts) reading a master playlist that lists H.264,
// HEVC and AV1 renditions, the way a Cipherframe tenant with extra_codecs gets it (ADR 0064). The
// player has no codec setting: hls.js drops the variants the browser cannot decode and plays the rest.
// MediaSource is stubbed, because jsdom has none; what it reports decodable is the test's input.

const MASTER = readFileSync(join(import.meta.dirname, "fixtures", "multi-codec-master.m3u8"), "utf8");
const URL_MASTER = "https://media.example.test/v1/play/ses_x/master.m3u8";

// A loader that answers the master from the fixture and nothing else.
class FixtureLoader {
  context: unknown;
  stats = { aborted: false, loaded: 0, retry: 0, total: 0, chunkCount: 0, bwEstimate: 0, loading: { start: 0, first: 0, end: 0 }, parsing: { start: 0, end: 0 }, buffering: { start: 0, first: 0, end: 0 } };
  load(context: { url: string }, _config: unknown, callbacks: { onSuccess: (r: { url: string; data: string }, s: unknown, c: unknown, n: unknown) => void }) {
    this.context = context;
    callbacks.onSuccess({ url: context.url, data: MASTER }, this.stats, context, null);
  }
  abort() {}
  destroy() {}
}

function supporting(decodable: (type: string) => boolean) {
  vi.stubGlobal("MediaSource", { isTypeSupported: decodable });
}

// What hls.js kept of the master: the levels of its MANIFEST_PARSED event and the level it starts on.
async function parse(): Promise<{ hls: Hls; levels: { codecs: string; height: number }[]; first: string | undefined }> {
  const hls = new Hls({ loader: FixtureLoader as never, autoStartLoad: false });
  const parsed = new Promise<ManifestParsedData>((resolve, reject) => {
    hls.on(Hls.Events.MANIFEST_PARSED, (_e, data) => resolve(data));
    hls.on(Hls.Events.ERROR, (_e, d) => reject(new Error(`${d.type} ${d.details}`)));
  });
  hls.loadSource(URL_MASTER);
  const data = await parsed;
  return {
    hls,
    levels: data.levels.map((l) => ({ codecs: l.attrs.CODECS ?? "", height: l.height })),
    first: data.levels[data.firstLevel]?.attrs.CODECS,
  };
}

afterEach(() => vi.unstubAllGlobals());

describe("a master playlist with H.264, HEVC and AV1 variants", () => {
  it("keeps only what the browser can decode: AV1 and H.264 where HEVC is not decodable", async () => {
    supporting((t) => !/hvc1|hev1/.test(t));
    const { hls, levels } = await parse();
    const families = new Set(levels.map((l) => l.codecs.split(".")[0]));
    expect([...families].sort()).toEqual(["av01", "avc1"]);
    expect(levels).toHaveLength(4); // 240p and 720p of each of the two decodable codecs
    hls.destroy();
  });

  it("keeps all three when the browser decodes HEVC too", async () => {
    supporting(() => true);
    const { hls, levels } = await parse();
    expect(new Set(levels.map((l) => l.codecs.split(".")[0]))).toEqual(new Set(["avc1", "hvc1", "av01"]));
    expect(levels).toHaveLength(6);
    hls.destroy();
  });

  it("falls back to the H.264 ladder when it is all the browser decodes", async () => {
    supporting((t) => /avc1|mp4a/.test(t));
    const { hls, levels } = await parse();
    expect(levels.map((l) => l.codecs.split(".")[0])).toEqual(["avc1", "avc1"]);
    expect(levels.map((l) => l.height)).toEqual([240, 720]);
    hls.destroy();
  });

  it("starts on a variant the browser can decode, whatever the codec", async () => {
    supporting((t) => !/hvc1|hev1/.test(t));
    const { hls, first } = await parse();
    expect(first).toMatch(/^(avc1|av01)\./);
    hls.destroy();
  });
});
