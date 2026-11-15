# Overlay drift conformance vectors

The overlay watermark drifts across the frame along a path that depends only on the session's
`overlay.drift.seed` (ADR 0048). Every player (the TypeScript player, the SDKs) must reproduce it
exactly. `drift.json` holds the vectors; the Go reference is `internal/overlay` and checks them in
`TestVectors`.

The overlay is deterrence only. The path makes a recording hard to crop and shows when it was made;
a viewer who controls the player can still remove it.

## Algorithm `lissajous-v1`

Inputs: `seed`, 16 lower-case hexadecimal characters (8 bytes `b[0..7]`), and `t`, the seconds since the
player received the session response, measured on a monotonic clock.

1. Frequencies: `(kx, ky)` is entry `b[0] mod 6` of `[(1,2), (2,1), (1,3), (3,1), (2,3), (3,2)]`.
2. Phases: `phase_x = 2*pi * uint16_be(b[1], b[2]) / 65536` and `phase_y = 2*pi * uint16_be(b[3], b[4]) / 65536`.
   `b[5..7]` are reserved and ignored.
3. Position, as fractions of the room the text moves in:
   `w = 2*pi * t / 240`, `u = 0.5 + 0.5*sin(kx*w + phase_x)`, `v = 0.5 + 0.5*sin(ky*w + phase_y)`.
   `u` and `v` are in `[0, 1]`. The curve is closed with a period of 240 seconds, and its speed never
   exceeds `pi * 3 / 240`, about 0.039 of the room per second (the frame is crossed in about 25 seconds at
   the fastest, usually far slower).
4. Placement: with `box_w` and `box_h` the text's width and height as fractions of the frame (measure the
   text as drawn, at `font_size_fraction` of the video height), and `margin` = 0.02 (the response's
   `drift.margin`), the box's top-left corner is
   `x = margin + u * max(0, 1 - box_w - 2*margin)` and `y = margin + v * max(0, 1 - box_h - 2*margin)`,
   as fractions of the frame width and height. The box therefore stays at least `margin` from every edge
   (a box wider than the room sits at the margin). Re-measure the box when the text changes, for
   example every second when `{time}` changes: `u` and `v` do not change.

The seed is the first 8 bytes of `SHA-256("cipherframe/overlay/seed/v1" 0x00 || session ID text)`. It is
one way, so the seed reveals nothing usable about the session ID. A player never derives it: it uses the
`seed` of the response.

## `drift.json`

- `vectors[]`: a `seed`, the derived `kx`, `ky`, `phase_x`, `phase_y`, and `positions[]` of `{t, u, v}`.
- `placements[]`: `{u, box, offset}` for step 4.
- `tolerance`: 1e-9. Compare with an absolute difference; the sine of different math libraries differs in
  the last bits.

An implementation passes when, for every vector, its derived parameters and positions are within the
tolerance. To change the algorithm, add a new `algorithm` name; never change `lissajous-v1`.
