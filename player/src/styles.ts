// Customise with the --cf-* custom properties or the ::part() names (see README.md).
export const css = `
:host { display: block; position: relative; aspect-ratio: 16 / 9; background: var(--cf-bg, #000); color: var(--cf-fg, #fff);
  font: var(--cf-font, 14px/1.4 system-ui, sans-serif); }
.wrap { position: absolute; inset: 0; overflow: hidden; background: inherit; }
video { position: absolute; inset: 0; width: 100%; height: 100%; object-fit: contain; background: var(--cf-bg, #000); }
video:focus-visible, button:focus-visible, select:focus-visible, input:focus-visible {
  outline: 2px solid var(--cf-focus, #6ea8fe); outline-offset: 2px; }
.overlay { position: absolute; overflow: hidden; pointer-events: none; }
.status { position: absolute; inset: 0; display: none; align-items: center; justify-content: center; text-align: center;
  padding: 1rem; background: rgba(0, 0, 0, .78); font-size: 1.1em; }
:host([state="expired"]) .status, :host([state="revoked"]) .status, :host([state="error"]) .status,
:host([state="ended"]) .status { display: flex; }
.controls { position: absolute; left: 0; right: 0; bottom: 0; display: flex; align-items: center; gap: .5rem; padding: .5rem;
  background: var(--cf-controls-bg, linear-gradient(transparent, rgba(0, 0, 0, .75))); }
button, select { color: inherit; background: var(--cf-control-bg, rgba(255, 255, 255, .14)); border: 0;
  border-radius: var(--cf-radius, 4px); padding: .35rem .6rem; font: inherit; min-height: 2rem; cursor: pointer; }
select option { color: #000; }
button:disabled, select:disabled, input:disabled { opacity: .4; cursor: default; }
.time { font-variant-numeric: tabular-nums; white-space: nowrap; }
.seekwrap { position: relative; flex: 1; min-width: 4rem; }
input[type=range] { width: 100%; accent-color: var(--cf-accent, #6ea8fe); margin: 0; min-height: 2rem; }
.preview { position: absolute; bottom: 2.4rem; display: none; pointer-events: none; background: #000 no-repeat;
  border: 1px solid rgba(255, 255, 255, .5); border-radius: var(--cf-radius, 4px); }
.preview span { position: absolute; bottom: 0; left: 0; right: 0; text-align: center; font-size: 12px;
  background: rgba(0, 0, 0, .6); font-variant-numeric: tabular-nums; }
@media (prefers-reduced-motion: no-preference) { button, select { transition: background-color .15s; } }
`;
