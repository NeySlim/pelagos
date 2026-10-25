# Motion primitives (motion system v2)

Motion traces signals; it never decorates. Something moves because the UI received
an event (WebSocket message, API answer, counter sample), and nothing moves when the
cluster is idle. Feature code builds on the primitives below; keep their APIs small.

## Rules

- **Levels.** `useMotionLevel()` returns `full`, `reduced` or `off` (the `animations`
  preference, lowered by `prefers-reduced-motion`). It is written as `data-motion` on
  `<html>`; the `ambient` preference (`on`, `off`) as `data-ambient`; a hidden tab
  sets `data-page-hidden`. Every primitive honors them:
  - `full`: everything below;
  - `reduced`: no travel, no scale, no spring; fades and color changes of 150 ms or
    less that carry a state remain; numbers jump; canvases redraw on events only;
  - `off`: everything is instant except spinners and the running step arc.
- **Properties.** `transform`, `opacity`, `stroke-dashoffset` and canvas only;
  `grid-template-rows` for folds. Never `width`, `height`, `top`, `left`, `filter`,
  `box-shadow` or blur.
- **Curves** (`styles/motion.css`, `lib/motion.js`): beziers for UI entries and exits
  (`--ease-out`, `--ease-in-out`, `--ease-exit`), `--spring` for things that move and
  stop (cursors, ink, reordered rows), `--settle` for things that land (digits, ticks,
  markers), `linear` for time and transport (paper, pulses, rails, sweeps). One thing
  always moves with the same curve.
- **Durations**: `--d-instant` 70, `--d-fast` 110, `--d-quick` 150, `--d-base` 200,
  `--d-panel` 240, `--d-page` 260, `--d-slow` 400, `--d-moment` 600 ms
  (`DURATIONS` in JS). Routine UI stays under 300 ms.
- **One loop.** Per-frame work goes through `useAnimationLoop`: one shared
  `requestAnimationFrame`, registered only at `full` on a visible page. Budget: 2 ms of
  script per frame for everything on screen (`loopStats().p95`, `window.__pelagosLoop()`
  in development). `useCountUp` and `SignalLink` register on it too; nothing else calls
  `requestAnimationFrame` per frame.
- **Accessibility.** Decorative marks are `aria-hidden`; numbers expose their final
  value; a state is always a word next to its color.

## Hooks

| Hook | Use |
| --- | --- |
| `useMotionLevel()` | the resolved level |
| `useAmbient()` | true while ambient layers may move |
| `useAnimationLoop(fn, { enabled })` | `fn(time, dt)` every frame on the shared loop; returns whether it runs |
| `useCanvas(draw)` | `{ ref, redraw }`: a canvas sized by `ResizeObserver`, DPR capped at 2, `draw({ ctx, width, height })` on resize and `redraw()` |
| `useBootSequence()` | used once by `AppShell`: `html.boot` on the first shell mount of a session |

## Components

| Component | Props | Notes |
| --- | --- | --- |
| `RollingNumber` | `value`, `format?`, `direction?`, `delta = true` | odometer: only changed characters roll, up or down; a unit rolls like a character; a hairline lights under a change |
| `SwapText` | `text` | crossfade of a label (states, link labels) |
| `Readout` | `channel`, `unit`, `rate`, `count` | `CH1 · q/s · 0.25 S/s · n 00142`, the count rolls |
| `Ruler` | `max`, `count = 4`, `format` | value ruler for the right edge of a strip; round ticks glide when `max` changes |
| `ScaleBar` | `ratio`, `label` | 60 px reference scaled to a time span, label crossfades |
| `Checklist` | `items: [{ id, label, detail?, state, ms? }]` | checks draw themselves, side rail fills, `n/total` rolls |
| `StepRail` | `steps: [{ id, label, state, ms?, nodes?: [{ name, state, durationMs? }] }]`, `reverse` | 2 px rail filled linearly by step; node chip underline fills over the real duration; `reverse` walks back in amber |
| `CheckMark` | `state` | the mark alone |
| `SignalLink` | `state: 'ok' \| 'down'`, `rate`, `tickTone`, `direction`, `labelTop`, `labelBottom`; ref `pulse({ tone, dir })`, `transfer({ tone, dir, label, durationMs })` | canvas link between two nodes; Poisson ticks at `rate` per second (at most 4), pulses 600 ms linear, transfer head and tail 300 ms apart; red dashes when down; returns `false` when nothing travels (below full, or down) |
| `RowEnter` | a `<tr>` with its cells, `highlight = true` | unfolds through grid rows, content fades in 110 ms later, highlight 1.2 s (`--fx-row-hl`) |
| `RowLeave` | a `<tr>`, `onLeft` | folds (fades below full), then `onLeft()` once |
| `NavCursor` | `container` ref, `activeKey`, `layoutKey`, `selector` | 2 px cursor gliding on the spring, stretched while travelling (Instrument only) |
| `TabInk` | `container` ref, `activeKey`, `selector` | ink sliding and resizing under the active tab (Instrument only) |
| `Skeleton`, `SkeletonTable` | `lines` / `columns`, `rows` | placeholders at the final geometry and a calibration sweep (600 ms once, then 1.4 s while waiting); first load only |
| `AmbientScreen` | | graticule drifting at the trace paper speed, breathing over 12 s, faint contours; still unless `full` and `ambient` on; absent when ambient is off |
| `AmbientTile` | `children` | layer under a tile body (`TileFrame` `ambient` prop); holds the canvases below |
| `AmbientWave`, `AmbientSpectrum`, `AmbientDots` | `rate`, `peak` / `values` / `pulse` | tile canvases: wave amplitude is the query rate, spectrum the last 28 lease samples, dot matrix with hairline mesh that ripples once per `pulse` change. About 30 fps on the shared loop at `full`; one static frame (redrawn on new data) below; nothing when ambient is off or the family is not Instrument |
| `RegMarks`, `Sweep` | `pulse` / `trigger` | corner brackets pulse once per event; a calibration sweep crosses the tile per refresh (`TileFrame` reads per-tile sweeps, event pulses and reading order from `TileRefresh`, fed by the dashboard page) |

`Ruler` takes `cursor` (marker following the latest sample) and `inset`.

Helpers (`primitives.js`): `flipRows(rows, mutate, level?)` measures, runs `mutate`
(synchronous DOM update, e.g. `flushSync`) and glides moved rows on the spring;
`rollCells`, `rollDirection`, `niceTicks`, `progressOf`, `poissonGap`, `PULSE_MS`,
`MAX_TICKS`, `STEP_STATES`.

`DataTable` uses `SkeletonTable` while loading, `flipRows` on a local sort and
`RowEnter` for rows that appear after the first load when `animateInserts` is set.

## Wiring left to feature lots

These primitives are tested in isolation; each gets an e2e check when a page uses it.

- `Checklist` and `StepRail`: plan preview, apply and job progress (procedures lot).
- `RowEnter` and `RowLeave`: set `animateInserts` on live tables (leases, records, jobs).
- `RollingNumber`, `Readout`, `Ruler`, `ScaleBar`, `SignalLink`: the dashboard cluster
  trace, which replaces the Mission radar; under Instrument the radar is a still frame.
- Hover row actions on tables.

## Navigation choreography

- `lib/viewTransition.js`: `withViewTransitions(router)` wraps `router.navigate` so a page
  change (another nav entry, or a list and its detail page) runs in a view transition;
  `runThemeTransition` does the same for the theme switch (root cross-fade). Instrument
  only: full travels 4 px in the direction of `data-dir`, reduced cross-fades 100 ms, off
  never starts one. `styles/transitions.css` holds the pseudo-element rules.
- `SharedElement` / `useSharedName(name, to)`: a node takes its `view-transition-name` only
  while a transition to or from `to` runs (zone name, zones panel).
- `DataTable` glides rows whose order changed (any cause) and shows a column band (one
  delegated listener, `hooks/useColumnBand.js`); `[data-magnetic]` primary buttons lean
  by at most 1 px (`hooks/useMagnetic.js`).
- A running view transition swallows pointer events: e2e tests wait for `data-vt` to clear.

## Choices

- **RollingNumber, not NumberFlow.** The odometer is 60 lines, rolls the unit as a
  character, draws the change hairline and follows our levels; NumberFlow would add a
  dependency (a contract change) for `Intl` formats we pass in already formatted.
- **No Motion library.** FLIP of table rows is `flipRows`; springs are CSS `linear()`
  sampled from `lib/motion.js`, so CSS and canvas share the same curve.

The Mission Control primitives (`RadarRing`, `PulsingHalo`, `FlowLine`, `Reticle`,
`AppBackdrop`) stay for that family; their styles only apply under its
`data-effects`.
