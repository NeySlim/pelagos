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
| `StepRail` | `steps: [{ id, label, detail?, state, ms?, note?, nodes?: [{ name, state, durationMs? }] }]`, `reverse`, `fillMs?` | 2 px rail filled linearly by step, `fillMs` times the current move; node chip underline fills over the real duration; `reverse` walks back in amber; `note` replaces the duration ("Reverted") |
| `CheckMark` | `state` | the mark alone |
| `SignalLink` | `state: 'ok' \| 'down'`, `rate`, `tickTone`, `direction`, `labelTop`, `labelBottom`; ref `pulse({ tone, dir })`, `tick({ tone, dir, durationMs })`, `transfer({ tone, dir, label, durationMs })` | canvas link between two nodes; Poisson ticks at `rate` per second (at most 4), pulses 600 ms linear, transfer head and tail 300 ms apart; red dashes when down; returns `false` when nothing travels (below full, or down) |
| `ClusterTrace` | `lanes`, `windowMs`, `ruler`, `names`, `readout`, `reveal`, `clockOffset`, `locale`, `labels`, `eventLabel`; ref `scrubTo(t)`, `release()`, `redraw()` | canvas strip-chart recorder: x is a function of the clock (sub-pixel paper at full, a jump per sample below), lanes `line`, `bars`, `ecg` (rows of beats, lost marks, outage), `events` (plan, rb, fail, alert, ok, axfr, repl, ha), `step`; smoothed Y scale, ruler whose tick sets crossfade with spacing, window zoom over 400 ms, magnetic playhead (7 px) with the nearest sample in a mono readout, a one-time reveal; draws on the shared loop only while visible at full |
| `ThresholdTrace` | `samples`, `thresholds: [{ v, label, bad }]`, `latches: [{ t, v, state: 'open' \| 'held' \| 'released' }]`, `windowMs`, `min`, `max`, `channel`, `unit` | one line lane of `ClusterTrace` with threshold lines and alert latches |
| `StripChart` | `points`, `kind: 'line' \| 'bars'`, `tone`, `slots = 45`, `height`, `channel`, `unit`, `rate`, `count`, `format`, `formatTime` | SVG strip: paper slides one slot over the real sample interval (linear), value `Ruler`, `+` pen on the settle curve, crosshair readout |
| `RowEnter` | a `<tr>` with its cells, `highlight = true` | unfolds through grid rows, content fades in 110 ms later, highlight 1.2 s (`--fx-row-hl`) |
| `RowLeave` | a `<tr>`, `onLeft`, `holdMs = 0` | holds `holdMs` (a struck-through alert), folds (fades below full), then `onLeft()` once |
| `Dora` | `beat?`, `play = true`, `nak`, `labels`, `values`, `transient`, `onDone` | four ticks D, O, R, A landing 90 ms apart on `--settle`, again each time `beat` changes (otherwise once when `play`); `nak` stops on a red last tick; `values` sit under the ticks; `transient` fades and unmounts once landed (table rows) |
| `HeartbeatTrace` | `beat`, `lost`, `label?` | a QRS traced (`stroke-dashoffset`, 250 ms linear) each time `beat` changes, resting at 35 %; `lost` draws a red dashed flat line |
| `UnsentQueue` | `count` | one 1 x 6 px tick per lease update waiting for the HA partner (24 at most, then `+`); new ones land, sent ones leave toward the partner 70 ms apart; the count rolls |
| `TransferBar` | `run`, `durationMs = 900`, `tone`, `label?` | a measured transport along a 1 px track: head, tail 300 ms behind, both linear; full motion only |
| `TransferSerial` | `value`, `transfer = true` | a rising serial: the transfer runs, then the serial rolls on arrival and its cell lights once; below full, or with `transfer` false, it rolls at once |
| `SerialTrace` | `lanes: [{ id, label, points: [[ms, serial]] }]`, `markers: [{ t, kind: 'plan' \| 'rollback', label? }]`, `windowMs`; ref `scrubTo(t)`, `release()` | canvas step lanes on paper that scrolls at constant speed (30 fps, paused off screen); serial rank is the step height; hover gives a magnetic playhead and a DOM readout; `scrubTo` glides the playhead back (700 ms ease-in-out) and dims what came after, `release` returns to the present |
| `IncidentTrace` | `points: [[ms, value]]`, `thresholds: [{ value, label?, tone }]`, `latches: [{ t, value, state: 'open' \| 'held' \| 'released' }]`, `from`, `to`, `min`, `max` | a value against fixed dashed thresholds; the pen writes the history once (600 ms), a latch (dot and hairline to the axis) closes on the spring where the signal crossed, hollow once held, green where it came back |
| `NavCursor` | `container` ref, `activeKey`, `layoutKey`, `selector` | 2 px cursor gliding on the spring, stretched while travelling (Instrument only) |
| `TabInk` | `container` ref, `activeKey`, `selector` | ink sliding and resizing under the active tab (Instrument only) |
| `Skeleton`, `SkeletonTable` | `lines` / `columns`, `rows` | placeholders at the final geometry and a calibration sweep (600 ms once, then 1.4 s while waiting); first load only |
| `AmbientScreen` | | graticule drifting at the trace paper speed, breathing over 12 s, faint contours; still unless `full` and `ambient` on; absent when ambient is off |
| `AmbientTile` | `children` | layer under a tile body (`TileFrame` `ambient` prop); holds the canvases below |
| `AmbientWave`, `AmbientSpectrum`, `AmbientDots` | `rate`, `peak` / `values` / `pulse` | tile canvases: wave amplitude is the query rate, spectrum the last 28 lease samples, dot matrix with hairline mesh that ripples once per `pulse` change. About 30 fps on the shared loop at `full`; one static frame (redrawn on new data) below; nothing when ambient is off or the family is not Instrument |
| `RegMarks`, `Sweep` | `pulse` / `trigger` | corner brackets pulse once per event; a calibration sweep crosses the tile per refresh, under the body like the ambient canvases (panels and text cover it; only the corner brackets sit above the body) (`TileFrame` reads per-tile sweeps, event pulses and reading order from `TileRefresh`, fed by the dashboard page) |

`Ruler` takes `cursor` (marker following the latest sample) and `inset`.

Helpers (`primitives.js`): `flipRows(rows, mutate, level?)` measures, runs `mutate`
(synchronous DOM update, e.g. `flushSync`) and glides moved rows on the spring;
`rollCells`, `rollDirection`, `niceTicks`, `progressOf`, `poissonGap`, `stripGeometry`, `PULSE_MS`,
`MAX_TICKS`, `STEP_STATES`.

`DataTable` uses `SkeletonTable` while loading, `flipRows` on a local sort,
`RowEnter` for rows that appear after the first load when `animateInserts` is set
(renderers get `{ entering }` as a third argument), `RowLeave` ghosts kept in place for
removed rows with `animateRemovals` (and `leaveHoldMs`), and a one-time tint on cells of
`highlightChanges` columns whose value changed. More than 10 rows in or out at once is a
page or filter change: nothing moves.

## Domain wiring

Each mark follows a real signal: a WebSocket topic of architecture section 18 when the
server publishes it, otherwise the answer of an API call or a quiet poll of the page
(`usePoll`, visible tab only). `pages/domainMotion.test.jsx` checks every row; the live
mock (`mock/events.mjs`) produces each event for `e2e/procedures.spec.js`.

| Signal | Mark | Where |
| --- | --- | --- |
| plan shown (validations) | `Checklist` ticks in order, `n/total` rolls | `PlanPreview` |
| apply request, node audit entry on `audit` (`request.entry = node`), `ApplyResult` | sections fold, `StepRail` local, peers, results with node chips and measured ms | `PlanPreview` (`lib/planTrace.js`) |
| rollback request, local rollback audit entry, result | the rail walks back in amber; `lib/planEvents.js` tells the zone page | `PlanPreview` |
| `rollback-start` / `rolled-back` plan events | `SerialTrace.scrubTo(plan instant)`, hold 350 ms, `release()` | zone page (`ZoneSerialTrace`) |
| plan applied and the editor closed | toast with its duration hairline and a "Roll back plan" action | records tab |
| records refetched | `RowEnter`, `RowLeave`, changed TTL or data cell lit | records tab |
| zone status read (poll 15 s, 2.5 s after a plan) | a node that was behind and rises: `TransferSerial` | status per node, secondaries (poll 30 s) |
| `jobs` progress | job `StepRail` with measured durations | `PlanPreview` (install, import, security remediation) |
| `leases` summary with new leases | `Dora` on the latest lease; new rows of the table unfold with a transient `Dora` | dashboard DHCP tile, leases page |
| `ha` state (or poll 5 s), new `collected_at` | `HeartbeatTrace` beats, `UnsentQueue` fills and drains, lost partner flattens it | HA page |
| `nodes` status, new `last_seen` | `HeartbeatTrace` per peer | nodes page |
| `system` replication (or poll 10 s) | `SignalLink` pulse, the peer's configuration version rolls on arrival | nodes page |
| `alerts` opened, acked, resolved | rows unfold in red or strike through and fold; pool alerts latch on an `IncidentTrace` of `/series/pools` | alerts page |

| live rates, HA heartbeats, cluster events | `ClusterTrace`, `StripChart`, `ThresholdTrace` of the busiest pool, `Dora` of the latest exchange, `HeartbeatTrace` per HA pair, `SignalLink`, `RollingNumber`, `Readout`, `Ruler`, `ScaleBar` | dashboard |

Left to other lots: hover row actions on tables.

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
