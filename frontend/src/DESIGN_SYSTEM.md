# Pelagos Design System

Copied from the UCM design system (relicensed Apache-2.0 by its author) with the
Pelagos families added: Instrument (the default), Mission Control and Pelagic.

> Source of truth: `src/index.css` (tokens, component classes) and
> `src/contexts/ThemeContext.jsx` (per-theme color values). This document
> describes what those files actually implement: keep it in sync when they change.

## Theming model

Colors are **not** hardcoded. `ThemeContext.jsx` writes CSS custom properties on
`document.documentElement` at runtime. There are **6 theme families** × **2 modes**:

| Family | `id` | Accent | Modes |
|--------|------|--------|-------|
| Instrument: calm surfaces, signal colors, measured motion (default) | `instrument` | `#5FC7E6` | dark / light |
| Mission Control: graphite glass, ember and neon | `mission` | `#FF6A2B` | dark / light |
| Pelagic: Ocean Mission Control UI | `pelagic` | `#2DD4BF` | dark / light |
| Gray | `gray` | `#4F8EF7` | dark / light |
| Purple Night | `purple` | `#A855F7` | dark / light |
| Orange Sunset | `sunset` | `#F97316` | dark / light |

Mode resolves from `system` / `dark` / `light` (persisted in localStorage +
server prefs). Every component must read tokens (`var(--…)` or the Tailwind
aliases below) so it adapts to all 12 combinations. Never hardcode a hex.
Every family also defines `bg-inset` (bar tracks), `border-strong` (control
hairline), `contrast-bg` and `contrast-fg` (neutral primary action).

## Typography

### Font Sizes
| Token | Size | Usage |
|-------|------|-------|
| `text-3xs` | 9px | Micro labels, badges |
| `text-2xs` | 10px | Compact table cells, small badges |
| `text-xs` | 12px | Secondary text, labels |
| `text-sm` | 14px | Body text, buttons |
| `text-base` | 16px | Primary content |
| `text-lg` | 18px | Section headers |
| `text-xl` | 20px | Page subtitles |
| `text-2xl` | 24px | Page titles |

### Font Families
- `font-sans` (`--font-sans`): IBM Plex Sans under Instrument, Inter in the
  other families; self-hosted (`/fonts/IBMPlexSans-*.woff2`, `/fonts/Inter-*.woff2`).
- `font-mono` (`--font-mono`): IBM Plex Mono under Instrument (every datum: node
  names, zones, addresses, serials, counters, diffs), Fira Code elsewhere.
  `.font-mono` also applies `font-size: 0.92em`.
- `font-display` (`--font-display`): Michroma under Mission Control, the sans
  face under Instrument.

## Colors

All values below are the UCM **gray / dark** values (Pelagic values are in
`ThemeContext.jsx`); they shift per theme family
and mode. Tailwind aliases (`tailwind.config.js`) map to the CSS vars.

### Background
| Tailwind alias | CSS var | Usage |
|----------------|---------|-------|
| `bg-bg-primary` | `--bg-primary` | Main page background |
| `bg-bg-secondary` | `--bg-secondary` | Cards, panels |
| `bg-bg-tertiary` | `--bg-tertiary` | Inputs, nested elements |

### Text
| Tailwind alias | CSS var | Usage |
|----------------|---------|-------|
| `text-text-primary` | `--text-primary` | Headings, important text |
| `text-text-secondary` | `--text-secondary` | Body text |
| `text-text-tertiary` | `--text-tertiary` | Muted, placeholder |

### Accent & status
| Tailwind alias | CSS var | Usage |
|----------------|---------|-------|
| `accent-primary` | `--accent-primary` | Primary actions, links |
| `accent-pro` | `--accent-pro` | "Pro"/highlight accent (purple/pink, theme-dependent) |
| `status-success` / `accent-success` | `--accent-success` | Valid, active |
| `status-warning` / `accent-warning` | `--accent-warning` | Expiring, pending |
| `status-danger` / `status-error` / `accent-danger` | `--accent-danger` | Expired, revoked, error |
| `status-info` | `--accent-primary` | Info, neutral |
| `border` | `--border` | Default borders |

> **There is no `accent-secondary` token.** It is not defined in the Tailwind
> theme, `ThemeContext`, or `index.css`. Use `accent-pro` for a secondary
> highlight. (A few legacy usages of `text-accent-secondary` exist in the
> codebase and render nothing: they should be migrated.)

### Opacity with CSS-var colors: use the helper classes
Tailwind's `/opacity` syntax does **not** work on these var-backed colors. Use
the predefined classes instead of `bg-bg-tertiary/40`:
- `bg-tertiary-op30 / -op50 / -op60 / -op80`, `bg-secondary-op50`,
  `border-op30 / -op40 / -op50` (see `index.css`).
- Status tints: `status-success-bg` / `status-success-text` (+ `-bg-solid`),
  and the same for `status-warning`, `status-danger`, `status-primary`.

### Icon background classes (theme-aware, set by ThemeContext)
`icon-bg-blue`, `icon-bg-orange`, `icon-bg-violet`, `icon-bg-green`,
`icon-bg-teal`: colored tile backgrounds that avoid "ton sur ton" clashes per
theme. Backing vars: `--icon-{blue,orange,violet,amber,emerald,teal}-{bg,text}`.

## Spacing

| Token | Size | Usage |
|-------|------|-------|
| `gap-1` / `p-1` | 4px | Tight inline |
| `gap-2` / `p-2` | 8px | Default gap (most common) |
| `gap-3` / `p-3` | 12px | Card inner padding |
| `gap-4` / `p-4` | 16px | Section spacing |
| `px-3 py-2` |: | Button/input padding |

Vertical rhythm: `space-y-4` between sections, `space-y-2` for compact lists.

## Border Radius

| Token | Size | Usage |
|-------|------|-------|
| `rounded-sm` | 2px | Subtle |
| `rounded` / `rounded-md` | 4px | Default |
| `rounded-lg` | 6px | Cards, panels |
| `rounded-xl` | 8px | Large cards |
| `rounded-full` | 50% | Circles, pills |

Card classes (`card-soft`, `card-interactive`, `elevated`) use a literal
`12px` radius. Buttons use `8px`.

## Shadows & elevation

`index.css` defines a layered shadow scale (not plain Tailwind shadows):

| Var | `elevation-*` class | Usage |
|-----|---------------------|-------|
| `--shadow-xs` | `elevation-1` (`--shadow-sm`) | Resting cards/buttons |
| `--shadow-sm` |: | Hover lift |
| `--shadow-md` | `elevation-2` | Elevated cards |
| `--shadow-lg` | `elevation-3` | Dropdowns, popovers |
| `--shadow-xl` | `elevation-4` | Modals, overlays |

Extras: `--shadow-glow-{primary,success,danger,warning}` (focus/hover glow),
`--shadow-inner-highlight`, `--shadow-inner-sm`, `--floating-window-shadow`.

## Gradients

| Var | Usage |
|-----|-------|
| `--gradient-primary` | Primary gradient buttons (`btn-gradient`) |
| `--gradient-success` / `--gradient-danger` | Success/danger gradient buttons |
| `--gradient-surface` | Panel surfaces |
| `--gradient-shine` | Highlight sheen |
| `--gradient-accent` (per theme) | Brand gradient (from `--gradient-from`/`--gradient-to`) |
| `--logo-gradient-{start,mid,end,accent}` | Orange logo gradient (`#fb923c → #f97316 → #ea580c`) |

## Glassmorphism

`--glass-blur` (12px), `--glass-bg`, `--glass-border`, `--glass-shadow`: used
for floating panels / overlays.

## Motion (timing & easing)

Motion system v2 (`src/styles/motion.css`, `src/lib/motion.js`, primitives and
rules in `src/components/motion/README.md`):

| Var | Value | Use |
|-----|-------|-----|
| `--d-instant` / `--d-fast` / `--d-quick` | 70 / 110 / 150 ms | press, hover color, tooltip, cursor |
| `--d-base` / `--d-panel` / `--d-page` | 200 / 240 / 260 ms | dialog, menu, row, toast, page |
| `--d-slow` / `--d-moment` | 400 / 600 ms | gauges, rails; pulses, rare events |
| `--ease-out`, `--ease-out-soft`, `--ease-in-out`, `--ease-drawer`, `--ease-exit` | beziers | UI entries, moves, exits |
| `--spring` | `linear()`, zeta 0.8, 1.5 % overshoot, 300 ms | things that move and stop |
| `--settle` | `linear()`, critically damped | things that land |
| `linear` | | time and transport |

`--duration-fast/normal/slow` remain as aliases for the UCM-era rules.

### Motion levels and primitives

`MotionContext` resolves the `animations` preference (Account > Preferences:
`full`, `reduced`, `off`) against `prefers-reduced-motion` (which can only
lower it) and writes `data-motion` on `<html>`; the `ambient` preference (`on`,
`off`) is written as `data-ambient`; `data-page-hidden` is set while the tab is
hidden. `src/styles/effects.css` and `motion.css` apply them:

| Level | Loops (`fx-loop`: sweeps, pulses, flowing dashes) | Entries (stagger, page) | `CountUp` |
|-------|------|------|------|
| `full` | run, paused on a hidden page | rise and fade | counts |
| `reduced` | static | short fade | final value |
| `off` | static | none (no transitions at all) | final value |

Rules: animate `transform`, `opacity`, `stroke-dashoffset` and canvas only (no
animated blur, size, layout or filter), use a `backwards` fill for entries so nothing stays
transformed, never put a looping animation behind a glass panel (it would
re-blur every frame; loops pause while a dialog backdrop is open), and reserve the final size of changing numbers
(`CountUp` renders a hidden ghost of the final value).

Primitives (`components/motion/`, also exported from `components/index.js`):
`CountUp`, `StatusDot`, `PulsingHalo`, `FlowLine` (straight beam, dashes move
by transform), `Reticle` (corner brackets), `RadarRing` (perspective disc,
rotating tick ring and sweep), `MiniHistogram`, `StippledAreaChart` (dot
stipple under a thin line, glowing marker on the current point),
`SegmentedProgress` (done green, current ember, next gray), `Stagger`,
`PageTransition`, `StatChip`, `IconButton`, `AppBackdrop`. Tones: `primary`,
`pro`, `success`, `warning`, `danger`, `neutral`.

The shared components use them, so pages get motion without page code:
`PageLayout` staggers its children (`display: contents` wrapper), `DetailGrid`
staggers its fields, `DetailHeader` stats are `StatChip`s and `RichStatsBar`,
`CompactStats` and the header stats count up numbers (`AnimatedValue`),
`Badge`, `StatusIndicator` and the WebSocket dot draw `StatusDot`s, and the
icon-only header actions, the mobile menu toggle and the modal close button
are `IconButton`s. Dashboard tiles enter in reading order (`fx-stagger-item`).

### Screens in the Mission language

- Dashboard hero under Mission (`pages/dashboard/radarTile.jsx`, loaded on
  demand under its effects only, and `ClusterRadar.jsx`): the
  cluster radar is one react-grid-layout tile between a DNS tile and a DHCP
  tile. Its floor is a square scaled on Y (`radarLayout.js` holds the math:
  node angles, projection, link and HA states, pool segments): nodes are pins
  with halos colored by health, replication links flow (green ok, yellow and
  slow when a serial lags, red and still when the peer is offline), zones are
  blips, alerts are markers, the query rate drives the center beam and the HA
  servers form a rail of waypoint pills.
- Live rates (`lib/liveRates.js`, `hooks/useLiveRates.js`, `LiveRatePanel`):
  counters polled every 4 s while the page is visible become per-second series
  kept for the session; `StippledAreaChart` takes a `capacity` so a young
  series fills its window from the right, and `formatValue`/`formatLabel` for
  a glass tooltip (`fx-chart-tooltip`, also used by the recharts wrappers).
- `SegmentedProgress` states: `done`, `current`, `next`, plus `warning` and
  `danger` for thresholds; `value` reports a percentage. In Mission the
  `UtilizationBar` track and `ui-meter` bars are cut into segments by a mask.
- Waypoint pills (`ui-waypoint`, `fx-tone-*`) for states on a route (HA).
- Page headings: card titles carry `ui-card-title` (literal case for node
  names), tiny section labels `ui-label`; `RichStatsBar` reads label over
  value as round chips.
- Sign-in: `LoginScene` (loaded under Mission only) lays a radar disc with halos and beams behind an
  opaque glass card (no backdrop blur over a looping animation).

## Instrument palette and budget

Tokens (`ThemeContext.jsx`, `instrument`; the layer's own tokens `--i-*`,
`--r-*` are in `styles/instrument.css`):

| Token | Dark | Light |
|-------|------|-------|
| `bg-primary` / `bg-secondary` / `bg-tertiary` | `#121416` / `#191C1F` / `#1F2327` | `#ECEEF1` / `#FFFFFF` / `#F5F6F8` |
| `text-primary` / `-secondary` / `-tertiary` | `#E6E9EC` / `#A4ABB3` / `#858D96` | `#15191D` / `#4A535C` / `#616A73` |
| `accent-primary` (DNS) / `accent-pro` (DHCP) | `#5FC7E6` / `#C08CF5` | `#0A7391` / `#6B3FD1` |
| `accent-success` / `-warning` / `-danger` | `#5CCC8A` / `#E3B341` / `#F06A6A` | `#1A7A42` / `#8A5A00` / `#C22F45` |

Text is IBM Plex Sans, data is IBM Plex Mono (self-hosted, OFL, listed in
`NOTICE`). All text, small labels included, uses `text-primary`,
`-secondary` or `-tertiary` and keeps 4.5:1; `--i-faint` is for hairlines and
ticks only. `e2e/instrument-motion.spec.js` checks the trace, scale bar,
readout, DORA ticks, plan rail and alert latches in both schemes.

Motion tokens and springs are in `styles/motion.css` (table above) and
`lib/motion.js` (`spring()`); levels `full`, `reduced`, `off` come from
`MotionContext` (`data-motion`), and `prefers-reduced-motion` only lowers
them. The `ambient` preference (`data-ambient`, `on` or `off`) is separate:
ambient layers (`components/motion/Ambient.jsx`, `ambientDraw.js`) are drawn
still below `full` and removed when `off`.

Performance budget: one `requestAnimationFrame` loop for every canvas and
per-frame animator (`hooks/useAnimationLoop.js`), stopped while the tab is
hidden or nothing is registered. In dev, `window.__pelagosLoop()` returns
`{ active, frames, fps, p95 }` (p95 of script time per frame); the budget is
2 ms, asserted in `e2e/instrument-trace.spec.js` and
`e2e/instrument-motion.spec.js`. Pages do not scroll sideways at 400px.

## Instrument effects layer

`effects: 'instrument'` turns on `src/styles/instrument.css` (everything scoped
to `html[data-effects='instrument']`), through the same hook classes as below.

- Materials, not glass: three luminance steps (`bg-primary` < `bg-secondary` <
  `bg-tertiary`), `bg-inset` for tracks and alpha hairlines; a shadow only on what
  floats (menus, dialogs, toasts, windows); no `backdrop-filter`.
- Radii by material: 6px panels and tiles, 4px controls and chips, 10px dialogs,
  menus and toasts, 2px bars.
- Chrome: an inverted L darker than the content; the sidebar sits on the ground
  with a hairline, the active entry carries a 2px cursor that glides on the
  spring (`NavCursor`); groups fold through grid rows. The page header has no
  icon tile, a 17px title (mono for data titles) and tabs with a sliding ink
  (`TabInk`).
- Color: one signal per protocol (DNS cyan `accent-primary`, DHCP violet
  `accent-pro`), status colors only on dots, bars and readings; a state is a dot
  and a word (status badges get a dot, their word stays neutral); `info` is
  neutral. The primary button is neutral high contrast (`contrast-bg`).
- Type: IBM Plex Sans 400/500/600 for the UI, IBM Plex Mono 400/500 for data;
  no spaced capitals for labels.
- Ambient: `AmbientScreen` (graticule drifting at the trace paper speed, faint
  contours) under the app and the sign-in page; still below `full` motion,
  hidden when `ambient` is `off`.
- Loading: `SkeletonTable` with a calibration sweep in `DataTable`; the chrome
  lights up once per session (`html.boot`, `useBootSequence`).
- Dashboard hero (`pages/dashboard/traceTile.jsx`, `traceModel.js`): the cluster
  trace replaces the radar for every family but Mission. This node and its peer
  are cards (version, rolling config and audit, engines, an ECG per HA family that
  draws itself on each measured heartbeat) joined by a `SignalLink` whose lease
  ticks follow the real lease rate, with pulses for replication and HA changes and
  a transfer bar for a zone that catches up. Below, `ClusterTrace` (canvas): DNS
  queries (line), DHCP leases (bars), HA heartbeats (QRS at each beat measured from
  the Kea partner age, red dashes and crosses while the partner is lost), events
  (plan, rollback, alert, resolution, zone sync, replication, HA); readouts on the
  right (rates, mean interval and jitter, last event), legend, sample count, scale
  bar and a 30 s / 90 s / 5 min window. The DNS and DHCP tiles carry `StripChart`s
  (CH1, CH2), rcodes, the latest exchange as `Dora` ticks with the per step rates
  and the latest lease with its own ticks,
  the busiest pools against their thresholds and the HA pills; Pool usage adds the
  pressure of the hottest pool (`ThresholdTrace`, one hour, alert latches).
- Sign-in: `TraceScene`, the empty trace writing a flat line from the moment
  the page opened, under the opaque card.

## Procedures and domain events

`src/styles/procedures.css` and the domain primitives of `components/motion` (table in
its README, "Domain wiring") draw what the cluster does, never decoration:

- Plans: validations tick in order along a hairline; at apply the sections fold through
  grid rows and a step rail follows the real sequence (local apply, peers through
  replication, results per node) with measured durations; a rollback walks it back in
  amber and rewinds the zone serial trace to the plan's instant. The TTL drains under
  "Expires in". An applied record plan leaves a toast with a duration hairline and a
  "Roll back plan" action.
- Tables: rows that arrive unfold, rows that go fold in place (alerts strike through
  first), a changed cell tints once; never for a page or filter change.
- DNS: a node catching up shows a transfer bar (head, tail 300 ms behind) and its serial
  rolls on arrival. DHCP: a new lease lands four DORA ticks (a declined one stops on
  red). HA: one QRS per heartbeat received, a red flat line when the partner is lost, the
  unsent queue fills and drains. Nodes: a replication pulse crosses the link. Alerts: a
  pool alert latches where its use crossed the threshold.
- Levels: `reduced` keeps fades of 150 ms and color changes, no travel (no transfer bar,
  no pulse, no rail or checklist transition); `off` changes everything at once.

## Mission Control effects layer

A family declares `effects: 'instrument' | 'mission' | 'none'`; ThemeContext writes it as
`data-effects` on `<html>`. `src/styles/mission.css` styles the shared
components through stable hook classes (`ui-sidebar`, `ui-page-header`,
`ui-page-title`, `ui-tabs`/`ui-tab`, `ui-card-title`, `ui-table`/`ui-row`,
`ui-modal`, `ui-toast`, `ui-menu`, `ui-input`, `ui-badge-*`, `ui-btn-*`,
`ui-progress-*`, `ui-subpanel`, `ui-floating`) plus the existing `card-soft`
classes:

- Ground: generated backdrop (gradient, depth grid, contour lines, vignette),
  static, CSS and SVG only.
- Glass: `rgba` graphite (or frosted white in light mode) with
  `backdrop-filter: blur(16px)`, hairline borders, 18px outer and 10px inner
  radius; a panel nested in a panel becomes a lighter row with no second blur;
  solid `bg-secondary` when `backdrop-filter` is unsupported or
  `prefers-contrast: more`.
- Type: Michroma (`font-display`, `--font-display`) uppercase for the brand,
  page, card and modal titles and nav group labels (10px minimum; small
  section labels such as `ui-label`, `rich-stat-label` and `dash-label` go
  down to 9.5px, the radar readout label to 9px); Inter with
  tabular numerals everywhere else. A title that carries an identifier (a dot,
  colon, slash, `@` or `_`, or `literalTitle` on `PageLayout`) gets
  `ui-title-literal` and keeps its case (`lib/displayCase.js`).
- Controls: pill nav items and tabs (active = lighter fill), round icon
  buttons, ember primary buttons with dark text (white in light mode), ember
  focus glow on inputs, pill badges with glowing dots.

## Component Patterns

### Buttons (`components/Button.jsx`)
```jsx
<Button variant="primary" size="sm">Action</Button>
```
- **Variants**: `primary` (gradient: `btn-gradient`), `secondary` (`btn-soft`),
  `success`, `danger` (gradient), `danger-soft`, `warning-soft`, `ghost`,
  `outline`. Non-gradient variants get a `focus-ring`.
- **Sizes**: `xs`, `sm` (default), `default`, `lg`.
- `loading` prop shows a spinner + `loadingText`.

`primary` is a **gradient with a shine sweep on hover** (`--gradient-primary`),
not a flat `bg-accent-primary`. Match this when rebuilding buttons elsewhere.

### Badges (`components/Badge.jsx`)
```jsx
<Badge variant="success" dot pulse icon={Icon}>Active</Badge>
```
- **Semantic variants**: `default`, `primary`, `secondary`, `success`,
  `warning`, `danger`, `info`, `outline`.
- **Color aliases** (theme-aware): `emerald`, `red`, `blue`, `yellow`,
  `purple`/`violet`, `amber`, `orange`, `cyan`/`teal`, `gray`.
- **Props**: `dot` (status dot), `pulse` (animate dot), `icon`, `size`
  (`sm` pill / `default` / `lg`). Base class `badge-enhanced`.
- Helpers: `<ExperimentalBadge />`, `<CATypeIcon isRoot />`.

### Cards (`components/Card.jsx`)
```jsx
<Card variant="elevated" accent="primary">
  <Card.Header icon={Icon} iconColor="primary" title="Title" subtitle="…" action={…} />
  <Card.Body>Content</Card.Body>
  <Card.Footer>…</Card.Footer>
</Card>
```
- **Variants**: `default`/`soft` (`card-soft`), `elevated` (`elevation-2`),
  `bordered`. `interactive` makes it a clickable card with a lift effect
  (`card-interactive`: `translateY(-2px)` + accent-tinted border on hover).
- **`accent`** left-border: `primary`, `success`, `warning`, `danger`, `info`.
- `Card.Header` renders an `IconBadge` + `section-header-gradient`.

### Status indicators
```jsx
<span className="w-2 h-2 rounded-full status-success-bg-solid" />
<span className="px-2 py-px rounded-full text-2xs status-success-bg status-success-text">Active</span>
```

## Responsive Breakpoints

| Breakpoint | Min Width |
|------------|-----------|
| (default) | 0px (mobile) |
| `sm:` | 640px |
| `md:` | 768px |
| `lg:` | 1024px |
| `xl:` | 1280px |

## Do's and Don'ts

### Do
```jsx
<p className="text-sm text-text-secondary">          // design tokens
<span className="status-danger-text">                // semantic status
<div className="p-4 space-y-4">                      // consistent spacing
<div className="bg-tertiary-op40">                   // var-color opacity helper
```

### Don't
```jsx
<p className="text-gray-500">                         // BAD: hardcoded palette
<div style={{ color: '#ff0000' }}>                    // BAD: inline hex
<p className="text-[13px]">                            // BAD: arbitrary size
<div className="bg-bg-tertiary/40">                    // BAD: /opacity on var color
<span className="text-accent-secondary">              // BAD: token doesn't exist
```

## Pelagos color rules

- `accent-primary` is DNS and primary actions, `accent-pro` is DHCP.
- `accent-success`, `accent-warning`, `accent-danger` carry health meaning in
  every family. The UCM families and Pelagic share the UCM hues; Mission
  Control uses neon green, yellow (kept apart from the ember accent) and
  red-pink, checked for AA contrast in `ThemeContext.test.jsx`.
- `accent-warning-fill` is the non-text warning color (bars, dots, chart tone).
  It equals `accent-warning` except in Mission light, where the AA text token
  is a dark olive and the fill stays a bright yellow (`#E0B000`).
- Adding a family: one entry in `themeFamilies` with every key of an existing
  family (`id`, `name`, `description`, `accent`, `effects`, `dark`, `light`).
