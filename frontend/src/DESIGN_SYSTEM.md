# Pelagos Design System

Copied from the UCM design system (relicensed Apache-2.0 by its author) with the
Pelagos families added: Mission Control (the default) and Pelagic.

> Source of truth: `src/index.css` (tokens, component classes) and
> `src/contexts/ThemeContext.jsx` (per-theme color values). This document
> describes what those files actually implement: keep it in sync when they change.

## Theming model

Colors are **not** hardcoded. `ThemeContext.jsx` writes CSS custom properties on
`document.documentElement` at runtime. There are **5 theme families** × **2 modes**:

| Family | `id` | Accent | Modes |
|--------|------|--------|-------|
| Mission Control: graphite glass, ember and neon (default) | `mission` | `#FF6A2B` | dark / light |
| Pelagic: Ocean Mission Control UI | `pelagic` | `#2DD4BF` | dark / light |
| Gray | `gray` | `#4F8EF7` | dark / light |
| Purple Night | `purple` | `#A855F7` | dark / light |
| Orange Sunset | `sunset` | `#F97316` | dark / light |

Mode resolves from `system` / `dark` / `light` (persisted in localStorage +
server prefs). Every component must read tokens (`var(--…)` or the Tailwind
aliases below) so it adapts to all 8 combinations. Never hardcode a hex.

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
- `font-sans`: Inter (UI text), self-hosted (`/fonts/Inter-*.woff2`)
- `font-mono`: Fira Code (code, serials, hashes), self-hosted. `.font-mono`
  also applies `font-size: 0.92em; letter-spacing: -0.01em` (Fira runs wide).

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

| Var | Value | Use |
|-----|-------|-----|
| `--duration-fast` | 150ms | Transforms, taps |
| `--duration-normal` | 250ms | Color/box-shadow |
| `--duration-slow` | 400ms | Large transitions |
| `--ease-smooth` | `cubic-bezier(0.4,0,0.2,1)` | Default |
| `--ease-out` / `--ease-bounce` / `--ease-spring` |: | Entrances, playful motion |

Keyframe animations (Tailwind): `animate-fade-in`, `animate-slide-up`,
`animate-slide-in-right`, `animate-pulse-slow`.

### Motion levels and primitives

`MotionContext` resolves the `animations` preference (Account > Preferences:
`full`, `reduced`, `off`) against `prefers-reduced-motion` (which can only
lower it) and writes `data-motion` on `<html>`; `data-page-hidden` is set while
the tab is hidden. `src/styles/effects.css` applies them:

| Level | Loops (`fx-loop`: sweeps, pulses, flowing dashes) | Entries (stagger, page) | `CountUp` |
|-------|------|------|------|
| `full` | run, paused on a hidden page | rise and fade | counts |
| `reduced` | static | short fade | final value |
| `off` | static | none (no transitions at all) | final value |

Rules: animate `transform` and `opacity` only (no animated blur, size or
`stroke-dashoffset`), use a `backwards` fill for entries so nothing stays
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

- Dashboard hero (`pages/dashboard/heroTiles.jsx`, `ClusterRadar.jsx`): the
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
- Sign-in: `LoginScene` lays a radar disc with halos and beams behind an
  opaque glass card (no backdrop blur over a looping animation).

## Mission Control effects layer

A family declares `effects: 'mission' | 'none'`; ThemeContext writes it as
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
