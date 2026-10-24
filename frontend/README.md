# Pelagos frontend

React 18, Vite, Tailwind, Radix primitives, i18next, recharts and
react-grid-layout, on the design system copied from UCM
(`src/DESIGN_SYSTEM.md`). Everything runs on lab-dev (see `AGENTS.md`).

```sh
npm install
npm run mock                       # mock API on 127.0.0.1:8481 (--port N)
VITE_API_MOCK=1 npm run dev        # Vite on 5173, /api proxied to the mock
npm run dev                        # Vite, /api proxied to pelagos serve on 8480
npm run lint                       # eslint, zero warnings
npx vitest run                     # unit and component tests, mock server tests
npx playwright test                # smoke test; starts the mock and Vite itself
npm run build                      # dist/
```

Ports come from `MOCK_PORT`, `VITE_PORT` and `VITE_API_TARGET`, so parallel
runs on lab-dev pick free ports instead of the defaults.

Mock users: `admin`/`admin`, `alice`/`alice` (dns-operator), `bob`/`bob` with
TOTP code `123456` (dhcp-operator), `viewer`/`viewer`.

## Layout

| Path | Content |
| --- | --- |
| `src/services/api.js` | one function per endpoint of architecture section 17 |
| `src/services/endpoints.js` | the endpoint list; `api.test.js` and the mock check against it |
| `src/services/apiClient.js` | fetch wrapper: session cookie, `X-CSRF-Token`, problem documents as `ApiError` |
| `src/services/ws.js`, `src/hooks/useWebSocket.jsx` | WebSocket of section 18; pages call `useWsTopic(topic, handler)` |
| `src/contexts/` | auth (session, permissions, capabilities), theme, notifications, floating windows |
| `src/components/` | shared components, exported from `src/components/index.js` |
| `src/pages/<area>/` | one folder per area: `routes.js` plus its pages |
| `src/pages/routes.js` | the list of areas and the sidebar groups |
| `src/i18n/locales/<lang>/<ns>.json` | `common`, `auth` and one namespace per area |
| `mock/` | mock API (`server.mjs`), sample data (`data.mjs`), plan lifecycle (`plans.mjs`), WebSocket (`ws.mjs`) |
| `e2e/` | Playwright tests against the mock |

## Working on an area

Each area is self-contained so several people can build pages at the same
time without touching the same files:

- Pages live in `src/pages/<area>/` and are registered in that folder's
  `routes.js` (`routes` for the router, `nav` for the sidebar). A route
  carries `component` (a `React.lazy` page), optional `props`,
  `permission` (section 16 string) and `module` (`dhcpv6`,
  `advanced_editor`).
- Strings go in `src/i18n/locales/en/<area>.json` and
  `src/i18n/locales/fr/<area>.json` with the same keys
  (`src/i18n/i18n.test.js` checks parity). In a page use
  `useTranslation('<area>')`; shared wording comes from `common`
  (`t('common:actions.save')`). Nav labels are `'<area>:nav.<id>'`.
- Area-specific components stay in the area folder. A component two areas
  need goes to `src/components/` in its own commit.
- New mock behavior goes in `mock/server.mjs` next to the endpoint it serves.

Every area page currently renders `AreaPlaceholder`, which shows the raw
answer of its main endpoint; replace it with the real screen.

## Shared building blocks

- `DataTable`: columns with renderers, server or client sort, search,
  filter selects with chips, pagination, loading/empty/error states.
- `PlanPreview` / `PlanPreviewModal`: the one plan UX of section 6. Build a
  plan with a `.../plan` endpoint, pass it in, and the component handles
  confirmation, apply, per-node results, rollback and job progress.
- `FormModal`, `ConfirmDialog` (with `typeToConfirm`), `FloatingDetailWindow`
  (register a renderer per entity type with `registerDetailRenderer`, open
  with `useOpenDetail()`), `StatusBadge`, `UtilizationBar`, `JsonTree`,
  `DiffView`, `PageLayout`, and the charts in `DashboardChart.jsx`.
- `useApi` and `usePaginatedApi` for data fetching, `usePermission` for
  permission checks.

Data read from BIND and Kea is untrusted: render it as text, never as HTML.

## Third-party assets

`public/fonts/` holds Inter and Fira Code, both under the SIL Open Font
License 1.1.
