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
npx playwright test                # e2e against the mock; starts the mock and Vite itself
npm run build                      # dist/
```

Ports come from `MOCK_PORT`, `VITE_PORT` and `VITE_API_TARGET`, so parallel
runs on lab-dev pick free ports instead of the defaults.

Mock users: `admin`/`admin`, `alice`/`alice` (dns-operator), `bob`/`bob` with
TOTP code `123456` (dhcp-operator), `viewer`/`viewer`.

The mock answers with the shapes the real API returns (checked against a
backend driving real `named` and Kea); when the two disagree, the backend
wins and the mock follows. Shapes the specification leaves open are logged
in `docs/contracts-changes.md`.

## Against the real backend

`npm run dev` proxies `/api` to `VITE_API_TARGET` (default
`http://127.0.0.1:8480`, what `make run` starts). `pelagos serve` is the
Flask development server: REST works, but it has no WebSocket worker, so
the live-updates dot stays off. For the WebSocket, run the web process
under gunicorn with the gevent-websocket worker and point Vite at it:

```sh
cd backend
PELAGOS_HOME=.pelagos-dev .venv/bin/gunicorn -c pelagos/gunicorn_conf.py \
  -b 127.0.0.1:8443 --certfile .pelagos-dev/var/pki/node.crt \
  --keyfile .pelagos-dev/var/pki/node.key 'pelagos.app:wsgi_app()'
cd ../frontend
VITE_API_TARGET=https://127.0.0.1:8443 npm run dev
```

The backend accepts a WebSocket only when its `Origin` matches the `Host`
it receives, so the dev proxy presents the target's origin on upgrades
(`vite.config.js`). The proxy does not verify the node's self-signed
certificate.

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
| `e2e/` | Playwright tests against the mock: every page with its data and no console error, plan apply and rollback, area flows |

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
- A new page adds its path, page test id and data test id to `PAGES` in
  `e2e/smoke.spec.js`.

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
License 1.1. Their license texts ship next to them in
`public/fonts/OFL-Inter.txt` and `public/fonts/OFL-FiraCode.txt`.
