// SPDX-License-Identifier: Apache-2.0
// The one list of areas. Each area lives in src/pages/<area>/ and exports a module
// { id, routes: [{ path, component, props?, permission?, anyPermission?, module? }], nav: [{ id,
// group, path, labelKey: '<ns>:key', icon, permission?, anyPermission?, module?, order? }] }. Components are
// React.lazy, so each area is its own chunk. Adding an area means adding its folder,
// its locale files (src/i18n/locales/<lang>/<area>.json) and one line here.
import dashboard from './dashboard/routes'
import dns from './dns/routes'
import dhcp from './dhcp/routes'
import hosts from './hosts/routes'
import alerts from './alerts/routes'
import nodes from './nodes/routes'
import audit from './audit/routes'
import advanced from './advanced/routes'
import install from './install/routes'
import admin from './admin/routes'
import account from './account/routes'

export const areas = [dashboard, dns, dhcp, hosts, alerts, nodes, audit, advanced, install, admin, account]

// Sidebar groups in display order; nav items name their group by id.
export const navGroups = [
  { id: 'dns', labelKey: 'nav.groups.dns' },
  { id: 'dhcp', labelKey: 'nav.groups.dhcp' },
  { id: 'dhcpv6', labelKey: 'nav.groups.dhcpv6' },
  { id: 'hosts', labelKey: 'nav.groups.hosts' },
  { id: 'advanced', labelKey: 'nav.groups.advanced' },
  { id: 'admin', labelKey: 'nav.groups.admin' },
]

export const allRoutes = areas.flatMap((area) => area.routes.map((route) => ({ ...route, area: area.id })))

export const allNavItems = areas
  .flatMap((area) => (area.nav || []).map((item) => ({ ...item, area: area.id })))
  .sort((a, b) => (a.order ?? 100) - (b.order ?? 100))

// Longest matching nav path for a location, so /dns/zones/example.lan highlights "Zones".
export function resolveActiveNavId(pathname) {
  if (pathname === '/') return 'dashboard'
  const exact = allNavItems.find((item) => item.path === pathname)
  if (exact) return exact.id
  const prefix = allNavItems
    .filter((item) => item.path !== '/' && pathname.startsWith(`${item.path}/`))
    .sort((a, b) => b.path.length - a.path.length)[0]
  if (prefix) return prefix.id
  const route = allRoutes.find((r) => r.path === pathname)
  return route?.area || pathname.split('/')[1] || 'dashboard'
}

// Browser tab title: "<page> · Pelagos", or "Pelagos" when no nav entry matches.
export function pageTitle(pathname, t) {
  const item = allNavItems.find((i) => i.id === resolveActiveNavId(pathname))
  return item ? `${t(item.labelKey)} · Pelagos` : 'Pelagos'
}
