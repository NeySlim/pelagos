// SPDX-License-Identifier: Apache-2.0
// Every REST endpoint of docs/architecture.md section 17, as "METHOD /path" with
// `{param}` placeholders. api.js must call each one at least once (see api.test.js).
export const ENDPOINTS = [
  // Meta
  'GET /health',
  'GET /version',
  'GET /capabilities',
  // Auth and account
  'POST /auth/login',
  'POST /auth/logout',
  'GET /auth/session',
  'POST /auth/password',
  'POST /auth/totp/enroll',
  'POST /auth/totp/confirm',
  'DELETE /auth/totp',
  'GET /account/preferences',
  'PUT /account/preferences',
  // Nodes
  'GET /nodes',
  'GET /nodes/self',
  'GET /nodes/{id}',
  'POST /nodes/enroll-token',
  'DELETE /nodes/{id}',
  'POST /nodes/{id}/sync',
  'GET /nodes/replication',
  // Dashboard
  'GET /dashboard/summary',
  'GET /dashboard/layout',
  'PUT /dashboard/layout',
  // DNS
  'GET /dns/instances',
  'GET /dns/zones',
  'GET /dns/zones/{zone}',
  'POST /dns/zones/plan',
  'GET /dns/zones/{zone}/records',
  'POST /dns/zones/{zone}/records/plan',
  'POST /dns/zones/{zone}/retransfer',
  'POST /dns/zones/{zone}/notify',
  'POST /dns/zones/{zone}/reload',
  'GET /dns/zones/{zone}/dnssec',
  'GET /dns/config',
  'POST /dns/config/plan',
  'GET /dns/keys',
  'GET /dns/keys/{name}/secret',
  'POST /dns/keys/plan',
  'GET /dns/acls',
  'POST /dns/acls/plan',
  'GET /dns/resolver',
  'POST /dns/resolver/plan',
  'GET /dns/rpz',
  'GET /dns/catalog-zones',
  'POST /dns/catalog-zones/{zone}/members/plan',
  'GET /dns/dnssec/policies',
  'POST /dns/dnssec/policies/plan',
  'POST /dns/zones/{zone}/dnssec/plan',
  'GET /dns/stats',
  // DHCP
  'GET /dhcp/{family}/servers',
  'GET /dhcp/{family}/subnets',
  'GET /dhcp/{family}/subnets/{id}',
  'POST /dhcp/{family}/subnets/plan',
  'GET /dhcp/{family}/shared-networks',
  'POST /dhcp/{family}/shared-networks/plan',
  'GET /dhcp/{family}/client-classes',
  'POST /dhcp/{family}/client-classes/plan',
  'GET /dhcp/{family}/options',
  'POST /dhcp/{family}/options/plan',
  'GET /dhcp/{family}/reservations',
  'POST /dhcp/{family}/reservations/plan',
  'GET /dhcp/{family}/leases',
  'GET /dhcp/{family}/leases/recent',
  'GET /dhcp/{family}/leases/{ip}',
  'POST /dhcp/{family}/leases/{ip}/delete/plan',
  'GET /dhcp/{family}/utilization',
  'GET /dhcp/{family}/stats',
  'GET /dhcp/{family}/ha',
  'POST /dhcp/{family}/ha/maintenance/plan',
  'GET /dhcp/{family}/ha/transitions',
  'POST /dhcp/{family}/service/plan',
  'GET /dhcp/{family}/ddns',
  'POST /dhcp/{family}/ddns/plan',
  'GET /dhcp/{family}/hooks',
  'POST /dhcp/{family}/hooks/plan',
  'GET /dhcp/{family}/config',
  'POST /dhcp/{family}/config/plan',
  'GET /dhcp/{family}/config/file',
  'POST /dhcp/{family}/config/adopt/plan',
  'GET /dhcp/d2/servers',
  'GET /dhcp/d2/stats',
  'GET /dhcp/d2/config',
  'POST /dhcp/d2/config/plan',
  'GET /dhcp/d2/config/file',
  'POST /dhcp/d2/config/adopt/plan',
  // Hosts
  'GET /hosts',
  'GET /hosts/{key}',
  'POST /hosts/plan',
  // Plans and jobs
  'GET /plans/{id}',
  'POST /plans/{id}/apply',
  'POST /plans/{id}/rollback',
  'DELETE /plans/{id}',
  'GET /jobs/{id}',
  // Alerts and series
  'GET /alerts',
  'GET /alerts/summary',
  'POST /alerts/{id}/ack',
  'POST /alerts/consistency/run',
  'GET /series/pools',
  'GET /series/serials',
  'GET /series/ha-transitions',
  // Audit
  'GET /audit',
  'GET /audit/{id}',
  'GET /audit/export',
  // Advanced
  'GET /advanced/bind/grammar',
  'GET /advanced/bind/tree',
  'GET /advanced/kea/{family}/schema',
  'GET /advanced/history',
  'GET /advanced/history/{id}',
  // Runtime operations (allow-listed rndc and Kea commands)
  'GET /dns/ops',
  'POST /dns/ops',
  'GET /dhcp/{family}/ops',
  'POST /dhcp/{family}/ops',
  'GET /dhcp/d2/ops',
  'POST /dhcp/d2/ops',
  // Install, import, security
  'GET /install/detect',
  'POST /install/plan',
  'POST /install/import/plan',
  'GET /install/security',
  'POST /install/security/plan',
  // Administration
  'GET /admin/users',
  'POST /admin/users',
  'GET /admin/users/{id}',
  'PUT /admin/users/{id}',
  'DELETE /admin/users/{id}',
  'POST /admin/users/{id}/reset-password',
  'DELETE /admin/users/{id}/totp',
  'GET /admin/roles',
  'POST /admin/roles',
  'PUT /admin/roles/{name}',
  'DELETE /admin/roles/{name}',
  'GET /admin/permissions',
  'GET /admin/settings',
  'PUT /admin/settings',
  'GET /admin/modules',
  'PUT /admin/modules',
]

// Regex for one spec entry: `{x}` matches one path segment, `{family}` only v4 or v6.
export function endpointMatcher(spec) {
  const [method, path] = spec.split(' ')
  const pattern = path
    .split('/')
    .map((seg) => {
      if (seg === '{family}') return '(v4|v6)'
      if (/^\{.+\}$/.test(seg)) return '[^/]+'
      return seg.replace(/[.*+?^$()|[\]\\]/g, '\\$&')
    })
    .join('/')
  return { method, regex: new RegExp(`^${pattern}$`) }
}

// Literal paths win over placeholders, so /audit/export is not read as /audit/{id}.
export function matchEndpoint(method, path) {
  const clean = path.split('?')[0]
  const candidates = ENDPOINTS.filter((spec) => {
    const m = endpointMatcher(spec)
    return m.method === method.toUpperCase() && m.regex.test(clean)
  })
  candidates.sort((a, b) => (a.match(/\{/g) || []).length - (b.match(/\{/g) || []).length)
  return candidates[0]
}
