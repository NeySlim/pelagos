// SPDX-License-Identifier: Apache-2.0
// Kea 3.x migration analysis of the mock (architecture section 26): series and package source of
// every node, the available targets, and a read-only report (findings, diffs, packages, dry run).
import { iso, ulid } from './data.mjs'
import { auditEntry } from './plans.mjs'

// Debian 13 packages (dl.cloudsmith.io kea-3-2 and kea-3-0, qa.debian.org madison, read on 2026-10-28).
export const KEA_TARGETS = [
  { series: '3.2', source: 'isc', version: '3.2.1-isc20260928103142', available: true, recommended: true },
  { series: '3.0', source: 'isc', version: '3.0.5-isc20261026134027', available: true, recommended: false },
  { series: '3.0', source: 'backports', version: '3.0.3-1~bpo13+1', available: true, recommended: false, note: 'backports: no security support commitment' },
]
const SEVERITIES = ['blocking', 'converted', 'behavior', 'info']
const ISC_PACKAGES = ['isc-kea-common', 'isc-kea-dhcp4', 'isc-kea-dhcp6', 'isc-kea-dhcp-ddns', 'isc-kea-hooks', 'isc-kea-admin']
const DEBIAN_PACKAGES = ['kea-common', 'kea-dhcp4-server', 'kea-dhcp6-server', 'kea-dhcp-ddns-server', 'kea-ctrl-agent', 'kea-admin']
const KB_30 = 'https://kb.isc.org/docs/things-to-be-aware-of-when-upgrading-to-kea-300'

export function keaMigrationHandlers(state, { Problem, invalid }) {
  state.keaMigration ||= { analysis: null }
  const k = state.keaMigration
  const nameOf = (id) => state.nodes.find((n) => n.peer.id === id)?.peer.name || id
  const nodes = () => state.nodes.map((n) => ({
    node_id: n.peer.id, name: n.peer.name, reachable: true, error: null, arch: 'amd64',
    distro: { id: 'debian', codename: 'trixie' },
    engines: {
      kea4: { version: '2.6.3', series: '2.6', source: 'distro', package: 'kea-dhcp4-server', maintained: false },
      d2: { version: '2.6.3', series: '2.6', source: 'distro', package: 'kea-dhcp-ddns-server', maintained: false },
    },
  }))
  const finding = (severity, code, node_id, engine, path, params, action, reference = KB_30) => ({
    severity, code, node_id, engine, path, message: { key: `kea_migration.${code}`, params: { path, ...params } }, action, reference,
  })

  return {
    'GET /install/kea-migration': () => ({ nodes: nodes(), targets: KEA_TARGETS, analysis: k.analysis, current: null }),
    'POST /install/kea-migration/analyze': ({ body, user }) => {
      const target = KEA_TARGETS.find((t) => t.series === body.series && t.source === body.source)
      if (!target) throw invalid('series', `one of ${KEA_TARGETS.map((t) => `${t.series}/${t.source}`).join(', ')}`)
      const all = state.nodes.map((n) => n.peer.id)
      const ids = body.node_ids?.length ? body.node_ids : all
      const unknown = ids.find((id) => !all.includes(id))
      if (unknown) throw invalid('node_ids', `unknown node ${unknown}`)
      const findings = ids.flatMap((id) => [
        finding('converted', 'renamed_key', id, 'kea4', 'Dhcp4/subnet4[0]/require-client-classes', { old: 'require-client-classes', new: 'evaluate-additional-classes' }, 'convert'),
        finding('converted', 'restrict_commands', id, 'kea4', 'Dhcp4/hooks-libraries[1]/parameters/high-availability[0]', {}, 'convert'),
        finding('converted', 'd2_secret_file', id, 'd2', 'DhcpDdns/tsig-keys[0]', { key: 'kea-ddns' }, 'convert'),
        finding('converted', 'ctrl_agent_stop', id, 'kea4', '', {}, 'stop_service', 'https://kb.isc.org/docs/kea-control-agent-migration'),
        finding('behavior', 'lease_cache', id, 'kea4', 'Dhcp4', { engine: 'kea4' }, 'none'),
        finding('info', 'validation_skipped', id, 'kea4', '', { engine: 'kea4', reason: 'mock' }, 'none', null),
      ])
      for (const f of findings) if (!SEVERITIES.includes(f.severity)) throw new Problem(500, 'internal', 'bad severity')
      const report = {
        id: ulid(), created_at: iso(Date.now()), created_by: user.username, series: target.series, source: target.source,
        target_version: target.version, node_ids: ids, findings,
        diffs: Object.fromEntries(ids.map((id) => [id, {
          kea4: `--- ${nameOf(id)} kea-dhcp4.conf (2.6)\n+++ ${nameOf(id)} kea-dhcp4.conf (${target.series})\n-        "require-client-classes": [ "voip" ]\n+        "evaluate-additional-classes": [ "voip" ]\n`,
          d2: `--- ${nameOf(id)} kea-dhcp-ddns.conf (2.6)\n+++ ${nameOf(id)} kea-dhcp-ddns.conf (${target.series})\n-      "secret": "..."\n+      "secret-file": "/etc/kea/tsig/kea-ddns.secret"\n`,
        }])),
        packages: Object.fromEntries(ids.map((id) => [id, {
          remove: DEBIAN_PACKAGES.map((name) => ({ name, version: '2.6.3-1+deb13u1' })),
          install: (target.source === 'isc' ? ISC_PACKAGES : DEBIAN_PACKAGES.filter((p) => p !== 'kea-ctrl-agent')).map((name) => ({ name, version: target.version })),
        }])),
        validation: Object.fromEntries(ids.map((id) => [id, { kea4: { ok: true, mode: 'dry_run', output: '' }, d2: { ok: true, mode: 'dry_run', output: '' } }])),
        counts: Object.fromEntries(SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length])),
        blocking: findings.some((f) => f.severity === 'blocking'),
        unreachable: [],
        outage_estimate_seconds: 45,
      }
      k.analysis = report
      auditEntry(state, user, { action: 'kea.migration.analyze', target: `kea-migration:${report.id}`, request: { series: report.series, source: report.source, node_ids: ids }, response: { blocking: report.blocking, counts: report.counts } })
      return report
    },
  }
}
