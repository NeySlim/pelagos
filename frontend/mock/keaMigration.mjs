// SPDX-License-Identifier: Apache-2.0
// Kea 3.x migration of the mock: series and package source of every node, the available targets, a
// read-only report (architecture section 26), then the prepare, migrate and rollback plans whose job
// steps move the replicated migration state and the HA states (section 28). POST /_mock/kea-migration
// {fail_at: step} makes that step fail: before the primary's turn the pair goes back automatically.
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

// Step names and order of each phase (core/kea_migration.py); `who` picks the nodes that run it.
const PREPARE_STEPS = [['kea-mig-archive', 'all'], ['kea-mig-prepare', 'all']]
const MIGRATE_STEPS = [
  ['kea-mig-ha-maintenance', 'primary', 'standby'], ['kea-mig-stop', 'standby', 'standby'],
  ['kea-mig-install', 'standby', 'standby'], ['kea-mig-validate-partner', 'standby', 'standby'],
  ['kea-mig-stop', 'primary', 'window'], ['kea-mig-fetch-leases', 'standby', 'window'],
  ['kea-mig-leases-in', 'standby', 'window'], ['kea-mig-start', 'standby', 'window'],
  ['kea-mig-wait-partner-down', 'standby', 'window'], ['kea-mig-install', 'primary', 'primary'],
  ['kea-mig-start', 'primary', 'primary'], ['kea-mig-wait-ha', 'primary', 'primary'],
  ['kea-mig-delays', 'all', 'primary'], ['kea-mig-finish', 'all', 'primary'],
]
const ROLLBACK_STEPS = [
  ['kea-mig-ha-maintenance', 'primary'], ['kea-mig-stop', 'standby'], ['kea-mig-install', 'standby'],
  ['kea-mig-stop', 'primary'], ['kea-mig-fetch-leases', 'standby'], ['kea-mig-leases-in', 'standby'],
  ['kea-mig-start', 'standby'], ['kea-mig-wait-partner-down', 'standby'], ['kea-mig-install', 'primary'],
  ['kea-mig-start', 'primary'], ['kea-mig-wait-ha', 'primary'],
]
const REPLACEABLE = ['prepared', 'prepare_failed', 'migrated', 'rolled_back']
const stepKey = (step) => `job.step.kea_migration.${step.replace(/^kea-mig-/, '').replaceAll('-', '_')}`

export function keaMigrationHandlers(state, { Problem, invalid, createPlan, hasPermission }) {
  // Read at each call: a scenario switch replaces state.keaMigration.
  const K = () => (state.keaMigration ||= { analysis: null, migration: null, failAt: null })
  const nameOf = (id) => state.nodes.find((n) => n.peer.id === id)?.peer.name || id
  const nodes = () => state.nodes.map((n) => ({
    node_id: n.peer.id, name: n.peer.name, reachable: true, error: null, arch: 'amd64',
    distro: { id: 'debian', codename: 'trixie' },
    engines: {
      kea4: { version: '2.6.3', series: '2.6', source: 'distro', package: 'kea-dhcp4-server', maintained: false, eol: '2026-07-30', successor: '3.2' },
      d2: { version: '2.6.3', series: '2.6', source: 'distro', package: 'kea-dhcp-ddns-server', maintained: false, eol: '2026-07-30', successor: '3.2' },
    },
  }))
  const finding = (severity, code, node_id, engine, path, params, action, reference = KB_30) => ({
    severity, code, node_id, engine, path, message: { key: `kea_migration.${code}`, params: { path, ...params } }, action, reference,
  })

  const outageMax = () => state.settings.kea?.migration_outage_max_seconds ?? 180
  const rollbackPossible = (m) => !!m && ['migrating', 'failed', 'migrated'].includes(m.state) && m.nodes.every((n) => n.rollback_ready)
  const view = (m) => m && {
    ...m,
    nodes: m.nodes.map(({ packages_before: _b, packages_target: _t, ...n }) => n),
    outage_max_seconds: outageMax(),
    rollback_possible: rollbackPossible(m),
  }
  const roleOf = (id) => state.ha.v4?.find((s) => s.node_id === id)?.role || 'single'
  const haOf = (id) => state.ha.v4?.find((s) => s.node_id === id)
  const setHa = (id, haState, partnerState, inTouch) => {
    const s = haOf(id)
    if (!s) return
    s.state = haState
    if (s.partner) s.partner = { ...s.partner, state: partnerState, in_touch: inTouch, age: inTouch ? 0 : null }
    s.collected_at = iso(Date.now())
    state.emit?.('ha', 'state', s)
  }
  const nodeOf = (m, id) => m.nodes.find((n) => n.node_id === id)
  const touch = (m) => { m.updated_at = iso(Date.now()) }
  const pick = (m, who) => {
    if (who === 'all') return m.nodes.map((n) => n.node_id)
    const ids = m.nodes.filter((n) => n.role === who).map((n) => n.node_id)
    // Backups go with the standby (design 13.4); a node without HA runs both turns alone.
    if (who === 'standby') ids.unshift(...m.nodes.filter((n) => n.role === 'backup').map((n) => n.node_id))
    if (who === 'primary' && !ids.length) ids.push(...m.nodes.filter((n) => n.role === 'single').map((n) => n.node_id))
    return ids
  }
  const stepsOf = (m, list) => list.flatMap(([step, who, stage]) => pick(m, who).map((id) => ({ step, id, stage })))

  // The effect of one step starting on its node; false when the mock was told to fail it.
  const run = (m, phase, { step, id, stage }) => {
    const node = nodeOf(m, id)
    if (K().failAt === step) return false
    node.step = step
    node.status = 'running'
    node.started_at ||= iso(Date.now())
    if (stage) m.stage = stage
    const back = phase === 'rollback'
    if (step === 'kea-mig-archive') node.archive_id = ulid()
    if (step === 'kea-mig-prepare') Object.assign(node, { prepared_at: iso(Date.now()), rollback_ready: true })
    if (step === 'kea-mig-ha-maintenance') setHa(id, 'partner-in-maintenance', 'in-maintenance', true)
    if (step === 'kea-mig-stop') {
      setHa(id, 'unavailable', 'unavailable', false)
      if (node.role === 'primary') m.outage_started_at = iso(Date.now())
    }
    if (step === 'kea-mig-start') {
      node.to_version = back ? node.from_version : m.target_version
      if (node.role === 'primary' || node.role === 'single') {
        setHa(id, 'hot-standby', 'hot-standby', true)
        for (const other of m.nodes) if (other.node_id !== id) setHa(other.node_id, 'hot-standby', 'hot-standby', true)
      }
    }
    if (step === 'kea-mig-wait-partner-down') {
      setHa(id, 'partner-down', 'unavailable', false)
      m.outage_seconds = Math.round((Date.now() - new Date(m.outage_started_at).getTime()) / 100) / 10
    }
    touch(m)
    return true
  }
  const finishNodes = (m, status) => {
    for (const n of m.nodes) Object.assign(n, { status, finished_at: iso(Date.now()) })
  }
  const failed = (m, phase, { step }) => {
    const auto = (m.options.auto_rollback ?? state.settings.kea?.migration_auto_rollback_enabled ?? true)
    m.error = `${step} failed (mock)`
    m.error_step = step
    if (phase === 'migrate' && auto && ['standby', 'window'].includes(m.stage)) {
      // Automatic return during time 1 or 2: the standby back in 2.6, the primary serves again.
      m.state = 'rolled_back'
      m.phase = 'rollback'
      for (const n of m.nodes) { n.to_version = n.from_version; setHa(n.node_id, 'hot-standby', 'hot-standby', true) }
      finishNodes(m, 'rolled_back')
    } else {
      m.state = phase === 'prepare' ? 'prepare_failed' : 'failed'
      for (const n of m.nodes) if (n.status === 'running') n.status = 'failed'
    }
    m.finished_at = iso(Date.now())
    touch(m)
  }

  const plan = (user, id, body) => {
    const phase = body.phase
    if (!['prepare', 'migrate', 'rollback'].includes(phase)) throw invalid('phase', 'one of prepare, migrate, rollback')
    const opts = body.options || {}
    const delay = opts.response_delay_milliseconds
    if (delay !== undefined && (!Number.isInteger(delay) || delay < 1000 || delay > 60000)) throw invalid('options.response_delay_milliseconds', 'an integer from 1000 to 60000')
    let m = K().migration
    if (phase === 'prepare') {
      if (!K().analysis || K().analysis.id !== id) throw new Problem(404, 'not_found', `no analysis ${id}: analyze first`)
      if (K().analysis.blocking) throw new Problem(409, 'conflict', 'a blocking finding is still open')
      if (m && !REPLACEABLE.includes(m.state)) throw new Problem(409, 'conflict', `a migration is ${m.state}: finish or roll it back first`)
      const a = K().analysis
      const target = KEA_TARGETS.find((t) => t.series === a.series && t.source === a.source)
      m = {
        id: a.id, analysis_id: a.id, series: a.series, source: a.source, target_version: target?.version ?? a.target_version,
        from_series: '2.6', state: 'preparing', phase: 'prepare', stage: null, driver: state.selfId, plan_id: null,
        created_by: user.username, started_at: null, updated_at: iso(Date.now()), finished_at: null,
        outage_started_at: null, outage_seconds: null,
        options: { response_delay_milliseconds: delay ?? null, https_sockets: !!opts.https_sockets, auto_rollback: null },
        error: null, error_step: null,
        nodes: a.node_ids.map((nid, i) => ({
          node_id: nid, name: nameOf(nid), role: roleOf(nid), order: i, engines: ['kea4', 'd2'], step: null, status: 'pending',
          ha_state: haOf(nid)?.state ?? null, from_version: '2.6.3', to_version: '2.6.3',
          packages_before: a.packages?.[nid]?.remove ?? [], packages_target: a.packages?.[nid]?.install ?? [],
          archive_id: null, rollback_ready: false, prepared_at: null, started_at: null, finished_at: null, error: null,
        })),
      }
    } else {
      if (!m || m.id !== id) throw new Problem(404, 'not_found', `no Kea migration ${id}`)
      if (phase === 'migrate' && !(m.state === 'prepared' || (m.state === 'failed' && m.phase === 'migrate'))) throw new Problem(409, 'conflict', `the migration is ${m.state}: migrate needs it prepared`)
      if (phase === 'rollback' && !rollbackPossible(m)) throw new Problem(409, 'conflict', `no rollback possible from ${m.state}`)
    }
    const record = m
    const steps = stepsOf(record, phase === 'prepare' ? PREPARE_STEPS : phase === 'migrate' ? MIGRATE_STEPS : ROLLBACK_STEPS)
    const names = record.nodes.map((n) => n.name).join(', ')
    const series = phase === 'rollback' ? record.from_series : record.series
    const summary_message = { key: `plan.kea_migration.${phase}`, params: { nodes: names, series, source: record.source, outage: 30 } }
    const summary = phase === 'prepare'
      ? `prepare the move of ${names} to Kea ${series} (${record.source}): archives, packages downloaded, converted files written aside, nothing stopped`
      : phase === 'migrate'
        ? `move ${names} to Kea ${series} (${record.source}): standby first, a DHCP outage of about 30 s, then the primary`
        : `return ${names} to Kea ${series}: previous packages and files`
    const changes = steps.map(({ step, id: nid }) => ({
      op: 'replace', target: `kea-migration/${step}/${nid}`, before: null,
      after: { step, details: { migration_id: record.id, series: record.series, source: record.source }, summary: `${nameOf(nid)}: ${step}` },
      node_ids: [nid],
    }))
    const created = createPlan(state, user, {
      scope: 'kea.migration',
      engine: 'kea4',
      summary,
      summary_message,
      changes,
      diff: changes.map((c) => `~ ${c.target}: ${c.after.summary}`).join('\n'),
      targets: record.nodes.map((n) => n.node_id),
      tool: 'kea-dhcp4',
      requires_confirmation: true,
      job: steps.map(({ step, id: nid }) => ({ name: `kea-migration/${step}/${nid}`, label: `${nameOf(nid)}: ${step}`, label_message: { key: stepKey(step), params: { node: nameOf(nid) } } })),
      onStart: () => {
        if (phase === 'prepare') K().migration = record
        record.phase = phase
        record.state = phase === 'prepare' ? 'preparing' : phase === 'migrate' ? 'migrating' : 'rolling_back'
        record.started_at = iso(Date.now())
        record.finished_at = null
        record.error = record.error_step = null
        record.plan_id = created.id
        for (const n of record.nodes) Object.assign(n, { status: 'pending', started_at: null, finished_at: null })
        touch(record)
      },
      onStep: (index) => run(record, phase, steps[index]),
      onStepDone: (index) => { nodeOf(record, steps[index].id).status = 'done' },
      onFail: (index) => failed(record, phase, steps[index]),
      apply: () => {
        record.state = phase === 'prepare' ? 'prepared' : phase === 'migrate' ? 'migrated' : 'rolled_back'
        if (phase !== 'prepare') record.stage = phase === 'migrate' ? 'done' : record.stage
        record.finished_at = iso(Date.now())
        finishNodes(record, phase === 'rollback' ? 'rolled_back' : 'done')
        touch(record)
        auditEntry(state, user, { action: `kea.migration.${phase === 'migrate' ? 'step' : phase}`, target: `kea-migration:${record.id}`, request: { phase }, response: { state: record.state } })
      },
    })
    return created
  }

  return {
    'GET /install/kea-migration': () => ({ nodes: nodes(), targets: KEA_TARGETS, analysis: K().analysis, current: view(K().migration) }),
    'GET /install/kea-migration/{id}': ({ params }) => {
      if (!K().migration || K().migration.id !== params.id) throw new Problem(404, 'not_found', `no Kea migration ${params.id}`)
      return view(K().migration)
    },
    'POST /install/kea-migration/{id}/plan': ({ params, body, user }) => {
      if (!hasPermission(user, 'ops:dhcp.ha')) throw new Problem(403, 'forbidden', 'requires ops:dhcp.ha')
      return plan(user, params.id, body || {})
    },
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
      K().analysis = report
      auditEntry(state, user, { action: 'kea.migration.analyze', target: `kea-migration:${report.id}`, request: { series: report.series, source: report.source, node_ids: ids }, response: { blocking: report.blocking, counts: report.counts } })
      return report
    },
  }
}
