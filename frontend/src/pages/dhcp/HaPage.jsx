// SPDX-License-Identifier: Apache-2.0
// High availability, one section per relationship (a Kea 3 hub is in several): the pair and any
// number of backups, every server with its role and state (those no Pelagos node runs included),
// then one card per Kea server, live through the `ha` topic. An active server's card shows its
// mode, scopes and partner; a backup's what it receives, the last lease update it saw and its
// lease count against the primary. Maintenance and DHCP service toggles go through a confirmation
// dialog, then a plan that itself requires confirmation; the relationships are edited with
// HaSetupModal (promoting a backup is an edit of the roles).
import { useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Heartbeat, Wrench, Power, ArrowRight, CheckCircle, Warning, PencilSimple, ArrowFatLineUp, Trash } from '@phosphor-icons/react'
import { Badge } from '../../components/Badge'
import { Button } from '../../components/Button'
import { Card } from '../../components/Card'
import { ConfirmDialog } from '../../components/ConfirmDialog'
import { DataTable } from '../../components/DataTable'
import { EmptyState } from '../../components/EmptyState'
import { LoadingSpinner } from '../../components/LoadingSpinner'
import { StatusBadge } from '../../components/StatusBadge'
import { useApi } from '../../hooks/useApi'
import { usePermission } from '../../hooks/usePermission'
import { useWsTopic } from '../../hooks/useWebSocket'
import { api } from '../../services/api'
import { formatDate, formatRelativeTime } from '../../lib/utils'
import { FlowLine, HeartbeatTrace, StatusDot, UnsentQueue } from '../../components/motion'
import { usePoll } from '../../hooks/usePoll'
import { useFallbackMs } from '../../hooks/useClusterSignals'
import { haTone } from '../dashboard/radarLayout'
import { AreaPage, SectionError } from './ui'
import { usePlanFlow, useNodeNames } from './hooks'
import { HEALTHY_HA_STATES, haTransitionRows } from './lib'
import { HaSetupModal } from './HaSetupModal'
import { asSetup, backupGap, draftForNodes, draftFromRelationship, draftFromRelationships, flattenHa, promoteDraft, relationshipHealthy } from './haSetup'

const HA_POLL_MS = 5000
const ROLE_ORDER = { primary: 0, secondary: 1, standby: 1, backup: 2 }
// Cards follow the relationship: the pair, primary first, then the backups.
const byRole = (a, b) => (ROLE_ORDER[a.role] ?? 3) - (ROLE_ORDER[b.role] ?? 3)
const cardKey = (h) => `${h.node_id}:${h.server_name || ''}`

export default function HaPage({ family }) {
  const { t } = useTranslation(['dhcp', 'common'])
  const { hasPermission } = usePermission()
  const canOperate = hasPermission('ops:dhcp.ha')
  const canConfigure = hasPermission('write:dhcp.config')
  const { nameOf, nodes } = useNodeNames()
  const [setup, setSetup] = useState(null) // { draft, title }
  // Kea roles and modes (primary, standby, hot-standby, ...) read in the UI language.
  const haTerm = (value) => (value ? t(`common:status.${value}`, { defaultValue: value }) : '-')
  const ha = useApi(() => api.dhcp.ha(family), [family])
  const servers = useApi(() => api.dhcp.servers(family), [family])
  const transitions = useApi(() => api.dhcp.haTransitions(family), [family])
  const [confirm, setConfirm] = useState(null)
  const refresh = () => {
    ha.refetch()
    servers.refetch()
    transitions.refetch()
  }
  const flow = usePlanFlow({ onApplied: refresh })
  // Each HA status sample newer than the last one seen is a heartbeat on the card's trace.
  const beats = useRef(new Map()) // node id and server name -> { at, n }
  const beatOf = (h) => {
    const key = cardKey(h)
    const seen = beats.current.get(key)
    if (!seen) beats.current.set(key, { at: h.collected_at, n: 0 })
    else if (h.collected_at && h.collected_at !== seen.at) beats.current.set(key, { at: h.collected_at, n: seen.n + 1 })
    return beats.current.get(key).n
  }
  usePoll(async () => {
    const res = await api.dhcp.ha(family)
    if (res?.items) ha.setData(res)
  }, useFallbackMs(HA_POLL_MS), { enabled: Boolean(ha.data) })

  // Live state: replace the matching server's HAState (all its relationships) in place.
  useWsTopic('ha', (msg) => {
    const next = msg?.data
    if (!next || next.family !== family) return
    ha.setData((cur) => {
      if (!cur?.items) return cur
      const found = cur.items.some((h) => h.node_id === next.node_id)
      return { ...cur, items: found ? cur.items.map((h) => (h.node_id === next.node_id ? next : h)) : [...cur.items, next] }
    })
  })

  // One state per relationship a server is in: a hub's other relationships follow it.
  const items = useMemo(() => flattenHa(ha.data?.items).sort(byRole), [ha.data])
  // The relationships as the nodes configure them (GET .../ha `relationships`), live states merged in.
  const rels = useMemo(
    () =>
      (ha.data?.relationships || []).map((found) => ({
        ...found,
        servers: found.servers.map((srv) => {
          const live = items.find((h) => h.node_id && h.node_id === srv.node_id && (!h.server_name || h.server_name === srv.name))
          return live ? { ...srv, state: live.state, unsent_update_count: live.unsent_update_count } : srv
        }),
      })),
    [ha.data, items],
  )
  const serverOf = (nodeId) => (servers.data?.items || []).find((s) => s.node_id === nodeId)
  const inRel = (rel, h) => rel.servers.some((s) => s.name === h.server_name && (!s.node_id || s.node_id === h.node_id))
  const loose = items.filter((h) => !rels.some((rel) => inRel(rel, h)))

  const runConfirmed = async () => {
    const { kind, nodeId, value } = confirm
    setConfirm(null)
    if (kind === 'maintenance') await flow.build(() => api.dhcp.haMaintenancePlan(family, nodeId, value))
    else if (kind === 'remove') await flow.build(() => api.dhcp.haSetupPlan(family, { remove: true }))
    else await flow.build(() => api.dhcp.servicePlan(family, nodeId, value))
  }

  const transitionColumns = [
    { key: 'ts', label: t('fields.time'), render: (r) => <span title={formatDate(r.at)}>{formatRelativeTime(r.at)}</span>, sortable: true },
    { key: 'server_name', label: t('fields.server'), render: (r) => r.server_name || nameOf(r.node_id) },
    {
      key: 'change',
      label: t('ha.transition'),
      render: (r) => (
        <span className="inline-flex items-center gap-1.5">
          <StatusBadge status={r.from_state} dot={false} />
          <ArrowRight size={11} className="text-text-tertiary" />
          <StatusBadge status={r.to_state} dot={false} />
        </span>
      ),
    },
    { key: 'partner_state', label: t('ha.partnerState'), render: (r) => (r.partner_state ? <StatusBadge status={r.partner_state} dot={false} /> : '-') },
  ]

  const confirmText = confirm && {
    title: t(`ha.confirm.${confirm.kind}.${String(confirm.value)}.title`, { server: confirm.name }),
    message: t(`ha.confirm.${confirm.kind}.${String(confirm.value)}.message`, { server: confirm.name }),
  }

  const leasesCell = (r) =>
    r.leases === null || r.leases === undefined ? (
      '-'
    ) : (
      <span className="font-mono" title={r.last_lease_at ? t('ha.lastLease', { when: formatDate(r.last_lease_at) }) : undefined}>
        {r.leases}
      </span>
    )
  const serverColumns = [
    { key: 'name', label: t('fields.server'), render: (r) => <span className="font-mono">{r.name}</span> },
    { key: 'role', label: t('ha.setup.role'), render: (r) => <Badge variant={r.role === 'backup' ? 'gray' : 'purple'} size="sm">{haTerm(r.role)}</Badge> },
    { key: 'node', label: t('fields.node'), render: (r) => (r.node_id ? <span className="font-mono">{nameOf(r.node_id)}</span> : <span className="text-text-tertiary">{t('ha.setup.noNode')}</span>) },
    { key: 'state', label: t('ha.state'), render: (r) => (r.state ? <StatusBadge status={r.state} /> : '-') },
    {
      key: 'touch',
      label: t('ha.contact'),
      render: (r) =>
        r.role === 'backup' ? (
          <span className="text-text-tertiary">{t('ha.receivesUpdates')}</span>
        ) : r.in_touch === null || r.in_touch === undefined ? (
          '-'
        ) : (
          <Badge variant={r.in_touch ? 'success' : 'danger'} size="sm">
            {r.in_touch ? t('ha.inTouch') : t('ha.notInTouch')}
          </Badge>
        ),
    },
    { key: 'leases', label: t('ha.leases'), render: leasesCell },
    { key: 'url', label: t('ha.setup.url'), render: (r) => <span className="font-mono text-text-secondary">{r.url || '-'}</span> },
  ]

  const openSetup = (draft, title) => setSetup({ draft, title })
  const editRelationship = () =>
    openSetup(rels.length ? draftFromRelationships(rels) : asSetup(draftForNodes(nodes, family)), rels.length ? t('ha.setup.editTitle') : t('ha.setup.title'))
  const removeRelationship = () =>
    setConfirm({ kind: 'remove', value: true, name: [...new Set(rels.flatMap((rel) => rel.servers.map((srv) => srv.name)))].join(', ') })
  const promote = (r, name, label) =>
    openSetup({ relationships: rels.map((rel, j) => (j === r ? promoteDraft(rel, name) : draftFromRelationship(rel))) }, t('ha.setup.promoteTitle', { server: label }))

  // A backup's card: what it receives and how far its leases are from the primary's.
  const backupFields = (srv) => {
    const gap = backupGap(srv)
    return (
      <>
        <dt className="text-text-tertiary">{t('ha.receives')}</dt>
        <dd data-testid="ha-backup-receives">{srv?.receives_from?.length ? t('ha.receivesFrom', { servers: srv.receives_from.join(', ') }) : '-'}</dd>
        <dt className="text-text-tertiary">{t('ha.lastUpdate')}</dt>
        <dd data-testid="ha-backup-last" title={srv?.last_lease_at ? formatDate(srv.last_lease_at) : undefined}>
          {srv?.last_lease_at ? formatRelativeTime(srv.last_lease_at) : t('ha.noLeaseSeen')}
        </dd>
        <dt className="text-text-tertiary">{t('ha.leases')}</dt>
        <dd className="flex flex-wrap items-center gap-2" data-testid="ha-backup-leases">
          <span className="font-mono">{srv?.leases ?? '-'}</span>
          {srv?.lease_reference && (
            <>
              <span className="text-text-secondary">{t('ha.leasesOf', { server: srv.lease_reference.server, count: srv.lease_reference.leases })}</span>
              {gap !== null && (
                <Badge variant={gap.inStep ? 'success' : 'warning'} size="sm">
                  {gap.inStep ? t('ha.inStep') : t('ha.leaseGap', { n: gap.diff })}
                </Badge>
              )}
            </>
          )}
        </dd>
      </>
    )
  }

  const serverCard = (h, rel, r) => {
    const server = serverOf(h.node_id)
    const srv = rel?.servers.find((s) => s.name === h.server_name)
    const serviceEnabled = server?.status?.enabled
    const name = h.server_name || nameOf(h.node_id)
    const backup = h.role === 'backup'
    // node_id in a maintenance plan is the server that enters (or leaves) maintenance; the
    // partner card cancels on that same server.
    const inMaintenance = h.state === 'in-maintenance'
    const maintained = h.state === 'partner-in-maintenance' ? items.find((x) => x !== h && x.state === 'in-maintenance' && x.server_name === h.partner?.server_name) || items.find((x) => x !== h && x.state === 'in-maintenance') : null
    const cancelOn = inMaintenance ? h : maintained
    const cancelName = cancelOn && (cancelOn.server_name || nameOf(cancelOn.node_id))
    return (
      <Card key={cardKey(h)} className="p-0 overflow-hidden" hover={false} data-testid="ha-server" data-role={h.role || ''}>
        <div className="flex items-center gap-2 px-3 py-2 border-b border-border section-header-gradient">
          <Heartbeat size={16} className="text-accent-pro" />
          <span className="ui-card-title ui-title-literal text-sm font-semibold text-text-primary">{name}</span>
          {h.role && <Badge variant="outline" size="sm">{haTerm(h.role)}</Badge>}
          {h.enabled && !backup && (
            <span className="ml-auto inline-flex items-center" title={t('ha.heartbeat')}>
              <HeartbeatTrace beat={beatOf(h)} lost={h.partner?.in_touch === false || h.state === 'partner-down'} testId="ha-heartbeat" />
            </span>
          )}
          <span className={h.enabled && !backup ? undefined : 'ml-auto'}>{h.enabled ? <StatusBadge status={h.state} data-testid="ha-state" /> : <Badge variant="gray" size="sm">{t('ha.hookMissing')}</Badge>}</span>
        </div>
        <div className="p-3 space-y-3 text-xs">
          <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1">
            <dt className="text-text-tertiary">{t('fields.node')}</dt>
            <dd className="font-mono">{nameOf(h.node_id)}</dd>
            {backup ? (
              <>
                <dt className="text-text-tertiary">{t('ha.setup.role')}</dt>
                <dd>{haTerm('backup')}</dd>
                {backupFields(srv)}
              </>
            ) : (
              <>
                <dt className="text-text-tertiary">{t('ha.mode')}</dt>
                <dd>{haTerm(h.mode)}</dd>
                <dt className="text-text-tertiary">{t('ha.scopes')}</dt>
                <dd className="font-mono">{h.scopes?.length ? h.scopes.join(', ') : t('ha.noScopes')}</dd>
                <dt className="text-text-tertiary">{t('ha.unsent')}</dt>
                <dd>
                  <UnsentQueue count={h.unsent_update_count} />
                </dd>
                {srv?.leases !== null && srv?.leases !== undefined && (
                  <>
                    <dt className="text-text-tertiary">{t('ha.leases')}</dt>
                    <dd className="font-mono">{srv.leases}</dd>
                  </>
                )}
                <dt className="text-text-tertiary">{t('ha.service')}</dt>
                <dd>{serviceEnabled === undefined ? '-' : <StatusBadge status={serviceEnabled ? 'enabled' : 'disabled'} />}</dd>
              </>
            )}
            <dt className="text-text-tertiary">{t('ha.collected')}</dt>
            <dd title={formatDate(h.collected_at)}>{formatRelativeTime(h.collected_at)}</dd>
          </dl>
          {h.partner && !backup && (
            <div className="rounded-lg border border-border p-2 space-y-1" data-testid="ha-partner">
              <div className="flex items-center gap-2">
                <span className="text-2xs uppercase tracking-wider text-text-tertiary">{t('ha.partnerView')}</span>
                {h.partner.state && <StatusBadge status={h.partner.state} />}
                <Badge variant={h.partner.in_touch === false ? 'danger' : 'success'} size="sm">
                  {h.partner.in_touch === false ? t('ha.notInTouch') : t('ha.inTouch')}
                </Badge>
              </div>
              <div className="flex flex-wrap gap-x-4 gap-y-0.5 text-text-secondary">
                {h.partner.server_name && <span className="font-mono">{h.partner.server_name}</span>}
                <span>{t('ha.partnerRole', { role: haTerm(h.partner.role) })}</span>
                {h.partner.age !== null && h.partner.age !== undefined && <span>{t('ha.partnerAge', { seconds: h.partner.age })}</span>}
                {h.partner.unacked_clients > 0 && <span className="status-warning-text">{t('ha.unacked', { n: h.partner.unacked_clients })}</span>}
              </div>
            </div>
          )}
          {backup && (
            <div className="rounded-lg border border-dashed border-border p-2 text-text-secondary" data-testid="ha-backup-note">
              {t('ha.backupNote')}
            </div>
          )}
          {backup && canConfigure && rel && (
            <div className="flex flex-wrap gap-2 pt-1 border-t border-border">
              <Button variant="secondary" size="xs" onClick={() => promote(r, h.server_name, name)} disabled={flow.building} data-testid="ha-promote">
                <ArrowFatLineUp size={12} />
                {t('ha.setup.promote')}
              </Button>
            </div>
          )}
          {canOperate && h.enabled && !backup && (
            <div className="flex flex-wrap gap-2 pt-1 border-t border-border">
              <Button
                variant="warning-soft"
                size="xs"
                onClick={() =>
                  setConfirm(
                    cancelOn
                      ? { kind: 'maintenance', nodeId: cancelOn.node_id, value: 'cancel', name: cancelName }
                      : { kind: 'maintenance', nodeId: h.node_id, value: 'start', name },
                  )
                }
                disabled={flow.building || (!cancelOn && h.state === 'partner-in-maintenance')}
                data-testid={cancelOn ? 'ha-maintenance-cancel' : 'ha-maintenance-start'}
              >
                <Wrench size={12} />
                {cancelOn ? t('ha.cancelMaintenance') : t('ha.startMaintenance')}
              </Button>
              {serviceEnabled !== undefined && (
                <Button
                  variant={serviceEnabled ? 'danger-soft' : 'secondary'}
                  size="xs"
                  onClick={() => setConfirm({ kind: 'service', nodeId: h.node_id, value: !serviceEnabled, name })}
                  disabled={flow.building}
                  data-testid="ha-service-toggle"
                >
                  <Power size={12} />
                  {serviceEnabled ? t('ha.disableService') : t('ha.enableService')}
                </Button>
              )}
            </div>
          )}
        </div>
      </Card>
    )
  }

  // The health line and the rail of one relationship (or of the servers when none is configured).
  const summaryCard = (rel, members) => {
    const backups = rel?.servers.filter((srv) => srv.role === 'backup') || []
    const healthy = rel
      ? relationshipHealthy(rel)
      : members.length > 0 && members.every((h) => h.enabled && HEALTHY_HA_STATES.includes(h.state) && h.partner?.in_touch !== false)
    return (
      <Card className="px-4 py-3 flex flex-wrap items-center gap-x-6 gap-y-3" hover={false} data-testid="ha-summary">
        <span className={`flex items-center gap-2 text-sm ${healthy ? 'status-success-text' : 'status-warning-text'}`}>
          {healthy ? <CheckCircle size={16} weight="fill" /> : <Warning size={16} weight="fill" />}
          {healthy ? t(backups.length ? 'ha.healthyBackups' : 'ha.healthy', { mode: haTerm(rel?.mode || members[0]?.mode), count: backups.length }) : t('ha.degraded')}
        </span>
        <span className="ml-auto flex items-center flex-wrap gap-y-2" data-testid="ha-rail">
          {(rel ? rel.servers : members).map((x, i, all) => {
            const h = rel ? members.find((it) => it.node_id && it.node_id === x.node_id && it.server_name === x.name) || { state: x.state, partner: { in_touch: x.in_touch } } : x
            const name = rel ? x.name : x.server_name || nameOf(x.node_id)
            const role = x.role
            const prev = all[i - 1]
            const feed = role === 'backup'
            const lost = !feed && prev && (h.partner?.in_touch === false || (rel ? prev.in_touch === false : prev.partner?.in_touch === false))
            return (
              <span key={`${name}-${i}`} className="flex items-center" data-testid="ha-rail-server" data-role={role || ''}>
                {i > 0 &&
                  (feed ? (
                    <span className="mx-1.5 w-8 border-t border-dashed border-accent-pro" title={t('ha.leaseFeed')} aria-hidden="true" />
                  ) : (
                    <FlowLine tone={lost ? 'danger' : 'primary'} length="44px" thickness={2} className="mx-1.5 ui-waypoint-joint" />
                  ))}
                <span className={`ui-waypoint fx-tone-${haTone(h)}`} title={haTerm(h.state)}>
                  <StatusDot tone={haTone(h)} size={6} pulse={haTone(h) === 'danger'} />
                  {name}
                  <span className="ui-waypoint-sub">{feed ? haTerm('backup') : haTerm(h.state)}</span>
                </span>
              </span>
            )
          })}
        </span>
      </Card>
    )
  }

  return (
    <AreaPage
      ns="dhcp"
      page="ha"
      icon={Heartbeat}
      family={family}
      onRefresh={refresh}
      loading={ha.loading}
      actions={
        canConfigure && ha.data ? (
          <>
            {rels.length > 0 && (
              <Button variant="danger-soft" size="sm" onClick={removeRelationship} disabled={flow.building} data-testid="ha-remove">
                <Trash size={14} />
                {t('ha.setup.removeHa')}
              </Button>
            )}
            <Button variant="secondary" size="sm" onClick={editRelationship} disabled={flow.building} data-testid="ha-setup">
              <PencilSimple size={14} />
              {rels.length ? t(rels.length > 1 ? 'ha.setup.editMany' : 'ha.setup.edit') : t('ha.setup.start')}
            </Button>
          </>
        ) : null
      }
    >
      <div className="space-y-4">
        <SectionError error={ha.error} onRetry={ha.refetch} />
        {ha.loading && !ha.data && (
          <div className="flex justify-center py-10">
            <LoadingSpinner size="md" />
          </div>
        )}
        {!ha.loading && !ha.error && items.length === 0 && <EmptyState icon={Heartbeat} title={t('ha.empty')} description={t('ha.emptyHint')} />}
        {rels.map((rel, r) => {
          const members = items.filter((h) => inRel(rel, h))
          return (
            <section key={rel.servers.map((s) => s.name).join(',')} className="space-y-4" data-testid="ha-relationship">
              {rels.length > 1 && (
                <h2 className="ui-section-title text-sm font-semibold text-text-primary" data-testid="ha-relationship-title">
                  {t('ha.relationshipTitle', { n: r + 1, mode: haTerm(rel.mode), servers: rel.servers.map((s) => s.name).join(', ') })}
                </h2>
              )}
              {summaryCard(rel, members)}
              <DataTable
                title={t('ha.relationship', { count: rel.servers.length })}
                columns={serverColumns}
                rows={rel.servers}
                rowKey={(row) => row.name}
                emptyTitle={t('ha.empty')}
                dense
                testId="ha-servers"
              />
              <div className="grid gap-4 lg:grid-cols-2">{members.map((h) => serverCard(h, rel, r))}</div>
            </section>
          )
        })}
        {loose.length > 0 && (
          <>
            {!rels.length && summaryCard(null, loose)}
            <div className="grid gap-4 lg:grid-cols-2">{loose.map((h) => serverCard(h, null, -1))}</div>
          </>
        )}
        <DataTable
          title={t('ha.transitions')}
          columns={transitionColumns}
          rows={haTransitionRows(transitions.data?.items)}
          rowKey={(row, i) => `${row.ts}-${row.node_id}-${i}`}
          loading={transitions.loading}
          error={transitions.error}
          onRetry={transitions.refetch}
          clientSort
          emptyTitle={t('ha.noTransitions')}
          dense
          testId="ha-transitions"
        />
      </div>
      <ConfirmDialog
        open={Boolean(confirm)}
        onOpenChange={(o) => !o && setConfirm(null)}
        onConfirm={runConfirmed}
        title={confirmText?.title}
        message={confirmText?.message}
        confirmLabel={t('ha.buildPlan')}
        variant={confirm?.kind === 'remove' || (confirm?.kind === 'service' && confirm?.value === false) ? 'danger' : 'warning'}
        typeToConfirm={confirm?.kind === 'maintenance' && confirm?.value === 'start' ? confirm.name : undefined}
      />
      {setup && <HaSetupModal family={family} initial={setup.draft} title={setup.title} nodes={nodes} flow={flow} onClose={() => setSetup(null)} />}
      {flow.modal}
    </AreaPage>
  )
}
