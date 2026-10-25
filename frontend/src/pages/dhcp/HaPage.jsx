// SPDX-License-Identifier: Apache-2.0
// High availability: one card per Kea server (state, role, scopes, partner view),
// live through the `ha` topic; maintenance and DHCP service toggles go through a
// confirmation dialog, then a plan that itself requires confirmation.
import { useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Heartbeat, Wrench, Power, ArrowRight, CheckCircle, Warning } from '@phosphor-icons/react'
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
import { haTone } from '../dashboard/radarLayout'
import { AreaPage, SectionError } from './ui'
import { usePlanFlow, useNodeNames } from './hooks'
import { HEALTHY_HA_STATES } from './lib'

const HA_POLL_MS = 5000

export default function HaPage({ family }) {
  const { t } = useTranslation(['dhcp', 'common'])
  const { hasPermission } = usePermission()
  const canOperate = hasPermission('ops:dhcp.ha')
  const { nameOf } = useNodeNames()
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
  const beats = useRef(new Map()) // node id -> { at, n }
  const beatOf = (h) => {
    const seen = beats.current.get(h.node_id)
    if (!seen) beats.current.set(h.node_id, { at: h.collected_at, n: 0 })
    else if (h.collected_at && h.collected_at !== seen.at) beats.current.set(h.node_id, { at: h.collected_at, n: seen.n + 1 })
    return beats.current.get(h.node_id).n
  }
  usePoll(async () => {
    const res = await api.dhcp.ha(family)
    if (res?.items) ha.setData(res)
  }, HA_POLL_MS, { enabled: Boolean(ha.data) })

  // Live state: replace the matching server's HAState in place.
  useWsTopic('ha', (msg) => {
    const next = msg?.data
    if (!next || next.family !== family) return
    ha.setData((cur) => {
      if (!cur?.items) return cur
      const found = cur.items.some((h) => h.node_id === next.node_id)
      return { ...cur, items: found ? cur.items.map((h) => (h.node_id === next.node_id ? next : h)) : [...cur.items, next] }
    })
  })

  const items = useMemo(() => ha.data?.items || [], [ha.data])
  const serverOf = (nodeId) => (servers.data?.items || []).find((s) => s.node_id === nodeId)
  const healthy = items.length > 0 && items.every((h) => h.enabled && HEALTHY_HA_STATES.includes(h.state) && h.partner?.in_touch !== false)

  const runConfirmed = async () => {
    const { kind, nodeId, value } = confirm
    setConfirm(null)
    if (kind === 'maintenance') await flow.build(() => api.dhcp.haMaintenancePlan(family, nodeId, value))
    else await flow.build(() => api.dhcp.servicePlan(family, nodeId, value))
  }

  const transitionColumns = [
    { key: 'ts', label: t('fields.time'), render: (r) => <span title={formatDate(r.ts)}>{formatRelativeTime(r.ts)}</span>, sortable: true },
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

  return (
    <AreaPage ns="dhcp" page="ha" icon={Heartbeat} family={family} onRefresh={refresh} loading={ha.loading}>
      <div className="space-y-4">
        <SectionError error={ha.error} onRetry={ha.refetch} />
        {ha.loading && !ha.data && (
          <div className="flex justify-center py-10">
            <LoadingSpinner size="md" />
          </div>
        )}
        {!ha.loading && !ha.error && items.length === 0 && <EmptyState icon={Heartbeat} title={t('ha.empty')} description={t('ha.emptyHint')} />}
        {items.length > 0 && (
          <Card className="px-4 py-3 flex flex-wrap items-center gap-x-6 gap-y-3" hover={false} data-testid="ha-summary">
            <span className={`flex items-center gap-2 text-sm ${healthy ? 'status-success-text' : 'status-warning-text'}`}>
              {healthy ? <CheckCircle size={16} weight="fill" /> : <Warning size={16} weight="fill" />}
              {healthy ? t('ha.healthy', { mode: haTerm(items[0].mode) }) : t('ha.degraded')}
            </span>
            <span className="ml-auto flex items-center flex-wrap gap-y-2" data-testid="ha-rail">
              {items.map((h, i) => (
                <span key={h.node_id} className="flex items-center">
                  {i > 0 && <FlowLine tone={h.partner?.in_touch === false || items[i - 1].partner?.in_touch === false ? 'danger' : 'primary'} length="44px" thickness={2} className="mx-1.5 ui-waypoint-joint" />}
                  <span className={`ui-waypoint fx-tone-${haTone(h)}`} title={haTerm(h.state)}>
                    <StatusDot tone={haTone(h)} size={6} pulse={haTone(h) === 'danger'} />
                    {h.server_name || nameOf(h.node_id)}
                    <span className="ui-waypoint-sub">{haTerm(h.state)}</span>
                  </span>
                </span>
              ))}
            </span>
          </Card>
        )}
        <div className="grid gap-4 lg:grid-cols-2">
          {items.map((h) => {
            const server = serverOf(h.node_id)
            const serviceEnabled = server?.status?.enabled
            const name = h.server_name || nameOf(h.node_id)
            // node_id in a maintenance plan is the server that enters (or leaves)
            // maintenance; the partner card cancels on that same server.
            const inMaintenance = h.state === 'in-maintenance'
            const maintained = h.state === 'partner-in-maintenance' ? items.find((x) => x !== h && x.state === 'in-maintenance') : null
            const cancelOn = inMaintenance ? h : maintained
            const cancelName = cancelOn && (cancelOn.server_name || nameOf(cancelOn.node_id))
            return (
              <Card key={h.node_id} className="p-0 overflow-hidden" hover={false} data-testid="ha-server">
                <div className="flex items-center gap-2 px-3 py-2 border-b border-border section-header-gradient">
                  <Heartbeat size={16} className="text-accent-pro" />
                  <span className="ui-card-title ui-title-literal text-sm font-semibold text-text-primary">{name}</span>
                  {h.role && <Badge variant="outline" size="sm">{haTerm(h.role)}</Badge>}
                  {h.enabled && (
                    <span className="ml-auto inline-flex items-center" title={t('ha.heartbeat')}>
                      <HeartbeatTrace beat={beatOf(h)} lost={h.partner?.in_touch === false || h.state === 'partner-down'} testId="ha-heartbeat" />
                    </span>
                  )}
                  <span className={h.enabled ? undefined : 'ml-auto'}>{h.enabled ? <StatusBadge status={h.state} data-testid="ha-state" /> : <Badge variant="gray" size="sm">{t('ha.hookMissing')}</Badge>}</span>
                </div>
                <div className="p-3 space-y-3 text-xs">
                  <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1">
                    <dt className="text-text-tertiary">{t('fields.node')}</dt>
                    <dd className="font-mono">{nameOf(h.node_id)}</dd>
                    <dt className="text-text-tertiary">{t('ha.mode')}</dt>
                    <dd>{haTerm(h.mode)}</dd>
                    <dt className="text-text-tertiary">{t('ha.scopes')}</dt>
                    <dd className="font-mono">{h.scopes?.length ? h.scopes.join(', ') : t('ha.noScopes')}</dd>
                    <dt className="text-text-tertiary">{t('ha.unsent')}</dt>
                    <dd>
                      <UnsentQueue count={h.unsent_update_count} />
                    </dd>
                    <dt className="text-text-tertiary">{t('ha.service')}</dt>
                    <dd>{serviceEnabled === undefined ? '-' : <StatusBadge status={serviceEnabled ? 'enabled' : 'disabled'} />}</dd>
                    <dt className="text-text-tertiary">{t('ha.collected')}</dt>
                    <dd title={formatDate(h.collected_at)}>{formatRelativeTime(h.collected_at)}</dd>
                  </dl>
                  {h.partner && (
                    <div className="rounded-lg border border-border p-2 space-y-1" data-testid="ha-partner">
                      <div className="flex items-center gap-2">
                        <span className="text-2xs uppercase tracking-wider text-text-tertiary">{t('ha.partnerView')}</span>
                        {h.partner.state && <StatusBadge status={h.partner.state} />}
                        <Badge variant={h.partner.in_touch === false ? 'danger' : 'success'} size="sm">
                          {h.partner.in_touch === false ? t('ha.notInTouch') : t('ha.inTouch')}
                        </Badge>
                      </div>
                      <div className="flex flex-wrap gap-x-4 gap-y-0.5 text-text-secondary">
                        <span>{t('ha.partnerRole', { role: haTerm(h.partner.role) })}</span>
                        {h.partner.age !== null && h.partner.age !== undefined && <span>{t('ha.partnerAge', { seconds: h.partner.age })}</span>}
                        {h.partner.unacked_clients > 0 && <span className="status-warning-text">{t('ha.unacked', { n: h.partner.unacked_clients })}</span>}
                      </div>
                    </div>
                  )}
                  {canOperate && h.enabled && (
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
          })}
        </div>
        <DataTable
          title={t('ha.transitions')}
          columns={transitionColumns}
          rows={[...(transitions.data?.items || [])].sort((a, b) => String(b.ts).localeCompare(String(a.ts)))}
          rowKey={(r, i) => `${r.ts}-${r.node_id}-${i}`}
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
        variant={confirm?.kind === 'service' && confirm?.value === false ? 'danger' : 'warning'}
        typeToConfirm={confirm?.kind === 'maintenance' && confirm?.value === 'start' ? confirm.name : undefined}
      />
      {flow.modal}
    </AreaPage>
  )
}
