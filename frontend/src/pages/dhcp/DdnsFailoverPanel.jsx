// SPDX-License-Identifier: Apache-2.0
// DDNS > Failover (architecture section 24): the active primary of each dynamic zone with its
// copies, epoch and blockers, the D2 server lists, the outage and stale primary banners, and the
// prepare, promote, switchover and replay plans through the usual plan preview.
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { ArrowsCounterClockwise, ArrowUp, ShieldCheck, Swap, WarningOctagon } from '@phosphor-icons/react'
import { Badge } from '../../components/Badge'
import { Button } from '../../components/Button'
import { Card } from '../../components/Card'
import { DataTable } from '../../components/DataTable'
import { FormModal } from '../../components/FormModal'
import { Input } from '../../components/Input'
import { LoadingSpinner } from '../../components/LoadingSpinner'
import { useApi } from '../../hooks/useApi'
import { usePermission } from '../../hooks/usePermission'
import { useWsTopic } from '../../hooks/useWebSocket'
import { useMessage } from '../../i18n/message'
import { formatDate, formatRelativeTime } from '../../lib/utils'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { NativeSelect, SectionError, Stat } from './ui'
import { usePlanFlow, useNodeNames } from './hooks'
import {
  STATE_TONE, alertsByZone, blockerAction, isPrepared, isPreparable, outageSummary, replayBody, replayKnown, targetNodes,
  toLocalInput, zoneKey, zoneLabel, zoneState,
} from './ddnsFailover'

const ALERT_KINDS = ['ddns_outage', 'dns_stale_primary']

export function DdnsFailoverPanel({ selectedZone, refreshKey = 0 }) {
  const { t } = useTranslation(['dhcp', 'common'])
  const { hasPermission } = usePermission()
  const canRead = hasPermission('read:dhcp') && hasPermission('read:dns')
  const canPlan = hasPermission('write:dns.zones') && hasPermission('write:dhcp.config')
  const canReplay = hasPermission('ops:dhcp.leases')
  const res = useApi(() => api.ddnsFailover.resilience(), [refreshKey], { enabled: canRead })
  const alerts = useApi(
    async () => {
      const lists = await Promise.all(ALERT_KINDS.map((kind) => api.alerts.list({ kind, state: 'open', per_page: 200 }).catch(() => ({ items: [] }))))
      return lists.flatMap((l) => l?.items || [])
    },
    [refreshKey],
    { enabled: canRead },
  )
  // One reload at a time: during an outage the resilience read is slow and alert events come at
  // every poll, so a reload that superseded the one in flight would never show a result.
  const reloading = useRef({ running: false, again: false })
  const refetchAll = useCallback(async () => {
    const state = reloading.current
    if (state.running) {
      state.again = true
      return
    }
    state.running = true
    try {
      do {
        state.again = false
        await Promise.all([res.refetch(), alerts.refetch()])
      } while (state.again)
    } finally {
      state.running = false
    }
  }, [res, alerts])
  useWsTopic(
    'alerts',
    useCallback((message) => {
      if (ALERT_KINDS.includes(message?.data?.kind) || message?.data?.kind === 'ddns_replay') refetchAll()
    }, [refetchAll]),
  )
  const flow = usePlanFlow({ onApplied: refetchAll })
  const { nameOf } = useNodeNames()
  const [dialog, setDialog] = useState(null)
  const [replayOpen, setReplayOpen] = useState(false)

  const data = res.data
  const zones = useMemo(() => data?.zones || [], [data])
  const offline = data?.offline || []
  const byZone = useMemo(() => alertsByZone(alerts.data || []), [alerts.data])
  const outage = outageSummary(zones, byZone.outage)
  const preparable = zones.filter(isPreparable)
  const prepared = zones.filter(isPrepared)

  if (!canRead) {
    return <p className="text-sm text-text-secondary" data-testid="ddns-failover-denied">{t('ddnsFailover.denied')}</p>
  }
  if (res.loading && !data) return <LoadingSpinner size="sm" />
  if (res.error && !data) return <SectionError error={res.error} onRetry={res.refetch} />

  const prepare = (list) => flow.build(() => api.ddnsFailover.preparePlan(list ? list.map(zoneKey) : undefined))

  return (
    <div className="space-y-4" data-testid="ddns-failover">
      <OutageBanner outage={outage} windowOpen={data?.outage} nameOf={nameOf} canPlan={canPlan} onPromote={(list) => setDialog({ kind: 'failover', zones: list })} />
      <StaleBanner zones={zones} stale={byZone.stale} nameOf={nameOf} />
      {offline.length > 0 && (
        <div role="status" className="rounded-lg border status-warning-bg status-warning-border px-3 py-2 text-xs status-warning-text" data-testid="ddns-offline">
          {t('ddnsFailover.offline', { nodes: offline.map(nameOf).join(', ') })}
        </div>
      )}
      <ZonesTable
        zones={zones}
        byZone={byZone}
        offline={offline}
        nameOf={nameOf}
        selectedZone={selectedZone}
        canPlan={canPlan}
        busy={flow.building}
        onPrepare={(z) => prepare([z])}
        onRole={(kind, z) => setDialog({ kind, zones: [z] })}
        actions={
          canPlan && (
            <div className="flex flex-wrap gap-2">
              <Button size="sm" variant="secondary" onClick={() => prepare(null)} disabled={!preparable.length || offline.length > 0} loading={flow.building} data-testid="ddns-prepare-all">
                <ShieldCheck size={14} />
                {t('ddnsFailover.prepareAll', { count: preparable.length })}
              </Button>
              <Button size="sm" variant="secondary" onClick={() => setDialog({ kind: 'switchover', zones: prepared })} disabled={!prepared.length || outage.items.length > 0} data-testid="ddns-switchover-all">
                <Swap size={14} />
                {t('ddnsFailover.switchoverAll')}
              </Button>
            </div>
          )
        }
      />
      <ReplayCard replay={data?.replay} canReplay={canReplay} onOpen={() => setReplayOpen(true)} />
      <D2Lists d2={data?.d2 || []} nameOf={nameOf} />
      {dialog && <RoleDialog dialog={dialog} zones={zones} offline={offline} nameOf={nameOf} flow={flow} onClose={() => setDialog(null)} />}
      {replayOpen && <ReplayDialog replay={data?.replay} flow={flow} onClose={() => setReplayOpen(false)} />}
      {flow.modal}
    </div>
  )
}

function OutageBanner({ outage, windowOpen, nameOf, canPlan, onPromote }) {
  const { t } = useTranslation('dhcp')
  if (!outage.items.length && !windowOpen) return null
  const since = outage.since || windowOpen?.since
  return (
    <div role="alert" className="flex flex-col gap-2 rounded-lg border status-danger-bg status-danger-border px-3 py-2 text-xs status-danger-text" data-testid="ddns-outage-banner">
      <div className="flex items-start gap-2">
        <WarningOctagon size={16} weight="fill" className="shrink-0 mt-0.5" />
        <div className="flex-1 min-w-0 space-y-1">
          <p className="font-semibold">{t('ddnsFailover.outage.title', { since: formatDate(since), ago: formatRelativeTime(since) })}</p>
          {outage.items.map(({ zone, alert }) => (
            <p key={zoneKey(zone)} data-testid="ddns-outage-zone" data-zone={zoneKey(zone)}>
              {t(`ddnsFailover.outage.cause.${alert.details?.cause === 'peer_offline' ? 'peer_offline' : 'named_down'}`, { zone: zoneLabel(zone), node: nameOf(alert.node_id || zone.primary_node_id) })}
            </p>
          ))}
          {!outage.items.length && <p className="text-text-secondary">{t('ddnsFailover.outage.d2Only')}</p>}
          <p className="text-text-secondary">{outage.promotable.length ? t('ddnsFailover.outage.promoteHint') : t('ddnsFailover.outage.replayOnly')}</p>
        </div>
      </div>
      {canPlan && outage.promotable.length > 0 && (
        <div className="pl-6">
          <Button variant="danger" size="xs" onClick={() => onPromote(outage.promotable)} data-testid="ddns-promote">
            <ArrowUp size={12} />
            {t('ddnsFailover.outage.promote', { count: outage.promotable.length })}
          </Button>
        </div>
      )}
    </div>
  )
}

function StaleBanner({ zones, stale, nameOf }) {
  const { t } = useTranslation('dhcp')
  const items = zones.filter((z) => (z.stale || []).length || stale.has(zoneKey(z)))
  if (!items.length) return null
  return (
    <div role="alert" className="rounded-lg border status-danger-bg status-danger-border px-3 py-2 text-xs status-danger-text space-y-1" data-testid="ddns-stale-banner">
      <p className="font-semibold">{t('ddnsFailover.stale.title')}</p>
      {items.map((z) => {
        const alert = stale.get(zoneKey(z))
        const nodes = [...new Set([...(z.stale || []), ...(alert?.node_id ? [alert.node_id] : [])])]
        const demotable = alert?.details?.demotable !== false
        return (
          <p key={zoneKey(z)} data-testid="ddns-stale-zone" data-zone={zoneKey(z)}>
            {t('ddnsFailover.stale.zone', { zone: zoneLabel(z), nodes: nodes.map(nameOf).join(', '), primary: nameOf(z.primary_node_id), epoch: z.epoch })}{' '}
            <span className="text-text-secondary">{demotable ? t('ddnsFailover.stale.auto') : t('ddnsFailover.stale.conflict')}</span>
          </p>
        )
      })}
    </div>
  )
}

function ZonesTable({ zones, byZone, offline, nameOf, selectedZone, canPlan, busy, onPrepare, onRole, actions }) {
  const { t } = useTranslation(['dhcp', 'common'])
  const msg = useMessage()
  useEffect(() => {
    if (!selectedZone) return
    document.querySelector(`[data-zone-row="${CSS.escape(selectedZone)}"]`)?.scrollIntoView?.({ block: 'center' })
  }, [selectedZone, zones.length])
  const rows = zones.map((z) => ({ ...z, key: zoneKey(z), state: zoneState(z, byZone) }))
  const columns = [
    {
      key: 'zone', label: t('ddnsFailover.cols.zone'), mono: true, sortable: true,
      render: (z) => (
        <span data-zone-row={z.key}>
          {z.zone}
          {z.view !== '_default' && <span className="text-2xs text-text-tertiary">{' '}{z.view}</span>}
        </span>
      ),
    },
    { key: 'primary_node_id', label: t('ddnsFailover.cols.primary'), render: (z) => (z.primary_node_id ? nameOf(z.primary_node_id) : '-') },
    { key: 'epoch', label: t('ddnsFailover.cols.epoch'), align: 'right', render: (z) => (z.epoch ? z.epoch : '-') },
    { key: 'since', label: t('ddnsFailover.cols.since'), render: (z) => (z.since ? <span className="whitespace-nowrap" title={formatDate(z.since)}>{formatRelativeTime(z.since)}</span> : '-') },
    {
      key: 'copies', label: t('ddnsFailover.cols.copies'),
      render: (z) => (z.copies || []).map((id) => (
        <Badge key={id} size="sm" variant={offline.includes(id) ? 'danger' : 'gray'} className="mr-1">{nameOf(id)}</Badge>
      )),
    },
    {
      key: 'state', label: t('ddnsFailover.cols.state'),
      render: (z) => (
        <div className="space-y-1 max-w-md">
          <Badge size="sm" variant={STATE_TONE[z.state]} data-testid="ddns-zone-state" data-state={z.state}>{t(`ddnsFailover.state.${z.state}`)}</Badge>
          {z.state !== 'ready' && (z.blockers || []).map((b, i) => {
            const action = blockerAction(b, z)
            return (
              <p key={`${b.key}-${i}`} className="text-2xs text-text-secondary whitespace-normal" data-testid="ddns-blocker" data-key={b.key}>
                {msg(b, b.key)}
                {action && (
                  <Link to={action.to} className="ml-1 text-accent-primary hover:underline" data-testid={`ddns-blocker-${action.label}`}>
                    {t(`ddnsFailover.blockerAction.${action.label}`)}
                  </Link>
                )}
              </p>
            )
          })}
          {z.prepared_at && <p className="text-2xs text-text-tertiary">{t('ddnsFailover.preparedAt', { when: formatRelativeTime(z.prepared_at) })}</p>}
        </div>
      ),
    },
    ...(canPlan
      ? [{
          key: 'actions', label: '', align: 'right',
          render: (z) => (
            <span className="inline-flex gap-1 whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
              {isPreparable(z) && (
                <Button size="xs" variant="secondary" onClick={() => onPrepare(z)} disabled={busy || offline.length > 0} data-testid="ddns-prepare">
                  {t('ddnsFailover.prepare')}
                </Button>
              )}
              {isPrepared(z) && z.state === 'outage' && (
                <Button size="xs" variant="danger" onClick={() => onRole('failover', z)} data-testid="ddns-row-promote">
                  {t('ddnsFailover.promote')}
                </Button>
              )}
              {isPrepared(z) && z.state === 'ready' && (
                <Button size="xs" variant="secondary" onClick={() => onRole('switchover', z)} data-testid="ddns-row-switchover">
                  {t('ddnsFailover.switchover')}
                </Button>
              )}
            </span>
          ),
        }]
      : []),
  ]
  return (
    <DataTable
      title={t('ddnsFailover.zonesTitle')}
      toolbar={actions}
      columns={columns}
      rows={rows}
      rowKey="key"
      selectedKey={selectedZone || undefined}
      clientSort
      emptyTitle={t('ddnsFailover.noZones')}
      emptyDescription={t('ddnsFailover.noZonesHint')}
      dense
      testId="ddns-zones"
    />
  )
}

function ReplayCard({ replay, canReplay, onOpen }) {
  const { t } = useTranslation('dhcp')
  if (!replay) return null
  const known = replayKnown(replay)
  const none = replay.source === 'none' || replay.source === 'default'
  const count = known ? replay.candidates : null
  return (
    <Card className="p-3 space-y-2" hover={false} data-testid="ddns-replay">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="ui-card-title text-sm font-semibold text-text-primary">{t('ddnsFailover.replay.title')}</h3>
        {(known || none) && <Badge size="sm" variant={replay.source === 'open' ? 'danger' : known ? 'warning' : 'gray'} data-testid="ddns-replay-source">{t(`ddnsFailover.replay.source.${known ? replay.source : 'none'}`)}</Badge>}
        {canReplay && (
          <Button size="xs" variant={count ? 'primary' : 'secondary'} className="ml-auto" onClick={onOpen} data-testid="ddns-replay-open">
            <ArrowsCounterClockwise size={12} />
            {t(count ? 'ddnsFailover.replay.open' : 'ddnsFailover.replay.manual')}
          </Button>
        )}
      </div>
      {known ? (
        <>
          <p className="text-xs text-text-secondary">{t('ddnsFailover.replay.help')}</p>
          <div className="flex flex-wrap gap-4">
            <Stat label={t('ddnsFailover.replay.from')} value={replay.from ? formatDate(replay.from) : '-'} />
            <Stat label={t('ddnsFailover.replay.to')} value={replay.to ? formatDate(replay.to) : '-'} />
            <Stat label={t('ddnsFailover.replay.candidates')} value={count ?? '-'} tone={count ? 'warning' : undefined} />
          </div>
        </>
      ) : none && (
        <p className="text-xs text-text-secondary" data-testid="ddns-replay-none">{t('ddnsFailover.replay.noOutage')}</p>
      )}
      {(replay.notes || []).map((n, i) => (
        <p key={i} className="text-2xs status-warning-text" data-testid="ddns-replay-note">{n}</p>
      ))}
    </Card>
  )
}

function D2Lists({ d2, nameOf }) {
  const { t } = useTranslation('dhcp')
  return (
    <section className="space-y-2">
      <h3 className="ui-card-title text-sm font-semibold text-text-primary">{t('ddnsFailover.d2.title')}</h3>
      <p className="text-xs text-text-secondary">{t('ddnsFailover.d2.help')}</p>
      {!d2.length && <p className="text-xs text-text-tertiary">{t('ddnsFailover.d2.none')}</p>}
      <div className="grid gap-4 lg:grid-cols-2">
        {d2.map((node) => (
          <Card key={node.node_id} className="p-3 space-y-2" hover={false} data-testid="ddns-d2-node">
            <span className="text-sm font-semibold text-text-primary">{nameOf(node.node_id)}</span>
            <table className="w-full text-xs">
              <thead>
                <tr className="text-2xs uppercase tracking-wider text-text-tertiary">
                  <th className="text-left py-1">{t('ddnsFailover.d2.domain')}</th>
                  <th className="text-left py-1">{t('ddnsFailover.d2.servers')}</th>
                </tr>
              </thead>
              <tbody>
                {node.domains.map((d) => (
                  <tr key={`${d.direction}/${d.name}`} className="border-t border-border-op30 align-top">
                    <td className="py-1 font-mono">
                      {d.name}{' '}
                      <span className="text-2xs text-text-tertiary">{t(`ddnsFailover.d2.${d.direction === 'reverse' ? 'reverse' : 'forward'}`)}</span>
                    </td>
                    <td className="py-1">
                      <ol className="space-y-0.5" data-testid="ddns-d2-servers">
                        {d.servers.map((s, i) => (
                          <li key={`${s.address}:${s.port}:${i}`} className="flex items-center gap-1.5">
                            <span className="text-2xs text-text-tertiary w-3">{i + 1}.</span>
                            <span className="font-mono">{s.address}{s.port && s.port !== 53 ? `:${s.port}` : ''}</span>
                            {s.node_id && <span className="text-text-secondary">{nameOf(s.node_id)}</span>}
                            {s.role && <Badge size="sm" variant={s.role === 'primary' ? 'primary' : 'gray'} data-testid="ddns-d2-role">{t(`ddnsFailover.d2.role.${s.role}`)}</Badge>}
                          </li>
                        ))}
                      </ol>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        ))}
      </div>
    </section>
  )
}

// Promote (failover) or switchover: the target and which prepared zones move.
function RoleDialog({ dialog, zones, offline, nameOf, flow, onClose }) {
  const { t } = useTranslation(['dhcp', 'common'])
  const failover = dialog.kind === 'failover'
  // A promotion only takes zones whose primary is down: the plan refuses the others.
  const all = failover ? dialog.zones : zones.filter(isPrepared)
  const [scope, setScope] = useState(dialog.zones.length === 1 ? 'one' : 'listed')
  const chosen = scope === 'one' || scope === 'listed' ? dialog.zones : all
  const targets = targetNodes(chosen, offline)
  const [to, setTo] = useState(failover ? '' : targets[0] || '')
  const [error, setError] = useState(null)
  const submit = async () => {
    setError(null)
    const keys = chosen.map(zoneKey)
    try {
      const plan = await flow.build(
        () => (failover ? api.ddnsFailover.failoverPlan(to || undefined, keys) : api.ddnsFailover.switchoverPlan(to || undefined, keys)),
        { rethrow: true },
      )
      if (plan) onClose()
    } catch (err) {
      setError(errorMessage(err))
    }
  }
  const scopes = [
    ...(dialog.zones.length === 1 ? [{ value: 'one', label: t('ddnsFailover.role.scopeOne', { zone: zoneLabel(dialog.zones[0]) }) }] : [{ value: 'listed', label: t('ddnsFailover.role.scopeListed', { count: dialog.zones.length }) }]),
    ...(all.length > dialog.zones.length ? [{ value: 'all', label: t('ddnsFailover.role.scopeAll', { count: all.length }) }] : []),
  ]
  return (
    <FormModal
      open
      onClose={onClose}
      title={t(failover ? 'ddnsFailover.role.failoverTitle' : 'ddnsFailover.role.switchoverTitle')}
      onSubmit={submit}
      submitLabel={t('form.preview')}
      loading={flow.building}
      disabled={!targets.length}
      variant={failover ? 'danger' : 'primary'}
      size="sm"
      testId="ddns-role-form"
    >
      <p className="text-xs text-text-secondary">{t(failover ? 'ddnsFailover.role.failoverHelp' : 'ddnsFailover.role.switchoverHelp')}</p>
      {scopes.length > 1 ? (
        <NativeSelect label={t('ddnsFailover.role.zones')} value={scope} onChange={setScope} options={scopes} testId="ddns-role-scope" />
      ) : (
        <p className="text-xs font-mono text-text-primary" data-testid="ddns-role-zones">{chosen.map(zoneLabel).join(', ')}</p>
      )}
      {targets.length ? (
        <NativeSelect
          label={t('ddnsFailover.role.target')}
          value={to}
          onChange={setTo}
          options={[...(failover ? [{ value: '', label: t('ddnsFailover.role.auto') }] : []), ...targets.map((id) => ({ value: id, label: nameOf(id) }))]}
          testId="ddns-role-target"
        />
      ) : (
        <p className="text-xs status-warning-text">{t('ddnsFailover.role.noTarget')}</p>
      )}
      {failover && <p className="text-2xs text-text-tertiary">{t('ddnsFailover.role.failoverRisk')}</p>}
      {error && <p className="text-xs status-danger-text" data-testid="ddns-role-error">{error}</p>}
    </FormModal>
  )
}

function ReplayDialog({ replay, flow, onClose }) {
  const { t } = useTranslation(['dhcp', 'common'])
  // A manual window (no outage, or nothing counted in it) starts empty: the start is required.
  const manual = !replay?.candidates || !replayKnown(replay)
  const [form, setForm] = useState(manual ? { from: '', to: '', family: '', limit: '' } : { from: toLocalInput(replay.from), to: replay.source === 'open' ? '' : toLocalInput(replay.to), family: '', limit: '' })
  const [error, setError] = useState(null)
  const set = (k) => (v) => setForm((f) => ({ ...f, [k]: v }))
  const submit = async () => {
    const { body, error: bad } = replayBody(form, { requireFrom: manual })
    if (bad) {
      setError(t(bad))
      return
    }
    setError(null)
    try {
      const plan = await flow.build(() => api.ddnsFailover.replayPlan(body), { rethrow: true })
      if (plan) onClose()
    } catch (err) {
      setError(errorMessage(err))
    }
  }
  return (
    <FormModal open onClose={onClose} title={t('ddnsFailover.replay.dialogTitle')} onSubmit={submit} submitLabel={t('form.preview')} loading={flow.building} size="sm" testId="ddns-replay-form">
      <p className="text-xs text-text-secondary" data-testid="ddns-replay-dialog-help">{manual ? t('ddnsFailover.replay.manualHelp') : t('ddnsFailover.replay.dialogHelp', { count: replay.candidates })}</p>
      <Input type="datetime-local" label={t('ddnsFailover.replay.from')} value={form.from} onChange={(e) => set('from')(e.target.value)} data-testid="ddns-replay-from" />
      <Input type="datetime-local" label={t('ddnsFailover.replay.to')} value={form.to} onChange={(e) => set('to')(e.target.value)} helperText={t('ddnsFailover.replay.toHint')} data-testid="ddns-replay-to" />
      <NativeSelect
        label={t('ddnsFailover.replay.family')}
        value={form.family}
        onChange={set('family')}
        options={[{ value: '', label: t('ddnsFailover.replay.allFamilies') }, { value: 'v4', label: 'DHCPv4' }, { value: 'v6', label: 'DHCPv6' }]}
        testId="ddns-replay-family"
      />
      <Input type="number" min={1} label={t('ddnsFailover.replay.limit')} value={form.limit} onChange={(e) => set('limit')(e.target.value)} helperText={t('ddnsFailover.replay.limitHint')} data-testid="ddns-replay-limit" />
      {error && <p className="text-xs status-danger-text" data-testid="ddns-replay-error">{error}</p>}
    </FormModal>
  )
}
