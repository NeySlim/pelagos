// SPDX-License-Identifier: Apache-2.0
// Dashboard tiles, each fed by GET /dashboard/summary (plus open alerts for the
// inconsistencies tile). The header is the drag handle while editing the layout.
import { useTranslation } from 'react-i18next'
import { useMessage } from '../../i18n/message'
import { Link } from 'react-router-dom'
import {
  HardDrives, ArrowsLeftRight, WarningDiamond, Globe, ChartBar, Lightning, DotsSixVertical, ArrowRight, Crown,
} from '@phosphor-icons/react'
import { StatusBadge } from '../../components/StatusBadge'
import { Badge } from '../../components/Badge'
import { UtilizationBar } from '../../components/UtilizationBar'
import { EmptyState } from '../../components/EmptyState'
import { cn, formatRelativeTime } from '../../lib/utils'
import { CountUp, MiniHistogram, StatusDot } from '../../components/motion'
import { dhcpFamily, poolThresholds, formatErrorRate } from './summary'

export function TileFrame({ id, icon: Icon, title, link, linkLabel, editing, status, children, bodyClassName, className }) {
  return (
    <div className={cn('h-full flex flex-col card-soft overflow-hidden dash-tile', className)} data-testid={`tile-${id}`}>
      <div className={cn('tile-handle flex items-center gap-2 px-3.5 py-2.5 border-b border-border-op30 section-header-gradient dash-tile-head', editing && 'cursor-move select-none')}>
        {editing && <DotsSixVertical size={14} className="text-text-tertiary" />}
        {Icon && <Icon size={16} className="text-accent-primary shrink-0" weight="duotone" />}
        <h3 className="ui-card-title text-sm font-semibold text-text-primary truncate">{title}</h3>
        {status}
        {link && !editing && (
          <Link to={link} className="ml-auto inline-flex items-center gap-1 text-2xs text-text-tertiary hover:text-accent-primary">
            {linkLabel}
            <ArrowRight size={11} />
          </Link>
        )}
      </div>
      <div className={cn('flex-1 min-h-0 overflow-auto p-3', bodyClassName)}>{children}</div>
    </div>
  )
}

function Empty({ icon, title }) {
  return (
    <div className="h-full flex items-center justify-center">
      <EmptyState icon={icon} title={title} />
    </div>
  )
}

export function NodesTile({ summary, editing, live }) {
  const { t } = useTranslation(['dashboard', 'common'])
  const nodes = summary?.nodes || []
  const offline = nodes.filter((n) => n.status !== 'online').length
  return (
    <TileFrame
      id="nodes"
      icon={HardDrives}
      title={t('tiles.nodes.title')}
      link="/nodes"
      linkLabel={t('viewAll')}
      editing={editing}
      status={<StatusBadge status={offline ? 'degraded' : 'online'} label={t('tiles.nodes.online', { online: nodes.length - offline, total: nodes.length })} />}
    >
      {nodes.length === 0 ? (
        <Empty icon={HardDrives} title={t('tiles.nodes.empty')} />
      ) : (
        <ul className="space-y-1.5">
          {nodes.map((n) => {
            const series = live?.dns.seriesByNode?.[n.peer.id] || []
            const tone = n.status === 'online' ? (n.error ? 'warning' : 'success') : 'danger'
            return (
              <li key={n.peer.id} className="dash-row items-start text-xs" data-testid="tile-node">
                <StatusDot tone={tone} pulse={tone !== 'success'} className="mt-1.5" label={t(`common:status.${n.status || 'unknown'}`)} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-1.5">
                    <span className="dash-node-name text-text-primary">{n.peer.name}</span>
                    {n.is_self && (
                      <Badge variant="primary" size="sm">
                        {t('tiles.nodes.self')}
                      </Badge>
                    )}
                  </div>
                  <div className="text-2xs text-text-tertiary font-mono truncate">
                    {t('tiles.nodes.meta', { version: n.version || '?', config: n.config_version ?? '?', audit: n.audit_count ?? '?' })}
                  </div>
                  {n.error && <div className="text-2xs status-danger-text">{n.error}</div>}
                </div>
                <div className="flex flex-col items-end gap-1 shrink-0">
                  <span className="text-2xs text-text-tertiary whitespace-nowrap">{n.last_seen ? formatRelativeTime(n.last_seen, t) : '-'}</span>
                  {series.length > 1 && <MiniHistogram data={series.slice(-24).map((p) => p.v)} tone="primary" height={14} />}
                </div>
              </li>
            )
          })}
        </ul>
      )}
    </TileFrame>
  )
}

export function HaTile({ summary, editing, nameOf }) {
  const family = dhcpFamily(summary)
  const { t } = useTranslation(['dashboard', 'common'])
  const ha = (summary?.ha || []).filter((h) => h.enabled !== false)
  const bad = ha.filter((h) => !['hot-standby', 'load-balancing', 'backup', 'passive-backup'].includes(h.state) || h.partner?.in_touch === false)
  return (
    <TileFrame
      id="ha"
      icon={ArrowsLeftRight}
      title={t('tiles.ha.title')}
      link={`/dhcp/${family}/ha`}
      linkLabel={t('viewAll')}
      editing={editing}
      status={ha.length > 0 && <StatusBadge status={bad.length ? 'degraded' : 'ok'} />}
    >
      {ha.length === 0 ? (
        <Empty icon={ArrowsLeftRight} title={t('tiles.ha.empty')} />
      ) : (
        <table className="w-full text-xs">
          <thead>
            <tr className="text-2xs uppercase tracking-wider text-text-tertiary">
              <th className="text-left font-semibold pb-1">{t('tiles.ha.server')}</th>
              <th className="text-left font-semibold pb-1">{t('tiles.ha.state')}</th>
              <th className="text-left font-semibold pb-1">{t('tiles.ha.partner')}</th>
              <th className="text-right font-semibold pb-1">{t('tiles.ha.unsent')}</th>
            </tr>
          </thead>
          <tbody>
            {ha.map((h) => (
              <tr key={`${h.node_id}/${h.family}`} className="border-t border-border-op30" data-testid="tile-ha-row">
                <td className="py-1 pr-2">
                  <span className="inline-flex items-center gap-1">
                    {h.role === 'primary' && <Crown size={11} className="text-accent-warning" />}
                    <span className="font-medium text-text-primary">{h.server_name || nameOf(h.node_id)}</span>
                    <Badge variant={h.family === 'v6' ? 'violet' : 'secondary'} size="sm">
                      {h.family === 'v6' ? 'DHCPv6' : 'DHCPv4'}
                    </Badge>
                  </span>
                </td>
                <td className="py-1 pr-2">
                  <StatusBadge status={h.state || 'unknown'} />
                </td>
                <td className="py-1 pr-2">
                  {h.partner ? (
                    <span className="inline-flex items-center gap-1">
                      <StatusBadge status={h.partner.state || 'unknown'} dot={false} />
                      {h.partner.in_touch === false && <span className="text-2xs status-danger-text">{t('tiles.ha.notInTouch')}</span>}
                    </span>
                  ) : (
                    '-'
                  )}
                </td>
                <td className="py-1 text-right font-mono">{h.unsent_update_count ?? '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </TileFrame>
  )
}

const SEVERITIES = ['critical', 'warning', 'info']
const SEVERITY_TONE = { critical: 'danger', warning: 'warning', info: 'neutral' }

export function InconsistenciesTile({ summary, alerts, editing }) {
  const { t } = useTranslation(['dashboard', 'common'])
  const msg = useMessage()
  const counts = summary?.alerts || { open: 0, critical: 0, warning: 0, info: 0 }
  return (
    <TileFrame
      id="inconsistencies"
      icon={WarningDiamond}
      title={t('tiles.inconsistencies.title')}
      link="/alerts"
      linkLabel={t('viewAll')}
      editing={editing}
      status={<StatusBadge status={counts.critical ? 'critical' : counts.warning ? 'warning' : 'ok'} label={t('tiles.inconsistencies.open', { count: counts.open })} />}
    >
      <div className="grid grid-cols-3 gap-2 mb-3">
        {SEVERITIES.map((s) => (
          <Link key={s} to={`/alerts?severity=${s}`} className="dash-row flex-col items-start gap-0.5 hover:bg-tertiary-op40" data-testid={`tile-alerts-${s}`}>
            <span className="dash-label inline-flex items-center gap-1.5">
              <StatusDot tone={SEVERITY_TONE[s]} pulse={s === 'critical' && Boolean(counts[s])} />
              {t(`common:status.${s}`)}
            </span>
            <span className={cn('text-lg font-semibold tabular-nums', counts[s] ? (s === 'critical' ? 'status-danger-text' : s === 'warning' ? 'status-warning-text' : 'text-accent-primary') : 'text-text-tertiary')}>
              <CountUp value={counts[s] ?? 0} />
            </span>
          </Link>
        ))}
      </div>
      {alerts === null ? null : alerts.length === 0 ? (
        <p className="text-xs text-text-tertiary italic">{t('tiles.inconsistencies.none')}</p>
      ) : (
        <ul className="space-y-1.5">
          {alerts.map((a) => (
            <li key={a.id} className="flex items-start gap-2 text-xs" data-testid="tile-alert">
              <StatusBadge status={a.severity} />
              <span className="flex-1 min-w-0 text-text-primary truncate" title={msg(a.title_message, a.title)}>
                {msg(a.title_message, a.title)}
              </span>
              <span className="text-2xs text-text-tertiary font-mono whitespace-nowrap">{t(`kinds.${a.kind}`, { defaultValue: a.kind })}</span>
            </li>
          ))}
        </ul>
      )}
    </TileFrame>
  )
}

export function ZoneSyncTile({ summary, editing, nameOf }) {
  const { t } = useTranslation(['dashboard', 'common'])
  const zones = summary?.zones || []
  const divergent = zones.filter((z) => z.divergent)
  const sorted = [...divergent, ...zones.filter((z) => !z.divergent)]
  return (
    <TileFrame
      id="zones"
      icon={Globe}
      title={t('tiles.zones.title')}
      link="/dns/zones"
      linkLabel={t('viewAll')}
      editing={editing}
      status={zones.length > 0 && <StatusBadge status={divergent.length ? 'divergent' : 'in-sync'} label={t('tiles.zones.summary', { divergent: divergent.length, total: zones.length })} />}
    >
      {zones.length === 0 ? (
        <Empty icon={Globe} title={t('tiles.zones.empty')} />
      ) : (
        <ul className="space-y-1.5">
          {sorted.map((z) => {
            const values = Object.values(z.serials || {}).filter((v) => v !== null && v !== undefined)
            const max = values.length ? Math.max(...values) : null
            return (
              <li key={`${z.view}/${z.zone}`} className="dash-row text-xs py-1" data-testid="tile-zone">
                <StatusDot tone={z.divergent ? 'warning' : 'success'} pulse={z.divergent} label={t(`common:status.${z.divergent ? 'divergent' : 'in-sync'}`, { defaultValue: z.divergent ? 'divergent' : 'in sync' })} />
                <Link to={`/dns/zones/${encodeURIComponent(z.zone.replace(/\.$/, ''))}${z.view && z.view !== '_default' ? `?view=${encodeURIComponent(z.view)}` : ''}`} className="font-mono text-text-primary hover:text-accent-primary truncate flex-1 min-w-0" title={z.zone}>
                  {z.zone}
                </Link>
                <span className="flex gap-1 flex-wrap justify-end">
                  {Object.entries(z.serials || {}).map(([id, serial]) => (
                    <span
                      key={id}
                      className={cn('font-mono text-2xs rounded px-1 border', serial !== max ? 'status-warning-bg status-warning-text border-transparent' : 'border-border-op50 text-text-secondary')}
                      title={nameOf(id)}
                    >
                      {nameOf(id)} {serial ?? '?'}
                    </span>
                  ))}
                </span>
              </li>
            )
          })}
        </ul>
      )}
    </TileFrame>
  )
}

export function PoolsTile({ summary, editing, nameOf, thresholds }) {
  const { t } = useTranslation(['dashboard', 'common'])
  const pools = [...(summary?.pools || [])].sort((a, b) => b.percent - a.percent)
  const { warn, full } = poolThresholds(summary, thresholds)
  const family = dhcpFamily(summary)
  const hot = pools.filter((p) => p.percent >= warn).length
  return (
    <TileFrame
      id="pools"
      icon={ChartBar}
      title={t('tiles.pools.title')}
      link={`/dhcp/${family}/subnets`}
      linkLabel={t('viewAll')}
      editing={editing}
      status={pools.length > 0 && <StatusBadge status={hot ? 'warning' : 'ok'} label={t('tiles.pools.hot', { count: hot })} />}
    >
      {pools.length === 0 ? (
        <Empty icon={ChartBar} title={t('tiles.pools.empty')} />
      ) : (
        <ul className="space-y-2">
          {pools.map((p) => (
            <li key={`${p.node_id}/${p.engine}/${p.subnet_id}/${p.pool}`} className="text-xs" data-testid="tile-pool">
              <div className="flex items-center gap-2 mb-0.5">
                <Badge variant={p.engine === 'kea6' ? 'violet' : 'secondary'} size="sm">
                  {p.engine === 'kea6' ? 'v6' : 'v4'}
                </Badge>
                <span className="font-mono text-text-primary truncate" title={p.pool}>
                  {p.pool}
                </span>
                <span className="ml-auto text-2xs text-text-tertiary font-mono whitespace-nowrap">
                  {p.subnet} · {nameOf(p.node_id)}
                </span>
              </div>
              <UtilizationBar assigned={p.assigned} total={p.total} percent={p.percent} warn={warn} full={full} size="sm" label={`${p.pool} (${p.subnet})`} />
            </li>
          ))}
        </ul>
      )}
    </TileFrame>
  )
}

const D2_COUNTERS = ['update-success', 'update-error', 'update-timeout', 'ncr-error']

export function D2Tile({ summary, editing, nameOf }) {
  const family = dhcpFamily(summary)
  const { t, i18n } = useTranslation(['dashboard', 'common'])
  const d2 = summary?.d2 || []
  const errors = (s) => (s.totals?.['update-error'] || 0) + (s.totals?.['update-timeout'] || 0) + (s.totals?.['ncr-error'] || 0)
  const total = d2.reduce((acc, s) => acc + errors(s), 0)
  return (
    <TileFrame
      id="d2"
      icon={Lightning}
      title={t('tiles.d2.title')}
      link={`/dhcp/${family}/ddns`}
      linkLabel={t('viewAll')}
      editing={editing}
      status={d2.length > 0 && <StatusBadge status={total ? 'warning' : 'ok'} label={t('tiles.d2.errors', { count: total })} />}
    >
      {d2.length === 0 ? (
        <Empty icon={Lightning} title={t('tiles.d2.empty')} />
      ) : (
        <div className="grid gap-3" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(14rem, 1fr))' }}>
          {d2.map((s) => {
            const sent = s.totals?.['update-sent'] || 0
            const rate = formatErrorRate(errors(s), sent, i18n.language)
            return (
              <div key={s.node_id} className="dash-subpanel" data-testid="tile-d2-node">
                <div className="flex items-center gap-2 mb-1.5">
                  <StatusDot tone={errors(s) ? 'warning' : 'success'} />
                  <span className="dash-node-name text-text-primary">{nameOf(s.node_id)}</span>
                  <span className={cn('ml-auto text-2xs font-mono', errors(s) ? 'status-warning-text' : 'text-text-tertiary')}>{t('tiles.d2.rate', { rate })}</span>
                </div>
                <dl className="grid grid-cols-2 gap-x-3 gap-y-0.5 text-2xs">
                  {D2_COUNTERS.map((c) => (
                    <div key={c} className="flex justify-between gap-2">
                      <dt className="text-text-tertiary">{t(`tiles.d2.counters.${c}`)}</dt>
                      <dd className={cn('font-mono', c !== 'update-success' && s.totals?.[c] ? 'status-warning-text' : 'text-text-primary')}>{s.totals?.[c] ?? 0}</dd>
                    </div>
                  ))}
                </dl>
                {Object.keys(s.per_key || {}).length > 0 && (
                  <div className="mt-1.5 pt-1.5 border-t border-border-op30 space-y-0.5">
                    {Object.entries(s.per_key).map(([key, v]) => (
                      <div key={key} className="flex justify-between text-2xs font-mono">
                        <span className="text-text-secondary">{key}</span>
                        <span className={v['update-error'] || v['update-timeout'] ? 'status-warning-text' : 'text-text-tertiary'}>
                          {v['update-success'] ?? 0}/{v['update-sent'] ?? 0}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </TileFrame>
  )
}
