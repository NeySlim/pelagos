// SPDX-License-Identifier: Apache-2.0
// Resolver tile: the worst p95 and SERVFAIL share over the BIND nodes, the root and TLD probes,
// and the forwarder fallback when one is active (GET /dns/resolver/health, polled).
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { Heartbeat } from '@phosphor-icons/react'
import { StatusBadge } from '../../components/StatusBadge'
import { EmptyState } from '../../components/EmptyState'
import { StatusDot } from '../../components/motion'
import { useApi } from '../../hooks/useApi'
import { usePoll } from '../../hooks/usePoll'
import { usePermission } from '../../hooks/usePermission'
import { api } from '../../services/api'
import { cn, formatDate } from '../../lib/utils'
import { resolverSummary } from '../dns/resolverHealth'
import { TileFrame } from './tiles'

const POLL_MS = 60000
const STATUS = { danger: 'critical', warning: 'warning', success: 'ok', neutral: 'unknown' }
const TEXT = { danger: 'status-danger-text', warning: 'status-warning-text', success: 'text-text-primary', neutral: 'text-text-primary' }

export function ResolverTile({ editing }) {
  const { t, i18n } = useTranslation('dashboard')
  const { hasPermission } = usePermission()
  const enabled = hasPermission('read:dns') && Boolean(api.resolverHealth?.health)
  const health = useApi(() => api.resolverHealth.health(), [], { enabled })
  usePoll(health.refetch, POLL_MS, { enabled })
  const s = resolverSummary(health.data)
  const number = (v, digits = 0) => (v === null || v === undefined ? '-' : new Intl.NumberFormat(i18n.language, { maximumFractionDigits: digits }).format(v))
  return (
    <TileFrame
      id="resolver"
      icon={Heartbeat}
      title={t('tiles.resolver.title')}
      link="/dns/resolver"
      linkLabel={t('viewAll')}
      editing={editing}
      status={s && s.nodes > 0 && <StatusBadge status={STATUS[s.tone]} label={t(`tiles.resolver.state.${s.tone}`)} />}
    >
      {!enabled || (health.error && !health.data) ? (
        <div className="h-full flex items-center justify-center"><EmptyState icon={Heartbeat} title={t('tiles.resolver.unavailable')} /></div>
      ) : !s ? null : s.nodes === 0 ? (
        <div className="h-full flex items-center justify-center"><EmptyState icon={Heartbeat} title={t('tiles.resolver.empty')} /></div>
      ) : (
        <div className="space-y-2" data-testid="tile-resolver-body" data-tone={s.tone}>
          {s.fallback && (
            <Link to="/dns/resolver" className="dash-subpanel flex items-center gap-2 text-2xs hover:underline" data-testid="tile-resolver-fallback">
              <StatusDot tone="warning" pulse />
              <span className="text-text-secondary">{t('tiles.resolver.fallback')}</span>
              <span className="ml-auto font-mono text-text-primary truncate">{s.fallback.forwarders.slice(0, 2).join(', ')}</span>
              <span className="text-text-tertiary">{t('tiles.resolver.until', { when: formatDate(s.fallback.until) })}</span>
            </Link>
          )}
          <dl className="grid grid-cols-2 gap-2">
            <div className="dash-subpanel">
              <dt className="text-2xs text-text-tertiary">{t('tiles.resolver.p95')}</dt>
              <dd className={cn('text-lg font-semibold tabular-nums', TEXT[s.latencyTone])} data-testid="tile-resolver-p95">{t('tiles.resolver.ms', { value: number(s.p95) })}</dd>
            </div>
            <div className="dash-subpanel">
              <dt className="text-2xs text-text-tertiary">{t('tiles.resolver.servfail')}</dt>
              <dd className={cn('text-lg font-semibold tabular-nums', TEXT[s.servfailTone])} data-testid="tile-resolver-servfail">{t('tiles.resolver.percent', { value: number(s.servfail, 1) })}</dd>
            </div>
          </dl>
          <p className={cn('text-2xs', s.unhealthy ? 'status-danger-text' : 'text-text-tertiary')} data-testid="tile-resolver-probes">
            {s.unhealthy ? t('tiles.resolver.probesFailing', { count: s.unhealthy }) : t('tiles.resolver.probesOk', { measured: s.measured, total: s.nodes })}
            {s.unavailable > 0 && <span className="status-warning-text"> {t('tiles.resolver.silent', { count: s.unavailable })}</span>}
          </p>
          {!s.fallback && <p className="text-2xs text-text-tertiary">{t('tiles.resolver.direct')}</p>}
        </div>
      )}
    </TileFrame>
  )
}
