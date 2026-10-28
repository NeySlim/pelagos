// SPDX-License-Identifier: Apache-2.0
// DDNS tile: the failover state of the dynamic zones (ready, outage, stale primary, leases to
// replay), linked to DHCP > DDNS > Failover. Nothing when the user cannot read it.
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { useApi } from '../../hooks/useApi'
import { usePermission } from '../../hooks/usePermission'
import { api } from '../../services/api'
import { cn } from '../../lib/utils'
import { StatusDot } from '../../components/motion'
import { failoverPath, resilienceSummary } from '../dhcp/ddnsFailover'

export function DdnsFailoverLine() {
  const { t } = useTranslation('dashboard')
  const { hasPermission } = usePermission()
  const enabled = hasPermission('read:dhcp') && hasPermission('read:dns') && Boolean(api.ddnsFailover?.resilience)
  const res = useApi(() => api.ddnsFailover.resilience(), [], { enabled })
  if (!enabled || !res.data) return null
  const s = resilienceSummary(res.data)
  if (!s.total) return null
  const text = s.outage
    ? t('tiles.d2.failover.outage')
    : s.stale
      ? t('tiles.d2.failover.stale', { count: s.stale })
      : t('tiles.d2.failover.ready', { ready: s.ready, total: s.total })
  return (
    <Link to={failoverPath()} className="dash-subpanel mb-2 flex items-center gap-2 text-2xs hover:underline" data-testid="tile-d2-failover" data-tone={s.tone}>
      <StatusDot tone={s.tone === 'danger' ? 'danger' : s.tone === 'success' ? 'success' : 'warning'} />
      <span className="text-text-secondary">{t('tiles.d2.failover.label')}</span>
      <span className={cn('ml-auto font-mono', s.tone === 'danger' ? 'status-danger-text' : 'text-text-primary')}>{text}</span>
      {s.replay > 0 && <span className="status-warning-text">{t('tiles.d2.failover.replay', { count: s.replay })}</span>}
    </Link>
  )
}
