// SPDX-License-Identifier: Apache-2.0
// Design 13.4: while `kea_series_obsolete` is open, the DHCP pages name the nodes whose Kea series
// ISC no longer maintains and point admins at the read-only migration analysis.
import { useCallback, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { Info, X } from '@phosphor-icons/react'
import { usePermission } from '../../hooks/usePermission'
import { useApi } from '../../hooks/useApi'
import { useWsTopic } from '../../hooks/useWebSocket'
import { api } from '../../services/api'
import { useNodeNames } from './hooks'
import { KIND, obsoleteSeries } from './keaSeries'

const DISMISS_KEY = 'pelagos.keaSeriesBanner.dismissed'

function readDismissed() {
  try {
    return window.localStorage.getItem(DISMISS_KEY) || ''
  } catch {
    return ''
  }
}

export function KeaSeriesBanner() {
  const { t } = useTranslation('dhcp')
  const { hasPermission } = usePermission()
  const { nameOf } = useNodeNames()
  const alerts = useApi(() => api.alerts.list({ state: 'open', kind: KIND }), [])
  const refetch = alerts.refetch
  useWsTopic(
    'alerts',
    useCallback((message) => {
      if (message?.data?.kind === KIND) refetch()
    }, [refetch]),
  )
  const [dismissed, setDismissed] = useState(readDismissed)
  const rows = obsoleteSeries(alerts.data?.items)
  // Dismissal holds for this set of alerts: a new one shows the banner again.
  const key = rows.map((r) => r.id).sort().join(',')
  if (!rows.length || dismissed === key) return null
  const dismiss = () => {
    setDismissed(key)
    try {
      window.localStorage.setItem(DISMISS_KEY, key)
    } catch {
      /* the banner stays hidden for this page view only */
    }
  }
  return (
    <div role="status" className="flex items-start gap-2 rounded-lg border status-primary-bg status-primary-border px-3 py-2 text-xs status-primary-text" data-testid="kea-series-banner">
      <Info size={16} weight="fill" className="shrink-0 mt-0.5" />
      <div className="flex-1 min-w-0 space-y-1">
        {rows.map((r) => (
          <p key={r.id} data-testid="kea-series-banner-row">
            {r.eol
              ? t('keaSeries.rowSince', { node: nameOf(r.nodeId), series: r.series, date: r.eol })
              : t('keaSeries.row', { node: nameOf(r.nodeId), series: r.series })}
          </p>
        ))}
        {hasPermission('admin:install') && (
          <Link to="/install/kea-migration" className="text-accent-primary hover:underline" data-testid="kea-series-banner-link">
            {t('keaSeries.analyze')}
          </Link>
        )}
      </div>
      <button type="button" onClick={dismiss} aria-label={t('keaSeries.dismiss')} className="shrink-0 text-text-secondary hover:text-text-primary" data-testid="kea-series-banner-dismiss">
        <X size={14} />
      </button>
    </div>
  )
}

export default KeaSeriesBanner
