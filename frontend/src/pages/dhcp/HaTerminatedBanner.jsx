// SPDX-License-Identifier: Apache-2.0
// HA in `terminated`: Kea keeps serving but no longer copies leases, and only a restart of
// both servers recovers. The banner names the servers, the probable cause the collector found
// and Kea's own skew reading, and offers the repair plan (clocks checked, then each server's
// HA service restarted in turn).
import { useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { FirstAidKit, WarningOctagon } from '@phosphor-icons/react'
import { Button } from '../../components/Button'
import { useApi } from '../../hooks/useApi'
import { useWsTopic } from '../../hooks/useWebSocket'
import { useMessage } from '../../i18n/message'
import { api } from '../../services/api'
import { keaSkews, terminatedCauses, terminatedServers } from './haRepair'

export function HaTerminatedBanner({ family, items, canOperate, busy, onRepair }) {
  const { t } = useTranslation('dhcp')
  const msg = useMessage()
  const engine = family === 'v6' ? 'kea6' : 'kea4'
  const stuck = terminatedServers(items)
  const alerts = useApi(() => api.alerts.list({ kind: 'ha_terminated', engine }), [engine], { enabled: stuck.length > 0 })
  const refetch = alerts.refetch
  const watching = stuck.length > 0
  useWsTopic(
    'alerts',
    useCallback((message) => {
      if (watching && message?.data?.kind === 'ha_terminated') refetch()
    }, [refetch, watching]),
  )
  if (!stuck.length) return null
  const servers = [...new Set(stuck.map((h) => h.server_name).filter(Boolean))].join(', ')
  const causes = terminatedCauses(alerts.data?.items, engine)
  return (
    <div role="alert" className="flex flex-col gap-2 rounded-lg border status-danger-bg status-danger-border px-3 py-2 text-xs status-danger-text" data-testid="ha-terminated-banner">
      <div className="flex items-start gap-2">
        <WarningOctagon size={16} weight="fill" className="shrink-0 mt-0.5" />
        <div className="flex-1 min-w-0 space-y-1">
          <p className="font-semibold">{t('ha.terminated.title', { servers })}</p>
          <p className="text-text-secondary">{t('ha.terminated.explain')}</p>
          {causes.map((c) => (
            <p key={c.code} data-testid="ha-terminated-cause" data-cause={c.code}>
              {t('ha.terminated.cause', { cause: msg(c.message, c.title) })}
            </p>
          ))}
          {keaSkews(items).map((s) => (
            <p key={s.server} className="text-text-secondary" data-testid="ha-terminated-skew">
              {t('ha.terminated.keaSkew', { seconds: s.seconds, partner: s.partner || '-' })}
            </p>
          ))}
          <p className="text-text-secondary">{t('ha.terminated.steps')}</p>
        </div>
      </div>
      <div className="flex flex-wrap gap-2 pl-6">
        <Link to="/nodes" className="text-accent-primary hover:underline self-center">
          {t('ha.terminated.nodes')}
        </Link>
        {canOperate && (
          <Button variant="danger" size="xs" onClick={() => onRepair(servers)} disabled={busy} data-testid="ha-repair">
            <FirstAidKit size={12} />
            {t('ha.terminated.repair')}
          </Button>
        )}
      </div>
    </div>
  )
}
