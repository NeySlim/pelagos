// SPDX-License-Identifier: Apache-2.0
// Zone page badge of a dynamic zone under DDNS failover: "active primary on ns2 since ...
// (epoch 3)", linked to DHCP > DDNS > Failover. Nothing for a zone with no recorded primary.
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { Badge } from '../../components/Badge'
import { useApi } from '../../hooks/useApi'
import { usePermission } from '../../hooks/usePermission'
import { formatDate } from '../../lib/utils'
import { api } from '../../services/api'
import { failoverPath, zoneKey, zoneResilience } from '../dhcp/ddnsFailover'
import { useNodeNames } from './helpers'

export function FailoverBadge({ zone }) {
  const { t } = useTranslation('dns')
  const { hasPermission } = usePermission()
  const { nameOf } = useNodeNames()
  const enabled = Boolean(zone?.dynamic) && hasPermission('read:dhcp') && hasPermission('read:dns') && Boolean(api.ddnsFailover?.resilience)
  const res = useApi(() => api.ddnsFailover.resilience(), [zone?.name, zone?.view], { enabled })
  const entry = enabled ? zoneResilience(res.data, zone.name, zone.view) : null
  if (!entry || !entry.epoch || !entry.primary_node_id) return null
  const stale = (entry.stale || []).length > 0
  return (
    <Link to={failoverPath(zoneKey(entry))} data-testid="zone-failover-badge">
      <Badge size="sm" variant={stale ? 'danger' : 'info'}>
        {t('detail.failover', { node: nameOf(entry.primary_node_id), since: entry.since ? formatDate(entry.since) : '-', epoch: entry.epoch })}
      </Badge>
    </Link>
  )
}
