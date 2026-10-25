// SPDX-License-Identifier: Apache-2.0
// Badge for the domain's status enums (nodes, alerts, plans, jobs, HA, leases, zones).
// The label is translated from common:status.<value>; unknown values render as text.
import { useTranslation } from 'react-i18next'
import { Badge } from './Badge'
import { cn } from '../lib/utils'

const VARIANTS = {
  // NodeStatus
  online: 'success',
  offline: 'danger',
  unknown: 'gray',
  // Severity
  info: 'info',
  warning: 'warning',
  critical: 'danger',
  // AlertState
  open: 'warning',
  acked: 'info',
  resolved: 'success',
  // PlanState and JobState
  draft: 'gray',
  validated: 'info',
  applying: 'warning',
  applied: 'success',
  failed: 'danger',
  rolled_back: 'warning',
  rolling_back: 'warning',
  expired: 'gray',
  queued: 'gray',
  running: 'warning',
  done: 'success',
  // AuditResult
  ok: 'success',
  error: 'danger',
  denied: 'danger',
  // HA states (Kea)
  'hot-standby': 'success',
  'load-balancing': 'success',
  'partner-down': 'danger',
  'partner-in-maintenance': 'warning',
  'in-maintenance': 'warning',
  'communication-recovery': 'warning',
  waiting: 'warning',
  syncing: 'warning',
  ready: 'success',
  terminated: 'danger',
  'backup': 'info',
  'passive-backup': 'info',
  // LeaseState
  default: 'success',
  declined: 'danger',
  'expired-reclaimed': 'gray',
  released: 'gray',
  registered: 'info',
  // Zone kinds and misc
  primary: 'primary',
  secondary: 'violet',
  stub: 'gray',
  forward: 'gray',
  mirror: 'teal',
  divergent: 'warning',
  'in-sync': 'success',
  degraded: 'warning',
  enabled: 'success',
  disabled: 'gray',
  true: 'success',
  false: 'gray',
}

export function statusVariant(status) {
  return VARIANTS[String(status)] || 'default'
}

// `truncate` lets a narrow cell shorten the label with an ellipsis, the full text as title.
export function StatusBadge({ status, label, size = 'sm', dot = true, pulse, truncate = false, className, ...props }) {
  const { t } = useTranslation()
  const key = String(status ?? 'unknown')
  const text = label ?? t(`status.${key}`, { defaultValue: key.replace(/[-_]/g, ' ') })
  const variant = statusVariant(key)
  return (
    <Badge
      variant={variant}
      size={size}
      dot={dot}
      pulse={pulse ?? ['applying', 'rolling_back', 'running', 'syncing'].includes(key)}
      className={truncate ? cn('max-w-full min-w-0', className) : className}
      title={truncate && typeof text === 'string' ? text : undefined}
      {...props}
    >
      {truncate ? <span className="truncate min-w-0">{text}</span> : text}
    </Badge>
  )
}

export default StatusBadge
