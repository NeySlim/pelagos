// SPDX-License-Identifier: Apache-2.0
// Pool or subnet utilization: a bar colored by threshold (success, warning at
// `warn` percent, danger at `full` percent) with the assigned/total figures. The fill
// scales from the left (transform only); the threshold marks show under Instrument.
import { cn, formatPercent } from '../lib/utils'
import i18n from '../i18n'

export function utilizationLevel(percent, { warn = 80, full = 95 } = {}) {
  if (percent >= full) return 'danger'
  if (percent >= warn) return 'warning'
  return 'success'
}

export function UtilizationBar({
  assigned,
  total,
  percent,
  warn = 80,
  full = 95,
  showNumbers = true,
  size = 'md',
  label,
  className,
}) {
  const safeTotal = Number(total) || 0
  const safeAssigned = Number(assigned) || 0
  const pct = percent ?? (safeTotal > 0 ? (safeAssigned / safeTotal) * 100 : 0)
  const clamped = Math.max(0, Math.min(100, pct))
  const level = utilizationLevel(clamped, { warn, full })
  const colors = {
    success: 'status-success-bg-solid',
    warning: 'status-warning-bg-solid',
    danger: 'status-danger-bg-solid',
  }
  const heights = { sm: 'h-1', md: 'h-1.5', lg: 'h-2.5' }

  return (
    <div className={cn('min-w-[120px]', className)} data-testid="utilization-bar" data-level={level}>
      <div className={cn('ui-progress-track w-full rounded-full bg-tertiary-op80 overflow-hidden', heights[size] || heights.md)}>
        {[warn, full].filter((v) => v > 0 && v < 100).map((v) => (
          <span key={v} className={cn('ui-progress-tick', v === full && 'is-full')} style={{ left: `${v}%` }} aria-hidden="true" />
        ))}
        <div
          className={cn('ui-progress-fill h-full w-full rounded-full origin-left', colors[level])}
          style={{ transform: `scaleX(${clamped / 100})` }}
          role="progressbar"
          aria-label={label || i18n.t('common:common.utilization')}
          aria-valuenow={Math.round(clamped)}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuetext={safeTotal > 0 ? `${formatPercent(pct)} (${safeAssigned}/${safeTotal})` : formatPercent(pct)}
        />
      </div>
      {showNumbers && (
        <div className="flex justify-between mt-0.5 text-2xs text-text-tertiary font-mono">
          <span>{formatPercent(pct)}</span>
          {safeTotal > 0 && (
            <span>
              {safeAssigned}/{safeTotal}
            </span>
          )}
        </div>
      )}
    </div>
  )
}

export default UtilizationBar
