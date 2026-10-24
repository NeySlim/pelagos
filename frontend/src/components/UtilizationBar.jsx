// SPDX-License-Identifier: Apache-2.0
// Pool or subnet utilization: a bar colored by threshold (success, warning at
// `warn` percent, danger at `full` percent) with the assigned/total figures.
import { cn } from '../lib/utils'

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
      <div className={cn('w-full rounded-full bg-tertiary-op80 overflow-hidden', heights[size] || heights.md)}>
        <div
          className={cn('h-full rounded-full transition-all duration-300', colors[level])}
          style={{ width: `${clamped}%` }}
          role="progressbar"
          aria-valuenow={Math.round(clamped)}
          aria-valuemin={0}
          aria-valuemax={100}
        />
      </div>
      {showNumbers && (
        <div className="flex justify-between mt-0.5 text-2xs text-text-tertiary font-mono">
          <span>{Math.round(clamped)}%</span>
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
