// SPDX-License-Identifier: Apache-2.0
// Loading is a warm-up, not a spinner: placeholders at the final geometry and a vertical
// calibration line that sweeps once (600 ms), then slowly loops while the wait lasts.
// It is for a first load only; a refetch of data already shown keeps the data.
import { useTranslation } from 'react-i18next'
import { cn } from '../../lib/utils'

const WIDTHS = [92, 70, 84, 60, 76]

export function Skeleton({ lines = 4, widths = WIDTHS, className, label, testId = 'skeleton', children }) {
  const { t } = useTranslation()
  return (
    <div className={cn('fx-skeleton', className)} role="status" aria-busy="true" aria-label={label || t('common:common.loading')} data-testid={testId}>
      {children ||
        Array.from({ length: lines }, (_, i) => <div key={i} className="fx-skeleton-line" style={{ width: `${widths[i % widths.length]}%` }} />)}
      <span className="fx-sweep" aria-hidden="true" />
    </div>
  )
}

// Table body placeholder: `rows` lines of `columns` cells, the first one wider.
export function SkeletonTable({ columns = 4, rows = 6, className, label, testId = 'skeleton-table' }) {
  const cols = Math.max(1, Math.min(columns, 8))
  return (
    <Skeleton className={cn('px-3 py-2', className)} label={label} testId={testId}>
      {Array.from({ length: rows }, (_, r) => (
        <div key={r} className="grid gap-4 items-center h-9" style={{ gridTemplateColumns: `repeat(${cols}, minmax(0, 1fr))` }}>
          {Array.from({ length: cols }, (_, c) => (
            <div key={c} className="fx-skeleton-line" style={{ width: `${WIDTHS[(r + c) % WIDTHS.length] - (c === 0 ? 0 : 20)}%` }} />
          ))}
        </div>
      ))}
    </Skeleton>
  )
}
