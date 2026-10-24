// SPDX-License-Identifier: Apache-2.0
// Unified diff renderer (Plan.diff, AuditEntry.diff): one row per line, colored by
// kind, file headers and hunk markers kept. Pure text, no HTML interpretation.
import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { cn } from '../lib/utils'

export function parseUnifiedDiff(text) {
  if (!text) return []
  return text.replace(/\n$/, '').split('\n').map((line, index) => {
    let kind = 'context'
    if (line.startsWith('+++') || line.startsWith('---')) kind = 'file'
    else if (line.startsWith('@@')) kind = 'hunk'
    else if (line.startsWith('diff ') || line.startsWith('index ')) kind = 'meta'
    else if (line.startsWith('+')) kind = 'add'
    else if (line.startsWith('-')) kind = 'del'
    else if (line.startsWith('~')) kind = 'change'
    return { index, kind, text: line }
  })
}

const rowClass = {
  add: 'bg-status-success-op10 text-status-success',
  del: 'bg-status-danger-op10 text-status-danger',
  change: 'bg-status-warning-op10 text-status-warning',
  hunk: 'text-accent-primary bg-accent-primary-op10',
  file: 'text-text-primary font-semibold bg-tertiary-op50',
  meta: 'text-text-tertiary',
  context: 'text-text-secondary',
}

export function DiffView({ diff, maxHeight = 360, className, emptyLabel }) {
  const { t } = useTranslation()
  const lines = useMemo(() => parseUnifiedDiff(diff), [diff])
  const stats = useMemo(
    () => lines.reduce((acc, l) => ({
      add: acc.add + (l.kind === 'add' ? 1 : 0),
      del: acc.del + (l.kind === 'del' ? 1 : 0),
      change: acc.change + (l.kind === 'change' ? 1 : 0),
    }), { add: 0, del: 0, change: 0 }),
    [lines],
  )

  if (lines.length === 0) {
    return <div className={cn('text-xs text-text-tertiary italic px-3 py-2', className)}>{emptyLabel || t('diff.empty')}</div>
  }

  return (
    <div className={cn('rounded-lg border border-border overflow-hidden bg-bg-primary', className)} data-testid="diff-view">
      <div className="flex items-center gap-3 px-3 py-1.5 border-b border-border text-2xs font-mono bg-bg-secondary">
        {/* A pseudo diff of `~` differences has no +/- lines: counting them would read as no change. */}
        {(stats.add > 0 || stats.del > 0 || stats.change === 0) && (
          <>
            <span className="text-status-success">+{stats.add}</span>
            <span className="text-status-danger">-{stats.del}</span>
          </>
        )}
        {stats.change > 0 && <span className="text-status-warning">~{stats.change}</span>}
        <span className="text-text-tertiary">{t('diff.lines', { count: lines.length })}</span>
      </div>
      <pre className="overflow-auto text-xs font-mono leading-5 m-0" style={{ maxHeight }}>
        {lines.map((line) => (
          <div key={line.index} className={cn('px-3 whitespace-pre', rowClass[line.kind])} data-kind={line.kind}>
            {line.text || ' '}
          </div>
        ))}
      </pre>
    </div>
  )
}

export default DiffView
