// SPDX-License-Identifier: Apache-2.0
// Small presentational pieces shared by the DNS screens.
import { useTranslation } from 'react-i18next'
import { Badge } from '../../components/Badge'
import { cn } from '../../lib/utils'
import { laggingNodes } from './helpers'

export function SerialCells({ serials = {}, nameOf, className }) {
  const { t } = useTranslation('dns')
  const lag = new Set(laggingNodes(serials))
  const entries = Object.entries(serials)
  if (!entries.length) return <span className="text-text-tertiary">-</span>
  return (
    <div className={cn('flex flex-wrap gap-1', className)} data-testid="zone-serials">
      {entries.map(([id, serial]) => (
        <span
          key={id}
          title={lag.has(id) ? t('zones.lagging') : undefined}
          className={cn(
            'inline-flex items-center gap-1 rounded px-1.5 py-px font-mono text-2xs border',
            lag.has(id) ? 'status-warning-bg status-warning-text border-transparent' : 'border-border-op50 text-text-secondary',
          )}
        >
          <span className="text-text-tertiary">{nameOf(id)}</span>
          <span>{serial ?? t('zones.noSerial')}</span>
        </span>
      ))}
    </div>
  )
}

export function SourceBadge({ source }) {
  const { t } = useTranslation('dns')
  if (!source) return null
  return (
    <Badge variant={source === 'pelagos' ? 'primary' : 'outline'} size="sm">
      {t(`source.${source}`, { defaultValue: source })}
    </Badge>
  )
}

// How record changes reach a zone: signed UPDATE (dynamic) or a zone file edit (static).
export function ModeBadge({ mode }) {
  const { t } = useTranslation('dns')
  if (mode !== 'dynamic' && mode !== 'static') return null
  return (
    <Badge variant={mode === 'static' ? 'warning' : 'secondary'} size="sm" data-testid="zone-mode">
      <span title={t(`mode.${mode}Help`)}>{t(`mode.${mode}`)}</span>
    </Badge>
  )
}

export function KeyValue({ label, children, mono = false }) {
  return (
    <div className="min-w-0">
      <dt className="text-2xs uppercase tracking-wider text-text-tertiary">{label}</dt>
      <dd className={cn('text-sm text-text-primary break-words', mono && 'font-mono text-xs')}>{children ?? <span className="text-text-tertiary">-</span>}</dd>
    </div>
  )
}

export function ListValue({ items, empty = '-' }) {
  if (!items || !items.length) return <span className="text-text-tertiary">{empty}</span>
  return (
    <span className="flex flex-wrap gap-1">
      {items.map((x) => (
        <span key={x} className="font-mono text-2xs rounded border border-border-op50 px-1.5 py-px text-text-secondary">
          {x}
        </span>
      ))}
    </span>
  )
}
