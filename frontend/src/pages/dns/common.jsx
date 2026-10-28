// SPDX-License-Identifier: Apache-2.0
// Small presentational pieces shared by the DNS screens.
import { useTranslation } from 'react-i18next'
import { Badge } from '../../components/Badge'
import { cn } from '../../lib/utils'
import { TransferSerial } from '../../components/motion'
import { laggingNodes } from './helpers'
import { useCatchUps } from './catchUp'

// A node that was behind and now rises has received a zone transfer: it is drawn as one.
export function SerialCells({ serials = {}, nameOf, className }) {
  const { t } = useTranslation('dns')
  const lag = new Set(laggingNodes(serials))
  const catching = useCatchUps(serials)
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
          <span className={lag.has(id) ? 'text-text-secondary' : 'text-text-tertiary'}>{nameOf(id)}</span>
          {serial === null || serial === undefined ? <span>{t('zones.noSerial')}</span> : <TransferSerial value={serial} transfer={catching.has(id)} testId="zone-serial" />}
        </span>
      ))}
    </div>
  )
}

const CHIP = 'inline-flex items-center gap-1 rounded px-1.5 py-px font-mono text-2xs border'

// One chip per node with what the nodes compare for a zone that has no serial of its own:
// the hints file version (hint) or the forward mode and forwarders (forward).
export function ConfigCells({ zone, nameOf, divergent }) {
  const { t } = useTranslation('dns')
  const hint = zone.zone.kind === 'hint'
  const entries = Object.entries((hint ? zone.hints : zone.forwarders) || {})
  if (!entries.length) return <span className="text-text-tertiary">-</span>
  const tone = divergent ? 'status-warning-bg status-warning-text border-transparent' : 'border-border-op50 text-text-secondary'
  return (
    <div className="flex flex-wrap gap-1" data-testid="zone-config" title={divergent ? t(hint ? 'zones.hintsDiffer' : 'zones.forwardDiffer') : undefined}>
      {entries.map(([id, value]) => {
        const text = hint
          ? value.related_version ? String(value.related_version) : value.error || t('zones.hintsNoVersion')
          : `${value.forward} ${(value.forwarders || []).join(', ')}`
        const title = hint && value.related_version ? t('zones.hintsVersion', { version: value.related_version }) : value.file
        return (
          <span key={id} className={cn(CHIP, tone)} title={title} data-testid="zone-config-cell">
            <span className="text-text-tertiary">{nameOf(id)}</span>
            <span>{text}</span>
          </span>
        )
      })}
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
