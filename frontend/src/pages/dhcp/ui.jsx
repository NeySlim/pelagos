// SPDX-License-Identifier: Apache-2.0
// Small components shared by the DHCP, hosts and nodes areas.
import { useTranslation } from 'react-i18next'
import { ArrowsClockwise, PencilSimple, Plus, Trash } from '@phosphor-icons/react'
import { Badge } from '../../components/Badge'
import { Button } from '../../components/Button'
import { Input } from '../../components/Input'
import { PageLayout } from '../../components/PageLayout'
import { errorMessage } from '../../services/apiClient'
import { cn } from '../../lib/utils'
import { userContextEntries } from './lib'
import { KeaFileBanner } from './KeaFileBanner'
import { KeaSeriesBanner } from './KeaSeriesBanner'

const KNOWN_LABELS = { 'pelagos.notes': 'userContext.note', 'pelagos:note': 'userContext.note', 'pelagos.owner': 'userContext.owner', 'pelagos:owner': 'userContext.owner' }

export function OptionChips({ options = [], empty = '-', className }) {
  if (!options.length) return <span className="text-text-tertiary">{empty}</span>
  return (
    <div className={cn('flex flex-wrap gap-1', className)}>
      {options.map((o, i) => (
        <span key={`${o.name}-${o.code}-${i}`} className="inline-flex items-center gap-1 px-1.5 py-px rounded bg-tertiary-op60 text-2xs font-mono text-text-secondary">
          <span className="text-text-primary">{o.name ?? o.code}</span>
          <span className="text-text-tertiary">=</span>
          <span className="break-all">{o.data}</span>
        </span>
      ))}
    </div>
  )
}

export function ClassChips({ classes = [] }) {
  if (!classes?.length) return null
  return (
    <span className="inline-flex flex-wrap gap-1">
      {classes.map((c) => (
        <Badge key={c} variant="violet" size="sm">
          {c}
        </Badge>
      ))}
    </span>
  )
}

// user-context comes from Kea and is untrusted: rendered as text, never as markup.
export function UserContextView({ context }) {
  const { t } = useTranslation('dhcp')
  const entries = userContextEntries(context)
  if (!entries.length) return <span className="text-xs text-text-tertiary">{t('userContext.empty')}</span>
  return (
    <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1 text-xs" data-testid="user-context">
      {entries.map(([key, value]) => (
        <div key={key} className="contents">
          <dt className="text-text-tertiary font-mono">
            {KNOWN_LABELS[key] ? t(KNOWN_LABELS[key]) : key}
          </dt>
          <dd className="text-text-primary break-all">{typeof value === 'string' ? value : JSON.stringify(value)}</dd>
        </div>
      ))}
    </dl>
  )
}

export function Checkbox({ label, checked, onChange, testId, disabled }) {
  return (
    <label className="flex items-center gap-2 text-xs text-text-primary cursor-pointer select-none">
      <input
        type="checkbox"
        checked={Boolean(checked)}
        onChange={(e) => onChange(e.target.checked)}
        disabled={disabled}
        className="accent-[var(--accent-pro)]"
        data-testid={testId}
      />
      {label}
    </label>
  )
}

export function FieldLabel({ children, hint }) {
  return (
    <span className="block text-xs font-medium text-text-secondary mb-1">
      {children}
      {/* The text separator keeps label and hint apart in the accessible name. */}
      {hint && <span className="font-normal text-text-tertiary">{' '}({hint})</span>}
    </span>
  )
}

export function TextArea({ label, hint, value, onChange, rows = 3, placeholder, error, testId, mono = true }) {
  return (
    <label className="block">
      <FieldLabel hint={hint}>{label}</FieldLabel>
      <textarea
        value={value}
        onChange={(e) => onChange(e.target.value)}
        rows={rows}
        placeholder={placeholder}
        data-testid={testId}
        className={cn(
          'w-full px-2.5 py-1.5 bg-bg-tertiary border rounded-md text-sm text-text-primary placeholder-text-tertiary focus:outline-none focus:border-accent-primary resize-y',
          mono && 'font-mono',
          error ? 'border-accent-danger' : 'border-border',
        )}
      />
      {error && <span className="block text-xs status-danger-text mt-1">{error}</span>}
    </label>
  )
}

// Native select: the forms keep plain FormData-free state, and this stays testable.
export function NativeSelect({ label, value, onChange, options, testId, disabled, helperText }) {
  return (
    <label className="block">
      {label && <FieldLabel>{label}</FieldLabel>}
      <select
        value={value ?? ''}
        onChange={(e) => onChange(e.target.value)}
        disabled={disabled}
        data-testid={testId}
        className="w-full h-8 px-2 bg-bg-tertiary border border-border rounded-md text-sm text-text-primary focus:outline-none focus:border-accent-primary disabled:opacity-50"
      >
        {options.map((o) => (
          <option key={String(o.value)} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      {helperText && <span className="block text-2xs text-text-tertiary mt-1">{helperText}</span>}
    </label>
  )
}

// Inline numbers "label value" for stat strips.
export function Stat({ label, value, tone }) {
  return (
    <div className="flex flex-col min-w-[90px]">
      <span className="text-2xs uppercase tracking-wider text-text-tertiary">{label}</span>
      <span className={cn('text-lg font-semibold font-mono', tone ? `status-${tone}-text` : 'text-text-primary')}>{value ?? '-'}</span>
    </div>
  )
}

// Page frame of every DHCP, hosts and nodes screen: title and subtitle from
// `<ns>:pages.<page>`, the family badge on DHCP pages, refresh plus extra actions.
export function AreaPage({ ns, page, icon, family, actions, onRefresh, loading, tabs, activeTab, onTabChange, children }) {
  const { t } = useTranslation([ns, 'common'])
  return (
    <PageLayout
      icon={icon}
      title={t(`${ns}:pages.${page}.title`)}
      subtitle={t(`${ns}:pages.${page}.subtitle`)}
      badge={
        family ? (
          <Badge variant={family === 'v6' ? 'violet' : 'purple'} size="sm" data-testid="family-badge">
            {family === 'v6' ? 'DHCPv6' : 'DHCPv4'}
          </Badge>
        ) : undefined
      }
      testId={`page-${ns}-${page}`}
      tabs={tabs}
      activeTab={activeTab}
      onTabChange={onTabChange}
      actions={
        <div className="flex items-center gap-2">
          {actions}
          {onRefresh && (
            <Button variant="secondary" size="sm" onClick={onRefresh} disabled={loading} data-testid="page-refresh">
              <ArrowsClockwise size={14} />
              {t('common:actions.refresh')}
            </Button>
          )}
        </div>
      }
    >
      {ns === 'dhcp' && family && <KeaFileBanner engine={family} />}
      {ns === 'dhcp' && family && <KeaSeriesBanner />}
      {children}
    </PageLayout>
  )
}

// Error line for a section whose read failed, with a retry button.
export function SectionError({ error, onRetry }) {
  const { t } = useTranslation()
  if (!error) return null
  return (
    <div className="flex items-center gap-3 rounded-lg status-danger-bg border status-danger-border px-3 py-2 text-xs status-danger-text" role="alert">
      <span className="flex-1">{errorMessage(error)}</span>
      {onRetry && (
        <Button variant="secondary" size="xs" onClick={onRetry}>
          {t('common:actions.retry')}
        </Button>
      )}
    </div>
  )
}

// Edit and delete icon buttons of a table row; clicks do not reach the row.
export function RowActions({ onEdit, onDelete, editLabel, deleteLabel, testId }) {
  return (
    <span className="inline-flex items-center gap-1" onClick={(e) => e.stopPropagation()} data-testid={testId}>
      {onEdit && (
        <Button variant="ghost" size="xs" onClick={onEdit} title={editLabel} aria-label={editLabel} data-testid="row-edit">
          <PencilSimple size={13} />
        </Button>
      )}
      {onDelete && (
        <Button variant="ghost" size="xs" onClick={onDelete} title={deleteLabel} aria-label={deleteLabel} data-testid="row-delete">
          <Trash size={13} className="status-danger-text" />
        </Button>
      )}
    </span>
  )
}

// Editable list of rows, one input per row with its own error, add and remove. `rows` is an
// array of strings; `onChange` receives the new array. Row `i` error: `errors[i]`.
export function PoolRows({ label, hint, rows, onChange, placeholder, errors = {}, addLabel, removeLabel, testId }) {
  const setRow = (i, value) => onChange(rows.map((r, j) => (j === i ? value : r)))
  return (
    <fieldset className="space-y-1.5" data-testid={testId}>
      <legend><FieldLabel hint={hint}>{label}</FieldLabel></legend>
      {rows.map((row, i) => (
        <div key={i} className="flex items-start gap-1.5" data-testid={`${testId}-row`}>
          <div className="flex-1">
            <Input
              aria-label={`${label} ${i + 1}`}
              value={row}
              onChange={(e) => setRow(i, e.target.value)}
              placeholder={placeholder}
              error={errors[i]}
              className="font-mono"
            />
          </div>
          <Button type="button" variant="ghost" size="xs" onClick={() => onChange(rows.filter((_, j) => j !== i))} title={removeLabel} aria-label={`${removeLabel} ${i + 1}`} data-testid={`${testId}-remove`}>
            <Trash size={13} className="status-danger-text" />
          </Button>
        </div>
      ))}
      <Button type="button" variant="secondary" size="xs" onClick={() => onChange([...rows, ''])} data-testid={`${testId}-add`}>
        <Plus size={12} />
        {addLabel}
      </Button>
    </fieldset>
  )
}

// Option rows { key, value }: name (or code) on the left, data on the right.
export function OptionRows({ label, hint, rows, onChange, keyLabel, valueLabel, keyPlaceholder, valuePlaceholder, errors = {}, addLabel, removeLabel, testId }) {
  const setRow = (i, patch) => onChange(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)))
  return (
    <fieldset className="space-y-1.5" data-testid={testId}>
      <legend><FieldLabel hint={hint}>{label}</FieldLabel></legend>
      {rows.map((row, i) => (
        <div key={i} className="flex items-start gap-1.5" data-testid={`${testId}-row`}>
          <div className="w-2/5">
            <Input aria-label={`${keyLabel} ${i + 1}`} value={row.key} onChange={(e) => setRow(i, { key: e.target.value })} placeholder={keyPlaceholder} error={errors[i]} className="font-mono" />
          </div>
          <div className="flex-1">
            <Input aria-label={`${valueLabel} ${i + 1}`} value={row.value} onChange={(e) => setRow(i, { value: e.target.value })} placeholder={valuePlaceholder} className="font-mono" />
          </div>
          <Button type="button" variant="ghost" size="xs" onClick={() => onChange(rows.filter((_, j) => j !== i))} title={removeLabel} aria-label={`${removeLabel} ${i + 1}`} data-testid={`${testId}-remove`}>
            <Trash size={13} className="status-danger-text" />
          </Button>
        </div>
      ))}
      <Button type="button" variant="secondary" size="xs" onClick={() => onChange([...rows, { key: '', value: '' }])} data-testid={`${testId}-add`}>
        <Plus size={12} />
        {addLabel}
      </Button>
    </fieldset>
  )
}
