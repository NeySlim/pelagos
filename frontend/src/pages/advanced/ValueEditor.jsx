// SPDX-License-Identifier: Apache-2.0
// Value input generated from a statement's grammar kind (bindGrammar.toForm).
import { useTranslation } from 'react-i18next'
import { Input, Select, TagsInput } from '../../components'
import { cn } from '../../lib/utils'

export function ValueEditor({ form, onChange, disabled, error }) {
  const { t } = useTranslation('advanced')
  const set = (patch) => onChange({ ...form, ...patch })
  const errorText = error ? t(`bind.errors.${error}`) : undefined

  switch (form.kind) {
    case 'boolean':
    case 'enum': {
      const values = form.kind === 'boolean' ? ['yes', 'no'] : form.values
      return (
        <Select
          label={t('bind.value')}
          options={values.map((v) => ({ value: v, label: v }))}
          value={form.value || undefined}
          onChange={(v) => set({ value: v })}
          placeholder={t('bind.choose')}
          disabled={disabled}
          error={errorText}
        />
      )
    }
    case 'list':
      return (
        <div className="space-y-3" data-testid="value-list">
          {form.prefix !== undefined && form.prefix !== '' && (
            <Input label={t('bind.prefix')} value={form.prefix} onChange={(e) => set({ prefix: e.target.value })} disabled={disabled} className="font-mono" />
          )}
          <TagsInput label={t('bind.elements')} value={form.items} onChange={(items) => set({ items })} placeholder={t('bind.elementsPlaceholder')} helperText={t('bind.elementsHelp')} />
        </div>
      )
    case 'block':
      return (
        <div className="space-y-2">
          <Input label={t('bind.blockName')} value={form.value || ''} onChange={(e) => set({ value: e.target.value })} disabled={disabled} helperText={t('bind.blockHelp')} />
        </div>
      )
    case 'raw':
      return (
        <div className="space-y-1.5">
          <label className="block text-xs font-medium text-text-secondary">{t('bind.rawValue')}</label>
          <textarea
            value={form.value}
            onChange={(e) => set({ value: e.target.value })}
            disabled={disabled}
            rows={3}
            spellCheck={false}
            className={cn('w-full px-2.5 py-1.5 bg-bg-tertiary border rounded-md text-xs font-mono text-text-primary', error ? 'border-accent-danger' : 'border-border')}
            data-testid="value-raw"
          />
          {errorText ? <p className="text-xs status-danger-text">{errorText}</p> : <p className="text-xs text-text-tertiary">{t('bind.rawHelp')}</p>}
        </div>
      )
    default:
      return (
        <Input
          label={t('bind.value')}
          value={form.value}
          onChange={(e) => set({ value: e.target.value })}
          disabled={disabled}
          error={errorText}
          inputMode={form.kind === 'integer' ? 'numeric' : undefined}
          data-testid="value-input"
        />
      )
  }
}

export default ValueEditor
