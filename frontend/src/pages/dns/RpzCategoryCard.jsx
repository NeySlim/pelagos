// SPDX-License-Identifier: Apache-2.0
// One category of the RPZ catalog: switch, level with its size, add-ons, extra URLs, action and the
// memory estimate per node before anything is subscribed.
import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Warning } from '@phosphor-icons/react'
import { Card } from '../../components/Card'
import { Badge } from '../../components/Badge'
import { Button } from '../../components/Button'
import { Input } from '../../components/Input'
import { Select } from '../../components/ui/Select'
import ToggleSwitch from '../../components/ui/ToggleSwitch'
import TagsInput from '../../components/ui/TagsInput'
import { api } from '../../services/api'
import {
  ACTIONS,
  LEVEL_VARIANT,
  categoryBody,
  estimatedMb,
  formFromSelection,
  formatCount,
  formatMb,
  levelsOf,
  sameForm,
  selectedLists,
  selectionEntries,
  validUrl,
} from './rpzHelpers'

function Estimate({ estimate, acknowledged, onAcknowledge }) {
  const { t } = useTranslation('dns')
  const warned = (estimate?.nodes || []).filter((n) => n.level !== 'ok')
  if (!warned.length) return null
  const high = warned.some((n) => n.level === 'high')
  return (
    <div className="rounded-lg border border-border p-3 space-y-2 text-sm" data-testid="rpz-estimate">
      {warned.map((n) => (
        <div key={n.node_id} className="flex items-start gap-2" data-testid="rpz-estimate-node">
          <Warning size={16} className={n.level === 'high' ? 'status-danger-text mt-0.5' : 'status-warning-text mt-0.5'} />
          <span>
            {t('rpzsub.estimate.node', { name: n.name, peak: formatMb(n.peak_mb), ram: formatMb(n.ram_mb), percent: n.percent_of_ram })}{' '}
            <Badge variant={LEVEL_VARIANT[n.level]} size="sm">{t(`rpzsub.estimate.${n.level}`)}</Badge>
          </span>
        </div>
      ))}
      {high && (
        <label className="flex items-center gap-2 cursor-pointer">
          <input type="checkbox" checked={acknowledged} onChange={(e) => onAcknowledge(e.target.checked)} data-testid="rpz-estimate-ack" />
          <span>{t('rpzsub.estimate.acknowledge')}</span>
        </label>
      )}
    </div>
  )
}

export function RpzCategoryCard({ id, category, catalog, selection, nodes, settings, canWrite, onSave, onClear, busy }) {
  const { t } = useTranslation(['dns', 'common'])
  const initial = useMemo(() => formFromSelection(category, selection), [category, selection])
  const [form, setForm] = useState(initial)
  const [estimate, setEstimate] = useState(null)
  const [acknowledged, setAcknowledged] = useState(false)
  useEffect(() => setForm(initial), [initial])
  const set = (key) => (value) => setForm((f) => ({ ...f, [key]: value }))
  const levels = levelsOf(category)
  const lists = selectedLists(category, form)
  const entries = selectionEntries(catalog, category, form)
  const bytes = settings?.bytes_per_entry || 800
  const dirty = !selection ? form.enabled : !sameForm(form, initial) || form.enabled !== initial.enabled

  useEffect(() => {
    setAcknowledged(false)
    if (!form.enabled || !dirty || !lists.length) {
      setEstimate(null)
      return undefined
    }
    let live = true
    const timer = setTimeout(() => {
      api.dns
        .rpzEstimate({ category: id, level: form.level, lists: form.lists, addons: form.addons, node_ids: form.nodes.length ? form.nodes : undefined })
        .then((e) => live && setEstimate(e))
        .catch(() => live && setEstimate(null))
    }, 250)
    return () => {
      live = false
      clearTimeout(timer)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id, form.enabled, form.level, JSON.stringify(form.lists), JSON.stringify(form.addons), JSON.stringify(form.nodes), dirty])

  const needsAck = (estimate?.nodes || []).some((n) => n.level === 'high')
  const invalid = (form.action === 'redirect' && !form.redirect.trim()) || (form.level === 'custom' && !form.lists.length)
  const toggleIn = (key, value) => set(key)(form[key].includes(value) ? form[key].filter((v) => v !== value) : [...form[key], value])
  const levelLabel = (level) =>
    level === 'custom' ? t('rpzsub.levels.custom') : `${t(`rpzsub.levels.${level}`)} (${formatCount(category.levels[level].entries)})`

  return (
    <Card className="p-4 space-y-3" hover={false} data-testid={`rpz-category-${id}`}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="font-semibold text-text-primary">{t(`rpzsub.categories.${id}.name`)}</h3>
          <p className="text-xs text-text-secondary mt-0.5">{t(`rpzsub.categories.${id}.description`)}</p>
        </div>
        <ToggleSwitch checked={form.enabled} onChange={set('enabled')} disabled={!canWrite} ariaLabel={t('rpzsub.enable', { name: t(`rpzsub.categories.${id}.name`) })} />
      </div>

      {form.enabled && (
        <div className="space-y-3">
          {levels.length > 1 && (
            <Select
              label={t('rpzsub.level')}
              value={form.level}
              onChange={set('level')}
              options={levels.map((l) => ({ value: l, label: levelLabel(l) }))}
              disabled={!canWrite}
              data-testid="rpz-level"
            />
          )}
          {form.level === 'custom' && (
            <div className="space-y-1" data-testid="rpz-custom-lists">
              {category.lists.map((listId) => (
                <label key={listId} className="flex items-center gap-2 text-sm cursor-pointer">
                  <input type="checkbox" checked={form.lists.includes(listId)} onChange={() => toggleIn('lists', listId)} disabled={!canWrite} />
                  <span>{catalog.lists[listId].name}</span>
                  <span className="text-text-tertiary">{formatCount(catalog.lists[listId].entries)}</span>
                </label>
              ))}
            </div>
          )}
          <p className="text-xs text-text-secondary" data-testid="rpz-size">
            {t('rpzsub.size', { entries: formatCount(entries), memory: formatMb(estimatedMb(entries, bytes)) })}
          </p>
          <ul className="text-xs space-y-0.5" data-testid="rpz-lists">
            {lists.map((listId) => (
              <li key={listId} className="flex flex-wrap gap-x-2">
                <a href={catalog.lists[listId].homepage} target="_blank" rel="noreferrer noopener" className="text-accent-primary hover:underline">
                  {catalog.lists[listId].name}
                </a>
                <span className="text-text-tertiary">{formatCount(catalog.lists[listId].entries)}</span>
                <span className="text-text-tertiary">{t('rpzsub.license', { license: catalog.lists[listId].license })}</span>
              </li>
            ))}
          </ul>
          {category.addons.length > 0 && (
            <div className="space-y-1" data-testid="rpz-addons">
              <div className="text-xs font-medium text-text-secondary">{t('rpzsub.addons')}</div>
              {category.addons.map((listId) => (
                <label key={listId} className="flex items-center gap-2 text-sm cursor-pointer">
                  <input type="checkbox" checked={form.addons.includes(listId)} onChange={() => toggleIn('addons', listId)} disabled={!canWrite} />
                  <span>{catalog.lists[listId].name}</span>
                  <span className="text-text-tertiary">{formatCount(catalog.lists[listId].entries)}</span>
                </label>
              ))}
            </div>
          )}
          <TagsInput
            label={t('rpzsub.ownUrls')}
            value={form.urls}
            onChange={set('urls')}
            placeholder="https://lists.example.com/list.txt"
            helperText={t('rpzsub.ownUrlsHelp')}
            validate={validUrl}
          />
          <details className="text-sm">
            <summary className="cursor-pointer text-text-secondary">{t('rpzsub.advanced')}</summary>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-2">
              <Select
                label={t('rpzsub.action')}
                value={form.action}
                onChange={set('action')}
                options={ACTIONS.map((a) => ({ value: a, label: t(`rpzsub.actions.${a}`) }))}
                disabled={!canWrite}
              />
              {form.action === 'redirect' && (
                <Input label={t('rpzsub.redirect')} value={form.redirect} onChange={(e) => set('redirect')(e.target.value)} placeholder="192.0.2.80" helperText={t('rpzsub.redirectHelp')} />
              )}
              <Input label={t('rpzsub.interval')} type="number" min="1" value={form.interval_hours} onChange={(e) => set('interval_hours')(e.target.value)} />
              {nodes.length > 1 && (
                <div className="space-y-1">
                  <div className="text-xs font-medium text-text-secondary">{t('rpzsub.onNodes')}</div>
                  <label className="flex items-center gap-2 text-sm cursor-pointer">
                    <input type="checkbox" checked={form.nodes.length === 0} onChange={() => set('nodes')([])} />
                    <span>{t('rpzsub.allNodes')}</span>
                  </label>
                  {nodes.map((n) => (
                    <label key={n.id} className="flex items-center gap-2 text-sm cursor-pointer">
                      <input type="checkbox" checked={form.nodes.includes(n.id)} onChange={() => toggleIn('nodes', n.id)} />
                      <span>{n.name}</span>
                    </label>
                  ))}
                </div>
              )}
            </div>
          </details>
        </div>
      )}

      <Estimate estimate={estimate} acknowledged={acknowledged} onAcknowledge={setAcknowledged} />

      {canWrite && (
        <div className="flex gap-2 justify-end">
          {selection && (
            <Button variant="ghost" size="sm" onClick={() => onClear(id)} disabled={busy} data-testid="rpz-category-clear">
              {t('rpzsub.remove')}
            </Button>
          )}
          <Button
            size="sm"
            onClick={() => (form.enabled ? onSave(id, categoryBody(form)) : onClear(id))}
            disabled={busy || !dirty || invalid || (needsAck && !acknowledged)}
            data-testid="rpz-category-save"
          >
            {t('rpzsub.save')}
          </Button>
        </div>
      )}
    </Card>
  )
}
