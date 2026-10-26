// SPDX-License-Identifier: Apache-2.0
// The subscriptions tab: nodes and their memory, the catalog by category, own lists and zone transfers,
// the state of every list (size, entries, source date, last update) and the order of the zones.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ArrowDown, ArrowUp, ArrowsClockwise, CloudArrowDown, Plus, Trash } from '@phosphor-icons/react'
import { Card } from '../../components/Card'
import { Badge } from '../../components/Badge'
import { Button } from '../../components/Button'
import { DataTable } from '../../components/DataTable'
import { FormModal } from '../../components/FormModal'
import { Input } from '../../components/Input'
import { Select } from '../../components/ui/Select'
import TagsInput from '../../components/ui/TagsInput'
import { useNotification } from '../../contexts/NotificationContext'
import { api } from '../../services/api'
import { RpzCategoryCard } from './RpzCategoryCard'
import {
  ACTIONS,
  STATUS_VARIANT,
  formatBytes,
  formatCount,
  formatEpoch,
  formatMb,
  latestStatus,
  validUrl,
  worstStatus,
} from './rpzHelpers'

const EMPTY = { kind: 'url', id: '', name: '', url: '', format: 'auto', zone: '', primaries: [], tsig_key: '', tsig_secret: '', action: 'nxdomain', redirect: '', interval_hours: 24 }

function SubscriptionModal({ open, onClose, onSave, busy }) {
  const { t } = useTranslation(['dns', 'common'])
  const [form, setForm] = useState(EMPTY)
  const set = (key) => (value) => setForm((f) => ({ ...f, [key]: value }))
  const axfr = form.kind === 'axfr'
  const ready = /^[a-z][a-z0-9-]{0,39}$/.test(form.id) && (axfr ? form.zone && form.primaries.length : validUrl(form.url)) && (form.action !== 'redirect' || form.redirect.trim())
  const submit = async () => {
    const body = { kind: form.kind, name: form.name || form.id, action: form.action, interval_hours: Number(form.interval_hours) || 24 }
    if (form.action === 'redirect') body.redirect = form.redirect.trim()
    if (axfr) Object.assign(body, { zone: form.zone.trim(), primaries: form.primaries, tsig_key: form.tsig_key.trim(), ...(form.tsig_secret ? { tsig_secret: form.tsig_secret } : {}) })
    else Object.assign(body, { url: form.url.trim(), format: form.format })
    if (await onSave(form.id, body)) setForm(EMPTY)
  }
  return (
    <FormModal open={open} onClose={onClose} title={t('rpzsub.sub.title')} onSubmit={submit} loading={busy} disabled={!ready} submitLabel={t('rpzsub.sub.submit')} testId="rpz-sub-modal">
      <Select
        label={t('rpzsub.sub.kind')}
        value={form.kind}
        onChange={set('kind')}
        options={[
          { value: 'url', label: t('rpzsub.sub.kindUrl') },
          { value: 'axfr', label: t('rpzsub.sub.kindAxfr') },
        ]}
      />
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <Input label={t('rpzsub.sub.id')} value={form.id} onChange={(e) => set('id')(e.target.value.toLowerCase())} placeholder="my-list" helperText={t('rpzsub.sub.idHelp')} data-testid="rpz-sub-id" />
        <Input label={t('rpzsub.sub.name')} value={form.name} onChange={(e) => set('name')(e.target.value)} />
      </div>
      {axfr ? (
        <>
          <Input label={t('rpzsub.sub.zone')} value={form.zone} onChange={(e) => set('zone')(e.target.value)} placeholder="rpz.example.net" helperText={t('rpzsub.sub.zoneHelp')} />
          <TagsInput label={t('rpzsub.sub.primaries')} value={form.primaries} onChange={set('primaries')} placeholder="192.0.2.53" />
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <Input label={t('rpzsub.sub.tsigKey')} value={form.tsig_key} onChange={(e) => set('tsig_key')(e.target.value)} />
            <Input label={t('rpzsub.sub.tsigSecret')} type="password" value={form.tsig_secret} onChange={(e) => set('tsig_secret')(e.target.value)} helperText={t('rpzsub.sub.tsigSecretHelp')} />
          </div>
        </>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <Input label={t('rpzsub.sub.url')} value={form.url} onChange={(e) => set('url')(e.target.value)} placeholder="https://lists.example.com/list.txt" data-testid="rpz-sub-url" />
          <Select
            label={t('rpzsub.sub.format')}
            value={form.format}
            onChange={set('format')}
            options={['auto', 'rpz', 'hosts', 'domains', 'adblock'].map((f) => ({ value: f, label: t(`rpzsub.formats.${f}`) }))}
          />
        </div>
      )}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <Select label={t('rpzsub.action')} value={form.action} onChange={set('action')} options={ACTIONS.map((a) => ({ value: a, label: t(`rpzsub.actions.${a}`) }))} />
        {form.action === 'redirect' && <Input label={t('rpzsub.redirect')} value={form.redirect} onChange={(e) => set('redirect')(e.target.value)} placeholder="192.0.2.80" helperText={t('rpzsub.redirectHelp')} />}
        {!axfr && <Input label={t('rpzsub.interval')} type="number" min="1" value={form.interval_hours} onChange={(e) => set('interval_hours')(e.target.value)} />}
      </div>
    </FormModal>
  )
}

export default function RpzCatalog({ overview, flow, canWrite, refetch }) {
  const { t } = useTranslation(['dns', 'common'])
  const { showInfo, showSuccess } = useNotification()
  const [adding, setAdding] = useState(false)
  const [busy, setBusy] = useState(false)
  const { catalog, categories, subscriptions, nodes, settings } = overview

  // A change saves the selection, then shows the plan that brings the nodes to it.
  const submit = async (call) => {
    setBusy(true)
    try {
      const result = await flow.run(async () => {
        const r = await call()
        return r.plan
      })
      refetch()
      if (!result) showInfo(t('rpzsub.nothingToApply'))
      return Boolean(result)
    } finally {
      setBusy(false)
    }
  }
  const applyNow = () => submit(() => api.dns.rpzPlan())
  const refresh = async (id) => {
    await api.dns.rpzRefresh(id)
    showSuccess(t('rpzsub.refreshRequested'))
    setTimeout(refetch, 1500)
  }
  const move = (index, delta) => {
    const ids = subscriptions.filter((s) => s.enabled).map((s) => s.id)
    const target = index + delta
    if (target < 0 || target >= ids.length) return
    ;[ids[index], ids[target]] = [ids[target], ids[index]]
    submit(() => api.dns.rpzSetOrder(ids))
  }
  const pending = nodes.some((n) => n.pending)
  const own = subscriptions.filter((s) => s.source !== 'catalog')
  const enabled = subscriptions.filter((s) => s.enabled)

  const statusCell = (s) => {
    const worst = worstStatus(s.status)
    return (
      <span title={worst.error || undefined}>
        <Badge variant={STATUS_VARIANT[worst.status] || 'default'} size="sm">{t(`rpzsub.status.${worst.status}`, { defaultValue: worst.status })}</Badge>
        {worst.error && <span className="block text-xs text-accent-danger mt-0.5 max-w-xs truncate">{worst.error}</span>}
      </span>
    )
  }

  const listColumns = [
    {
      key: 'name',
      label: t('rpzsub.table.list'),
      render: (s) => (
        <span>
          <span className="font-medium">{s.name}</span>
          {s.license && <span className="block text-xs text-text-tertiary">{t('rpzsub.license', { license: s.license })}</span>}
        </span>
      ),
    },
    { key: 'category', label: t('rpzsub.table.category'), render: (s) => (s.category ? t(`rpzsub.categories.${s.category}.name`) : '') },
    { key: 'entries', label: t('rpzsub.table.entries'), align: 'right', mono: true, render: (s) => formatCount(latestStatus(s.status)?.entries ?? '') },
    { key: 'size', label: t('rpzsub.table.size'), align: 'right', mono: true, render: (s) => formatBytes(latestStatus(s.status)?.bytes) },
    { key: 'source', label: t('rpzsub.table.sourceDate'), render: (s) => formatEpoch(latestStatus(s.status)?.source_date) },
    { key: 'updated', label: t('rpzsub.table.lastUpdate'), render: (s) => formatEpoch(latestStatus(s.status)?.updated_at) },
    { key: 'next', label: t('rpzsub.table.nextCheck'), render: (s) => formatEpoch(latestStatus(s.status)?.next_check) },
    { key: 'state', label: t('rpzsub.table.state'), render: statusCell },
    {
      key: 'actions',
      label: '',
      align: 'right',
      render: (s) =>
        canWrite && s.kind === 'url' ? (
          <Button variant="ghost" size="xs" onClick={() => refresh(s.id)} aria-label={t('rpzsub.refreshNow')} data-testid="rpz-refresh">
            <ArrowsClockwise size={13} />
          </Button>
        ) : null,
    },
  ]

  return (
    <div className="space-y-6 max-w-6xl">
      <Card className="p-4" hover={false} data-testid="rpz-nodes">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <ul className="flex flex-wrap gap-x-6 gap-y-1 text-sm">
            {nodes.map((n) => (
              <li key={n.id} data-testid="rpz-node">
                <span className="font-medium">{n.name}</span>{' '}
                <span className="text-text-tertiary">{n.ram_mb ? t('rpzsub.ram', { ram: formatMb(n.ram_mb) }) : ''}</span>{' '}
                <Badge variant={n.error ? 'danger' : n.pending ? 'warning' : 'success'} size="sm">
                  {n.error ? t('rpzsub.nodeError') : n.pending ? t('rpzsub.pending') : t('rpzsub.upToDate')}
                </Badge>
              </li>
            ))}
          </ul>
          {canWrite && pending && (
            <Button size="sm" onClick={applyNow} disabled={busy} data-testid="rpz-apply">
              <CloudArrowDown size={14} />
              {t('rpzsub.applyConfig')}
            </Button>
          )}
        </div>
        <p className="text-xs text-text-secondary mt-2">{t('rpzsub.catalogNote', { version: catalog.version })}</p>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4" data-testid="rpz-categories">
        {Object.entries(catalog.categories).map(([id, category]) => (
          <RpzCategoryCard
            key={id}
            id={id}
            category={category}
            catalog={catalog}
            selection={categories[id]}
            nodes={nodes}
            settings={settings}
            canWrite={canWrite}
            busy={busy}
            onSave={(cat, body) => submit(() => api.dns.rpzSetCategory(cat, body))}
            onClear={(cat) => submit(() => api.dns.rpzClearCategory(cat))}
          />
        ))}
      </div>

      <DataTable
        title={t('rpzsub.own.title')}
        columns={[
          { key: 'name', label: t('rpzsub.table.list'), render: (s) => <span className="font-medium">{s.name}</span> },
          { key: 'kind', label: t('rpzsub.sub.kind'), render: (s) => (s.kind === 'axfr' ? `${t('rpzsub.sub.kindAxfr')} ${s.zone}` : s.url), mono: true },
          { key: 'action', label: t('rpzsub.action'), render: (s) => t(`rpzsub.actions.${s.action}`) },
          { key: 'state', label: t('rpzsub.table.state'), render: statusCell },
          {
            key: 'actions',
            label: '',
            align: 'right',
            render: (s) =>
              canWrite && s.source === 'custom' ? (
                <Button variant="ghost" size="xs" onClick={() => submit(() => api.dns.rpzDeleteSubscription(s.id))} aria-label={t('common:actions.delete')} data-testid="rpz-sub-delete">
                  <Trash size={13} className="status-danger-text" />
                </Button>
              ) : null,
          },
        ]}
        rows={own}
        rowKey="id"
        emptyTitle={t('rpzsub.own.empty')}
        emptyDescription={t('rpzsub.own.emptyHelp')}
        toolbar={
          canWrite ? (
            <Button size="sm" onClick={() => setAdding(true)} data-testid="rpz-sub-add">
              <Plus size={14} />
              {t('rpzsub.own.add')}
            </Button>
          ) : null
        }
        testId="rpz-own-table"
      />

      <DataTable title={t('rpzsub.lists.title')} columns={listColumns} rows={enabled} rowKey="id" emptyTitle={t('rpzsub.lists.empty')} testId="rpz-lists-table" />

      {enabled.length > 1 && (
        <Card className="p-4" hover={false} data-testid="rpz-order">
          <h3 className="font-semibold text-text-primary mb-1">{t('rpzsub.order.title')}</h3>
          <p className="text-xs text-text-secondary mb-3">{t('rpzsub.order.help', { zone: overview.allow_zone })}</p>
          <ol className="space-y-1">
            {enabled.map((s, i) => (
              <li key={s.id} className="flex items-center gap-2 text-sm" data-testid="rpz-order-item">
                <span className="w-6 text-right text-text-tertiary">{i + 1}</span>
                <span className="flex-1">{s.name}</span>
                {canWrite && (
                  <>
                    <Button variant="ghost" size="xs" onClick={() => move(i, -1)} disabled={i === 0 || busy} aria-label={t('rpzsub.order.up')}>
                      <ArrowUp size={13} />
                    </Button>
                    <Button variant="ghost" size="xs" onClick={() => move(i, 1)} disabled={i === enabled.length - 1 || busy} aria-label={t('rpzsub.order.down')}>
                      <ArrowDown size={13} />
                    </Button>
                  </>
                )}
              </li>
            ))}
          </ol>
        </Card>
      )}

      <SubscriptionModal
        open={adding}
        onClose={() => setAdding(false)}
        busy={busy}
        onSave={async (id, body) => {
          const ok = await submit(() => api.dns.rpzSetSubscription(id, body))
          if (ok) setAdding(false)
          return ok
        }}
      />
    </div>
  )
}
