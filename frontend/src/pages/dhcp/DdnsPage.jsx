// SPDX-License-Identifier: Apache-2.0
// DDNS: the dhcp-ddns connection (read only), the ddns-* parameters (edited through
// a DDNS plan) and the D2 counters of every node, totals and per TSIG key; the Failover tab
// (?tab=failover, ?zone=<view>/<zone>) holds the DDNS failover of every dynamic zone.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'
import { ArrowsClockwise, Plus, ShieldCheck, SlidersHorizontal } from '@phosphor-icons/react'
import { Button } from '../../components/Button'
import { Card } from '../../components/Card'
import { DataTable } from '../../components/DataTable'
import { FormModal } from '../../components/FormModal'
import { Input } from '../../components/Input'
import { LoadingSpinner } from '../../components/LoadingSpinner'
import { useApi } from '../../hooks/useApi'
import { usePermission } from '../../hooks/usePermission'
import { api } from '../../services/api'
import { formatRelativeTime } from '../../lib/utils'
import { AreaPage, NativeSelect, RowActions, SectionError, Stat } from './ui'
import { KeaFileBanner } from './KeaFileBanner'
import { usePlanFlow, useNodeNames } from './hooks'
import { fieldErrors, parseDdnsValue } from './lib'
import { DdnsFailoverPanel } from './DdnsFailoverPanel'
import { FAILOVER_TAB } from './ddnsFailover'

const KNOWN_PARAMS = [
  'ddns-send-updates', 'ddns-override-no-update', 'ddns-override-client-update', 'ddns-replace-client-name',
  'ddns-generated-prefix', 'ddns-qualifying-suffix', 'ddns-update-on-renew', 'ddns-conflict-resolution-mode',
  'ddns-ttl-percent', 'ddns-ttl', 'ddns-ttl-min', 'ddns-ttl-max', 'hostname-char-set', 'hostname-char-replacement',
]
const D2_TOTALS = ['ncr-received', 'update-sent', 'update-success', 'update-timeout', 'update-error', 'ncr-error']

export default function DdnsPage({ family }) {
  const { t } = useTranslation(['dhcp', 'common'])
  const { hasPermission } = usePermission()
  const canWrite = hasPermission('write:dhcp.options')
  const ddns = useApi(() => api.dhcp.ddns(family), [family])
  const d2 = useApi(async () => {
    const servers = (await api.d2.servers())?.items || []
    const stats = await Promise.all(servers.map((s) => api.d2.stats(s.node_id).catch((error) => ({ node_id: s.node_id, error }))))
    return stats
  }, [])
  const [editing, setEditing] = useState(null)
  const flow = usePlanFlow({ onApplied: ddns.refetch })
  const { nameOf } = useNodeNames()
  const [search, setSearch] = useSearchParams()
  const tab = search.get('tab') === FAILOVER_TAB ? FAILOVER_TAB : 'settings'
  const [failoverKey, setFailoverKey] = useState(0)
  const setTab = (id) => setSearch(id === FAILOVER_TAB ? { tab: FAILOVER_TAB } : {}, { replace: true })
  const refresh = () => {
    if (tab === FAILOVER_TAB) {
      setFailoverKey((k) => k + 1)
      return
    }
    ddns.refetch()
    d2.refetch()
  }

  const params = Object.entries(ddns.data?.ddns_params || {}).map(([key, value]) => ({ key, value }))
  const connection = Object.entries(ddns.data?.dhcp_ddns || {}).map(([key, value]) => ({ key, value }))
  const remove = (row) => flow.build(() => api.dhcp.ddnsPlan(family, [{ op: 'delete', target: row.key, before: row.value, after: null }]))

  const paramColumns = [
    { key: 'key', label: t('fields.parameter'), mono: true, sortable: true },
    { key: 'value', label: t('fields.value'), mono: true, render: (r) => JSON.stringify(r.value) },
    ...(canWrite
      ? [{
          key: 'actions',
          label: '',
          align: 'right',
          render: (r) => (
            <RowActions editLabel={t('common:actions.edit')} deleteLabel={t('common:actions.delete')} onEdit={() => setEditing({ row: r })} onDelete={() => remove(r)} />
          ),
        }]
      : []),
  ]

  return (
    <AreaPage
      ns="dhcp"
      page="ddns"
      icon={ArrowsClockwise}
      family={family}
      onRefresh={refresh}
      loading={tab === FAILOVER_TAB ? false : ddns.loading}
      tabs={[
        { id: 'settings', label: t('ddns.tabs.settings'), icon: SlidersHorizontal },
        { id: FAILOVER_TAB, label: t('ddns.tabs.failover'), icon: ShieldCheck },
      ]}
      activeTab={tab}
      onTabChange={setTab}
      actions={
        canWrite && tab !== FAILOVER_TAB && (
          <Button size="sm" onClick={() => setEditing({ row: null })} data-testid="ddns-add">
            <Plus size={14} />
            {t('ddns.add')}
          </Button>
        )
      }
    >
      {tab === FAILOVER_TAB ? (
        <DdnsFailoverPanel selectedZone={search.get('zone')} refreshKey={failoverKey} />
      ) : (
        <div className="space-y-4">
          <KeaFileBanner engine="d2" />
          <div className="grid gap-4 lg:grid-cols-2">
            <DataTable
              title={t('ddns.parameters')}
              columns={paramColumns}
              rows={params}
              rowKey="key"
              loading={ddns.loading}
              error={ddns.error}
              onRetry={ddns.refetch}
              clientSort
              emptyTitle={t('ddns.noParameters')}
              dense
              testId="ddns-params"
            />
            <DataTable
              title={t('ddns.connection')}
              columns={[
                { key: 'key', label: t('fields.parameter'), mono: true },
                { key: 'value', label: t('fields.value'), mono: true, render: (r) => JSON.stringify(r.value) },
              ]}
              rows={connection}
              rowKey="key"
              loading={ddns.loading}
              emptyTitle={t('ddns.noConnection')}
              dense
              testId="ddns-connection"
            />
          </div>
          <section className="space-y-2">
            <h3 className="ui-card-title text-sm font-semibold text-text-primary">{t('ddns.d2Title')}</h3>
            <SectionError error={d2.error} onRetry={d2.refetch} />
            {d2.loading && !d2.data && <LoadingSpinner size="sm" />}
            <div className="grid gap-4 lg:grid-cols-2">
              {(d2.data || []).map((s) => (
                <Card key={s.node_id} className="p-3 space-y-3" hover={false} data-testid="d2-node">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-semibold text-text-primary">{nameOf(s.node_id)}</span>
                    {s.collected_at && <span className="text-2xs text-text-tertiary">{formatRelativeTime(s.collected_at)}</span>}
                  </div>
                  {s.error ? (
                    <SectionError error={s.error} />
                  ) : (
                    <>
                      <div className="flex flex-wrap gap-4">
                        {D2_TOTALS.map((key) => (
                          <Stat
                            key={key}
                            label={key}
                            value={s.totals?.[key]}
                            tone={['update-error', 'update-timeout', 'ncr-error'].includes(key) && s.totals?.[key] > 0 ? 'danger' : undefined}
                          />
                        ))}
                      </div>
                      <table className="w-full text-xs">
                        <thead>
                          <tr className="text-2xs uppercase tracking-wider text-text-tertiary">
                            <th className="text-left py-1">{t('ddns.key')}</th>
                            <th className="text-right py-1">{t('ddns.sent')}</th>
                            <th className="text-right py-1">{t('ddns.success')}</th>
                            <th className="text-right py-1">{t('ddns.timeout')}</th>
                            <th className="text-right py-1">{t('ddns.error')}</th>
                          </tr>
                        </thead>
                        <tbody>
                          {Object.entries(s.per_key || {}).map(([key, c]) => (
                            <tr key={key} className="border-t border-border-op30 font-mono">
                              <td className="py-1">{key}</td>
                              <td className="py-1 text-right">{c['update-sent'] ?? '-'}</td>
                              <td className="py-1 text-right">{c['update-success'] ?? '-'}</td>
                              <td className={`py-1 text-right ${c['update-timeout'] > 0 ? 'status-warning-text' : ''}`}>{c['update-timeout'] ?? '-'}</td>
                              <td className={`py-1 text-right ${c['update-error'] > 0 ? 'status-danger-text' : ''}`}>{c['update-error'] ?? '-'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                      {Object.keys(s.per_key || {}).length > 0 && (
                        <p className="text-2xs text-text-tertiary">{t('ddns.perKeyNote')}</p>
                      )}
                    </>
                  )}
                </Card>
              ))}
            </div>
          </section>
        </div>
      )}
      {editing && <ParamForm family={family} row={editing.row} existing={params} flow={flow} onClose={() => setEditing(null)} />}
      {flow.modal}
    </AreaPage>
  )
}

function ParamForm({ family, row, existing, flow, onClose }) {
  const { t } = useTranslation(['dhcp', 'common'])
  const isNew = !row
  const free = KNOWN_PARAMS.filter((k) => !existing.some((r) => r.key === k))
  const [key, setKey] = useState(row?.key || free[0] || '')
  const [value, setValue] = useState(row ? JSON.stringify(row.value) : '')
  const [errors, setErrors] = useState({})

  const submit = async () => {
    if (!/^[a-z0-9-]+$/.test(key)) {
      setErrors({ key: t('form.badName') })
      return
    }
    const parsed = parseDdnsValue(key, value)
    if (parsed.error) {
      setErrors({ value: t(parsed.error) })
      return
    }
    const after = parsed.value
    try {
      const plan = await flow.build(
        () => api.dhcp.ddnsPlan(family, [{ op: isNew ? 'add' : 'replace', target: key, before: row?.value ?? null, after }]),
        { rethrow: true },
      )
      if (plan) onClose()
    } catch (err) {
      setErrors({ ...fieldErrors(err), _form: err.message })
    }
  }

  return (
    <FormModal
      open
      onClose={onClose}
      title={isNew ? t('ddns.addTitle') : t('ddns.editTitle', { key: row.key })}
      onSubmit={submit}
      submitLabel={t('form.preview')}
      loading={flow.building}
      size="sm"
      testId="ddns-form"
    >
      {isNew ? (
        <NativeSelect label={t('fields.parameter')} value={key} onChange={setKey} options={free.map((k) => ({ value: k, label: k }))} testId="ddns-key" />
      ) : (
        <Input label={t('fields.parameter')} value={key} disabled />
      )}
      {errors.key && <p className="text-xs status-danger-text">{errors.key}</p>}
      <Input label={t('fields.value')} value={value} onChange={(e) => setValue(e.target.value)} helperText={t('ddns.valueHint')} error={errors.value} data-testid="ddns-value" />
      {errors._form && <p className="text-xs status-danger-text">{errors._form}</p>}
    </FormModal>
  )
}
