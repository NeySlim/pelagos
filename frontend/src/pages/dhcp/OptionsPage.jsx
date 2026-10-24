// SPDX-License-Identifier: Apache-2.0
// Global option data (add, replace, delete through one options plan) and the
// custom option definitions, read only.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { SlidersHorizontal, Plus } from '@phosphor-icons/react'
import { DataTable } from '../../components/DataTable'
import { Button } from '../../components/Button'
import { FormModal } from '../../components/FormModal'
import { Input } from '../../components/Input'
import { useApi } from '../../hooks/useApi'
import { usePermission } from '../../hooks/usePermission'
import { api } from '../../services/api'
import { AreaPage, Checkbox, RowActions } from './ui'
import { usePlanFlow } from './hooks'
import { fieldErrors, optionSpace } from './lib'

const flag = (value) => (value === true ? '✓' : '')
const optionId = (o) => o.name || String(o.code)

// Change target of a global option (architecture section 6): option-data/<space>/<name or code>.
const optionTarget = (o, family) => `option-data/${o.space || (family === 'v6' ? 'dhcp6' : 'dhcp4')}/${o.name || String(o.code)}`

export default function OptionsPage({ family }) {
  const { t } = useTranslation(['dhcp', 'common'])
  const { hasPermission } = usePermission()
  const canWrite = hasPermission('write:dhcp.options')
  const options = useApi(() => api.dhcp.options(family), [family])
  const [editing, setEditing] = useState(null)
  const flow = usePlanFlow({ onApplied: options.refetch })
  const items = options.data?.items || []
  const defs = options.data?.option_defs || []

  const remove = (o) =>
    flow.build(() => api.dhcp.optionsPlan(family, [{ op: 'delete', target: optionTarget(o, family), before: o, after: null }]))

  const columns = [
    { key: 'name', label: t('fields.name'), sortable: true, mono: true },
    { key: 'code', label: t('fields.code'), sortable: true, mono: true, width: 70 },
    { key: 'space', label: t('fields.space'), mono: true },
    { key: 'data', label: t('fields.data'), mono: true, truncate: true },
    { key: 'csv_format', label: t('fields.csvFormat'), align: 'center', render: (o) => flag(o.csv_format) },
    { key: 'always_send', label: t('fields.alwaysSend'), align: 'center', render: (o) => flag(o.always_send) },
    { key: 'never_send', label: t('fields.neverSend'), align: 'center', render: (o) => flag(o.never_send) },
    ...(canWrite
      ? [{
          key: 'actions',
          label: '',
          align: 'right',
          render: (o) => (
            <RowActions editLabel={t('common:actions.edit')} deleteLabel={t('common:actions.delete')} onEdit={() => setEditing({ option: o })} onDelete={() => remove(o)} />
          ),
        }]
      : []),
  ]

  const defColumns = [
    { key: 'name', label: t('fields.name'), mono: true },
    { key: 'code', label: t('fields.code'), mono: true },
    { key: 'space', label: t('fields.space'), mono: true },
    { key: 'type', label: t('fields.type'), mono: true },
    { key: 'array', label: t('fields.array'), align: 'center', render: (d) => flag(d.array) },
    { key: 'record_types', label: t('fields.recordTypes'), mono: true },
  ]

  return (
    <AreaPage
      ns="dhcp"
      page="options"
      icon={SlidersHorizontal}
      family={family}
      onRefresh={options.refetch}
      loading={options.loading}
      actions={
        canWrite && (
          <Button size="sm" onClick={() => setEditing({ option: null })} data-testid="option-create">
            <Plus size={14} />
            {t('options.create')}
          </Button>
        )
      }
    >
      <div className="space-y-4">
        <DataTable
          title={t('options.global')}
          columns={columns}
          rows={items}
          rowKey={(o, i) => `${optionId(o)}-${i}`}
          loading={options.loading}
          error={options.error}
          onRetry={options.refetch}
          clientSort
          emptyTitle={t('options.empty')}
          testId="options-table"
        />
        <DataTable
          title={t('options.definitions')}
          columns={defColumns}
          rows={defs}
          rowKey={(d, i) => `${d.space}-${d.code}-${i}`}
          loading={options.loading}
          emptyTitle={t('options.noDefinitions')}
          dense
          testId="option-defs-table"
        />
      </div>
      {editing && <OptionForm family={family} option={editing.option} existing={items} flow={flow} onClose={() => setEditing(null)} />}
      {flow.modal}
    </AreaPage>
  )
}

function OptionForm({ family, option, existing, flow, onClose }) {
  const { t } = useTranslation(['dhcp', 'common'])
  const isNew = !option
  const [form, setForm] = useState({
    name: option?.name || '',
    code: option?.code ?? '',
    space: option?.space || optionSpace(family),
    data: option?.data || '',
    csv_format: option?.csv_format ?? true,
    always_send: option?.always_send ?? false,
    never_send: option?.never_send ?? false,
  })
  const [errors, setErrors] = useState({})
  const set = (key) => (value) => setForm((f) => ({ ...f, [key]: value?.target ? value.target.value : value }))

  const submit = async () => {
    const e = {}
    if (!form.name && form.code === '') e.name = t('form.nameOrCode')
    if (form.code !== '' && !/^\d+$/.test(String(form.code))) e.code = t('form.positiveInteger')
    if (isNew && existing.some((o) => (form.name && o.name === form.name) || (form.code !== '' && o.code === Number(form.code)))) e.name = t('form.nameTaken')
    setErrors(e)
    if (Object.keys(e).length) return
    const after = {
      ...(option || { raw: {} }),
      name: form.name || null,
      code: form.code === '' ? null : Number(form.code),
      space: form.space,
      data: form.data,
      csv_format: form.csv_format,
      always_send: form.always_send,
      never_send: form.never_send,
    }
    try {
      const plan = await flow.build(
        () => api.dhcp.optionsPlan(family, [{ op: isNew ? 'add' : 'replace', target: optionTarget(after, family), before: option || null, after }]),
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
      title={isNew ? t('options.createTitle') : t('options.editTitle', { name: optionId(option) })}
      onSubmit={submit}
      submitLabel={t('form.preview')}
      loading={flow.building}
      testId="option-form"
    >
      <div className="grid gap-3 sm:grid-cols-[1fr_100px_120px]">
        <Input label={t('fields.name')} value={form.name} onChange={set('name')} error={errors.name} placeholder="domain-name-servers" data-testid="option-name" />
        <Input label={t('fields.code')} value={form.code} onChange={set('code')} error={errors.code} />
        <Input label={t('fields.space')} value={form.space} onChange={set('space')} />
      </div>
      <Input label={t('fields.data')} value={form.data} onChange={set('data')} placeholder={family === 'v6' ? '2001:db8::53' : '192.0.2.53, 192.0.2.54'} data-testid="option-data" />
      <div className="flex flex-wrap gap-4">
        <Checkbox label={t('fields.csvFormat')} checked={form.csv_format} onChange={set('csv_format')} />
        <Checkbox label={t('fields.alwaysSend')} checked={form.always_send} onChange={set('always_send')} />
        <Checkbox label={t('fields.neverSend')} checked={form.never_send} onChange={set('never_send')} />
      </div>
      {errors._form && <p className="text-xs status-danger-text">{errors._form}</p>}
    </FormModal>
  )
}
