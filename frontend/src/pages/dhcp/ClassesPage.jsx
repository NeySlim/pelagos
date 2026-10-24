// SPDX-License-Identifier: Apache-2.0
// Client classes: test expression, class options, boot fields, and the class plan form.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Tag, Plus } from '@phosphor-icons/react'
import { DataTable } from '../../components/DataTable'
import { Badge } from '../../components/Badge'
import { Button } from '../../components/Button'
import { FormModal } from '../../components/FormModal'
import { Input } from '../../components/Input'
import { useApi } from '../../hooks/useApi'
import { usePermission } from '../../hooks/usePermission'
import { api } from '../../services/api'
import { AreaPage, Checkbox, OptionChips, RowActions, TextArea } from './ui'
import { usePlanFlow } from './hooks'
import { NOTE_KEY, fieldErrors, optionsToText, textToOptions, withNote } from './lib'

export default function ClassesPage({ family }) {
  const { t } = useTranslation(['dhcp', 'common'])
  const { hasPermission } = usePermission()
  const canWrite = hasPermission('write:dhcp.classes')
  const classes = useApi(() => api.dhcp.clientClasses(family), [family])
  const [editing, setEditing] = useState(null)
  const flow = usePlanFlow({ onApplied: classes.refetch })
  const items = classes.data?.items || []

  const remove = (c) => flow.build(() => api.dhcp.clientClassPlan(family, { op: 'delete', target: `client-classes/${c.name}`, before: c, after: null }))

  const columns = [
    { key: 'name', label: t('fields.name'), sortable: true, render: (c) => <Badge variant="violet" size="sm">{c.name}</Badge> },
    { key: 'test', label: t('fields.test'), mono: true, truncate: true },
    { key: 'options', label: t('fields.options'), render: (c) => <OptionChips options={c.options} /> },
    {
      key: 'only_in_additional_list',
      label: t('fields.additionalOnly'),
      align: 'center',
      render: (c) => (c.only_in_additional_list ? <Badge variant="warning" size="sm">{t('common:common.yes')}</Badge> : ''),
    },
    ...(family === 'v4'
      ? [{ key: 'boot', label: t('fields.boot'), mono: true, render: (c) => [c.next_server, c.boot_file_name].filter(Boolean).join(' / ') }]
      : []),
    { key: 'note', label: t('fields.note'), truncate: true, render: (c) => c.user_context?.[NOTE_KEY] || '' },
    ...(canWrite
      ? [{
          key: 'actions',
          label: '',
          align: 'right',
          render: (c) => (
            <RowActions editLabel={t('common:actions.edit')} deleteLabel={t('common:actions.delete')} onEdit={() => setEditing({ cls: c })} onDelete={() => remove(c)} />
          ),
        }]
      : []),
  ]

  return (
    <AreaPage
      ns="dhcp"
      page="classes"
      icon={Tag}
      family={family}
      onRefresh={classes.refetch}
      loading={classes.loading}
      actions={
        canWrite && (
          <Button size="sm" onClick={() => setEditing({ cls: null })} data-testid="class-create">
            <Plus size={14} />
            {t('classes.create')}
          </Button>
        )
      }
    >
      <DataTable
        columns={columns}
        rows={items}
        rowKey="name"
        loading={classes.loading}
        error={classes.error}
        onRetry={classes.refetch}
        clientSort
        emptyTitle={t('classes.empty')}
        emptyIcon={Tag}
        testId="classes-table"
      />
      {editing && <ClassForm family={family} cls={editing.cls} existing={items} flow={flow} onClose={() => setEditing(null)} />}
      {flow.modal}
    </AreaPage>
  )
}

function ClassForm({ family, cls, existing, flow, onClose }) {
  const { t } = useTranslation(['dhcp', 'common'])
  const isNew = !cls
  const [form, setForm] = useState({
    name: cls?.name || '',
    test: cls?.test || '',
    only_in_additional_list: Boolean(cls?.only_in_additional_list),
    options: optionsToText(cls?.options),
    next_server: cls?.next_server || '',
    server_hostname: cls?.server_hostname || '',
    boot_file_name: cls?.boot_file_name || '',
    note: cls?.user_context?.[NOTE_KEY] || '',
  })
  const [errors, setErrors] = useState({})
  const set = (key) => (value) => setForm((f) => ({ ...f, [key]: value?.target ? value.target.value : value }))

  const submit = async () => {
    const e = {}
    if (!/^[A-Za-z0-9_.:-]+$/.test(form.name)) e.name = t('form.badName')
    else if (isNew && existing.some((c) => c.name === form.name)) e.name = t('form.nameTaken')
    setErrors(e)
    if (Object.keys(e).length) return
    const after = {
      ...(cls || { option_def: [], raw: {}, user_context: {} }),
      name: form.name,
      test: form.test.trim() || null,
      only_in_additional_list: form.only_in_additional_list,
      options: textToOptions(form.options, family, cls?.options),
      next_server: family === 'v4' ? form.next_server.trim() || null : null,
      server_hostname: family === 'v4' ? form.server_hostname.trim() || null : null,
      boot_file_name: family === 'v4' ? form.boot_file_name.trim() || null : null,
      user_context: withNote(cls?.user_context, form.note.trim()),
    }
    try {
      const plan = await flow.build(
        () => api.dhcp.clientClassPlan(family, { op: isNew ? 'add' : 'replace', target: `client-classes/${after.name}`, before: cls || null, after }),
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
      title={isNew ? t('classes.createTitle') : t('classes.editTitle', { name: cls.name })}
      onSubmit={submit}
      submitLabel={t('form.preview')}
      loading={flow.building}
      size="lg"
      testId="class-form"
    >
      <Input label={t('fields.name')} value={form.name} onChange={set('name')} disabled={!isNew} error={errors.name} required data-testid="class-name" />
      <TextArea label={t('fields.test')} hint={t('form.testHint')} value={form.test} onChange={set('test')} rows={2} placeholder="option[60].text == 'PXEClient'" testId="class-test" />
      <Checkbox label={t('fields.additionalOnly')} checked={form.only_in_additional_list} onChange={set('only_in_additional_list')} />
      <TextArea label={t('fields.options')} hint={t('form.optionHint')} value={form.options} onChange={set('options')} />
      {family === 'v4' && (
        <div className="grid gap-3 sm:grid-cols-3">
          <Input label={t('fields.nextServer')} value={form.next_server} onChange={set('next_server')} />
          <Input label={t('fields.serverHostname')} value={form.server_hostname} onChange={set('server_hostname')} />
          <Input label={t('fields.bootFileName')} value={form.boot_file_name} onChange={set('boot_file_name')} />
        </div>
      )}
      <Input label={t('fields.note')} value={form.note} onChange={set('note')} helperText={t('form.noteHint')} />
      {errors._form && <p className="text-xs status-danger-text">{errors._form}</p>}
    </FormModal>
  )
}
