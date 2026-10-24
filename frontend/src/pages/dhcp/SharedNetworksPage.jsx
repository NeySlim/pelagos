// SPDX-License-Identifier: Apache-2.0
// Shared networks: one card per network with its link, options and member subnets
// (with their utilization), and the shared network plan form.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { TreeStructure, Plus, ArrowRight } from '@phosphor-icons/react'
import { Button } from '../../components/Button'
import { Card } from '../../components/Card'
import { EmptyState } from '../../components/EmptyState'
import { FormModal } from '../../components/FormModal'
import { Input } from '../../components/Input'
import { LoadingSpinner } from '../../components/LoadingSpinner'
import { UtilizationBar } from '../../components/UtilizationBar'
import { useApi } from '../../hooks/useApi'
import { usePermission } from '../../hooks/usePermission'
import { api } from '../../services/api'
import { AreaPage, OptionChips, RowActions, SectionError, TextArea, UserContextView } from './ui'
import { usePlanFlow } from './hooks'
import { NOTE_KEY, fieldErrors, optionsToText, splitList, textToOptions, withNote } from './lib'

export default function SharedNetworksPage({ family }) {
  const { t } = useTranslation(['dhcp', 'common'])
  const navigate = useNavigate()
  const { hasPermission } = usePermission()
  const canWrite = hasPermission('write:dhcp.subnets')
  const networks = useApi(() => api.dhcp.sharedNetworks(family), [family])
  const subnets = useApi(() => api.dhcp.subnets(family), [family])
  const [editing, setEditing] = useState(null)
  const refresh = () => {
    networks.refetch()
    subnets.refetch()
  }
  const flow = usePlanFlow({ onApplied: refresh })
  const usage = subnets.data?.utilization || {}
  const items = networks.data?.items || []

  const remove = (network) =>
    flow.build(() => api.dhcp.sharedNetworkPlan(family, { op: 'delete', target: `shared-networks/${network.name}`, before: network, after: null }))

  return (
    <AreaPage
      ns="dhcp"
      page="sharedNetworks"
      icon={TreeStructure}
      family={family}
      onRefresh={refresh}
      loading={networks.loading}
      actions={
        canWrite && (
          <Button size="sm" onClick={() => setEditing({ network: null })} data-testid="network-create">
            <Plus size={14} />
            {t('sharedNetworks.create')}
          </Button>
        )
      }
    >
      <div className="space-y-4">
        <SectionError error={networks.error} onRetry={networks.refetch} />
        {networks.loading && !networks.data && (
          <div className="flex justify-center py-10">
            <LoadingSpinner size="md" />
          </div>
        )}
        {!networks.loading && !networks.error && items.length === 0 && (
          <EmptyState icon={TreeStructure} title={t('sharedNetworks.empty')} description={t('sharedNetworks.emptyHint')} />
        )}
        <div className="grid gap-4 lg:grid-cols-2" data-testid="network-list">
          {items.map((n) => (
            <Card key={n.name} className="p-0 overflow-hidden" hover={false} data-testid="network-card">
              <div className="flex items-center gap-2 px-3 py-2 border-b border-border section-header-gradient">
                <TreeStructure size={16} className="text-accent-pro" />
                <span className="text-sm font-semibold text-text-primary">{n.name}</span>
                <span className="text-xs text-text-tertiary font-mono">{n.interface || (n.relay?.length ? n.relay.join(', ') : '')}</span>
                <span className="ml-auto">
                  {canWrite && (
                    <RowActions
                      editLabel={t('common:actions.edit')}
                      deleteLabel={t('common:actions.delete')}
                      onEdit={() => setEditing({ network: n })}
                      onDelete={() => remove(n)}
                    />
                  )}
                </span>
              </div>
              <div className="p-3 space-y-3 text-xs">
                <div>
                  <h4 className="text-2xs uppercase tracking-wider text-text-tertiary mb-1">{t('fields.options')}</h4>
                  <OptionChips options={n.options} empty={t('subnets.noOptions')} />
                </div>
                <div>
                  <h4 className="text-2xs uppercase tracking-wider text-text-tertiary mb-1">{t('sharedNetworks.members', { n: n.subnets.length })}</h4>
                  {n.subnets.length === 0 ? (
                    <p className="text-text-tertiary">{t('sharedNetworks.noSubnets')}</p>
                  ) : (
                    <ul className="space-y-1.5">
                      {n.subnets.map((s) => (
                        <li key={s.id} className="grid grid-cols-[1fr_160px] items-center gap-3">
                          <span className="font-mono text-text-primary">{s.subnet}</span>
                          {usage[s.id] ? <UtilizationBar {...usage[s.id]} size="sm" /> : <span className="text-text-tertiary">-</span>}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
                {Object.keys(n.user_context || {}).length > 0 && <UserContextView context={n.user_context} />}
                <Button variant="ghost" size="xs" onClick={() => navigate(`/dhcp/${family}/subnets?shared_network=${encodeURIComponent(n.name)}`)}>
                  {t('sharedNetworks.openSubnets')}
                  <ArrowRight size={12} />
                </Button>
              </div>
            </Card>
          ))}
        </div>
      </div>
      {editing && <NetworkForm family={family} network={editing.network} existing={items} flow={flow} onClose={() => setEditing(null)} />}
      {flow.modal}
    </AreaPage>
  )
}

function NetworkForm({ family, network, existing, flow, onClose }) {
  const { t } = useTranslation(['dhcp', 'common'])
  const isNew = !network
  const [form, setForm] = useState({
    name: network?.name || '',
    interface: network?.interface || '',
    relay: (network?.relay || []).join(', '),
    options: optionsToText(network?.options),
    note: network?.user_context?.[NOTE_KEY] || '',
  })
  const [errors, setErrors] = useState({})
  const set = (key) => (value) => setForm((f) => ({ ...f, [key]: value?.target ? value.target.value : value }))

  const submit = async () => {
    const e = {}
    if (!/^[A-Za-z0-9_.-]+$/.test(form.name)) e.name = t('form.badName')
    else if (isNew && existing.some((n) => n.name === form.name)) e.name = t('form.nameTaken')
    setErrors(e)
    if (Object.keys(e).length) return
    // Member subnets are managed from the subnet form, so they are not sent here.
    const { subnets: _subnets, ...base } = network || { family, raw: {}, user_context: {} }
    const after = {
      ...base,
      name: form.name,
      family,
      interface: form.interface.trim() || null,
      relay: splitList(form.relay),
      options: textToOptions(form.options, family, network?.options),
      user_context: withNote(network?.user_context, form.note.trim()),
    }
    try {
      const plan = await flow.build(
        () => api.dhcp.sharedNetworkPlan(family, { op: isNew ? 'add' : 'replace', target: `shared-networks/${form.name}`, before: network || null, after }),
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
      title={isNew ? t('sharedNetworks.createTitle') : t('sharedNetworks.editTitle', { name: network.name })}
      onSubmit={submit}
      submitLabel={t('form.preview')}
      loading={flow.building}
      testId="network-form"
    >
      <Input label={t('fields.name')} value={form.name} onChange={set('name')} disabled={!isNew} error={errors.name} required data-testid="network-name" />
      <div className="grid gap-3 sm:grid-cols-2">
        <Input label={t('fields.interface')} value={form.interface} onChange={set('interface')} placeholder="eth2" />
        <Input label={t('fields.relay')} value={form.relay} onChange={set('relay')} helperText={t('form.commaSeparated')} />
      </div>
      <TextArea label={t('fields.options')} hint={t('form.optionHint')} value={form.options} onChange={set('options')} />
      <Input label={t('fields.note')} value={form.note} onChange={set('note')} helperText={t('form.noteHint')} />
      {errors._form && <p className="text-xs status-danger-text">{errors._form}</p>}
    </FormModal>
  )
}
