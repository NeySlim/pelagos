// SPDX-License-Identifier: Apache-2.0
// The HA relationships of a family: per relationship a mode, then one row per Kea server (name,
// URL of its ha listener, role, the cluster node that runs it), any number of backups next to the
// pair. Kea 3 hub and spoke: more relationships, a node running a server in each under its own
// name and URL. The plan writes the hook on every node, each server under its own name.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Plus, Trash, TreeStructure } from '@phosphor-icons/react'
import { Button } from '../../components/Button'
import { FormModal } from '../../components/FormModal'
import { Input } from '../../components/Input'
import { api } from '../../services/api'
import { NativeSelect } from './ui'
import { MODES, MODE_ROLES, addRelationship, relPrefix, setupRequest, validateSetup, withMode } from './haSetup'

export function HaSetupModal({ family, initial, nodes, flow, onClose, title }) {
  const { t } = useTranslation(['dhcp', 'common'])
  const [draft, setDraft] = useState(initial)
  const [errors, setErrors] = useState({})
  const engine = family === 'v6' ? 'kea6' : 'kea4'
  const dhcpNodes = (nodes || []).filter((n) => n.peer?.modules?.[engine] !== false)
  const term = (value) => t(`common:status.${value}`, { defaultValue: value })
  const several = draft.relationships.length > 1
  const setRel = (r, fn) => setDraft((d) => ({ ...d, relationships: d.relationships.map((rel, j) => (j === r ? fn(rel) : rel)) }))
  const setServer = (r, i, patch) => setRel(r, (rel) => ({ ...rel, servers: rel.servers.map((s, j) => (j === i ? { ...s, ...patch } : s)) }))
  const addServer = (r) => setRel(r, (rel) => ({ ...rel, servers: [...rel.servers, { name: '', url: '', role: 'backup', node_id: '', auto_failover: null }] }))
  const removeServer = (r, i) => setRel(r, (rel) => ({ ...rel, servers: rel.servers.filter((_, j) => j !== i) }))
  const removeRelationship = (r) => setDraft((d) => ({ ...d, relationships: d.relationships.filter((_, j) => j !== r) }))

  const submit = async () => {
    const found = validateSetup(draft)
    setErrors(found)
    if (Object.keys(found).length) return
    try {
      const plan = await flow.build(() => api.dhcp.haSetupPlan(family, setupRequest(draft)), { rethrow: true })
      if (plan) onClose()
    } catch (err) {
      const byField = {}
      for (const e of err?.errors || []) byField[e.field] = e.message
      setErrors({ ...byField, _form: err.message })
    }
  }

  return (
    <FormModal
      open
      onClose={onClose}
      title={title || t('ha.setup.title')}
      onSubmit={submit}
      submitLabel={t('form.preview')}
      loading={flow.building}
      size="xl"
      testId="ha-setup-form"
    >
      <p className="text-xs text-text-secondary">{t('ha.setup.intro')}</p>
      {draft.relationships.map((rel, r) => {
        const at = relPrefix(draft, r)
        const message = (key) => (key ? t(key, { role: term(errors[`${at}role`] || ''), mode: term(rel.mode) }) : undefined)
        const roles = Object.keys(MODE_ROLES[rel.mode] || {})
        return (
          <section key={r} className={several ? 'space-y-3 rounded-lg border border-border p-3' : 'space-y-3'} data-testid="ha-setup-relationship">
            {several && (
              <div className="flex items-center gap-2">
                <span className="text-2xs uppercase tracking-wider text-text-tertiary">{t('ha.setup.relationshipN', { n: r + 1 })}</span>
                <Button type="button" variant="ghost" size="xs" className="ml-auto" onClick={() => removeRelationship(r)} data-testid="ha-setup-remove-relationship">
                  <Trash size={12} />
                  {t('ha.setup.removeRelationship')}
                </Button>
              </div>
            )}
            <div className="grid gap-3 sm:grid-cols-[220px_1fr] items-end">
              <NativeSelect
                label={t('ha.mode')}
                value={rel.mode}
                onChange={(mode) => setRel(r, (cur) => withMode(cur, mode))}
                options={MODES.map((m) => ({ value: m, label: term(m) }))}
                testId="ha-setup-mode"
              />
              <p className="text-2xs text-text-tertiary pb-1.5">{t(`ha.setup.modeHint.${rel.mode}`)}</p>
            </div>
            <div className="space-y-2" data-testid="ha-setup-servers">
              {rel.servers.map((s, i) => (
                <div key={i} className="grid gap-2 sm:grid-cols-[minmax(0,0.8fr)_minmax(0,1.4fr)_minmax(0,0.8fr)_minmax(0,1fr)_auto] items-start rounded-md border border-border p-2" data-testid="ha-setup-server">
                  <Input label={t('fields.server')} value={s.name} onChange={(e) => setServer(r, i, { name: e.target.value })} error={message(errors[`${at}servers[${i}].name`])} data-testid="ha-setup-name" />
                  <Input
                    label={t('ha.setup.url')}
                    value={s.url}
                    onChange={(e) => setServer(r, i, { url: e.target.value })}
                    placeholder="http://192.0.2.11:8001/"
                    error={message(errors[`${at}servers[${i}].url`])}
                    data-testid="ha-setup-url"
                  />
                  <div>
                    <NativeSelect
                      label={t('ha.setup.role')}
                      value={s.role}
                      onChange={(role) => setServer(r, i, { role })}
                      options={roles.map((x) => ({ value: x, label: term(x) }))}
                      testId="ha-setup-role"
                    />
                    {errors[`${at}servers[${i}].role`] && <p className="text-2xs status-danger-text mt-1">{message(errors[`${at}servers[${i}].role`])}</p>}
                  </div>
                  <div>
                    <NativeSelect
                      label={t('fields.node')}
                      value={s.node_id || ''}
                      onChange={(node_id) => setServer(r, i, { node_id })}
                      options={[{ value: '', label: t('ha.setup.noNode') }, ...dhcpNodes.map((n) => ({ value: n.peer.id, label: n.peer.name }))]}
                      testId="ha-setup-node"
                    />
                    {errors[`${at}servers[${i}].node_id`] && <p className="text-2xs status-danger-text mt-1">{message(errors[`${at}servers[${i}].node_id`])}</p>}
                  </div>
                  <Button
                    type="button"
                    variant="ghost"
                    size="xs"
                    className="sm:mt-5"
                    onClick={() => removeServer(r, i)}
                    disabled={rel.servers.length <= 2}
                    aria-label={t('ha.setup.remove', { name: s.name || i + 1 })}
                    data-testid="ha-setup-remove"
                  >
                    <Trash size={13} />
                  </Button>
                </div>
              ))}
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <Button type="button" variant="secondary" size="xs" onClick={() => addServer(r)} data-testid="ha-setup-add">
                <Plus size={12} />
                {t('ha.setup.addBackup')}
              </Button>
              <span className="text-2xs text-text-tertiary">{t('ha.setup.backupHint')}</span>
            </div>
            {errors[`${at}servers`] && (
              <p className="text-xs status-danger-text" data-testid="ha-setup-error">
                {message(errors[`${at}servers`])}
              </p>
            )}
          </section>
        )
      })}
      <div className="flex flex-wrap items-center gap-3 pt-1 border-t border-border">
        <Button type="button" variant="secondary" size="xs" onClick={() => setDraft((d) => addRelationship(d, family))} data-testid="ha-setup-add-relationship">
          <TreeStructure size={12} />
          {t('ha.setup.addRelationship')}
        </Button>
        <span className="text-2xs text-text-tertiary">{t('ha.setup.hubHint')}</span>
      </div>
      {errors.relationships && <p className="text-xs status-danger-text">{errors.relationships}</p>}
      {errors._form && <p className="text-xs status-danger-text">{errors._form}</p>}
    </FormModal>
  )
}
