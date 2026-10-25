// SPDX-License-Identifier: Apache-2.0
// The HA relationship of a family: mode, then one row per Kea server (name, URL of its ha
// listener, role, the cluster node that runs it). Any number of backups next to the pair.
// The plan writes the hook on every node of the relationship, each under its own name.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Plus, Trash } from '@phosphor-icons/react'
import { Button } from '../../components/Button'
import { FormModal } from '../../components/FormModal'
import { Input } from '../../components/Input'
import { api } from '../../services/api'
import { NativeSelect } from './ui'
import { MODES, MODE_ROLES, setupBody, validateHaSetup, withMode } from './haSetup'

export function HaSetupModal({ family, initial, nodes, flow, onClose, title }) {
  const { t } = useTranslation(['dhcp', 'common'])
  const [draft, setDraft] = useState(initial)
  const [errors, setErrors] = useState({})
  const engine = family === 'v6' ? 'kea6' : 'kea4'
  const dhcpNodes = (nodes || []).filter((n) => n.peer?.modules?.[engine] !== false)
  const term = (value) => t(`common:status.${value}`, { defaultValue: value })
  const setServer = (i, patch) => setDraft((d) => ({ ...d, servers: d.servers.map((s, j) => (j === i ? { ...s, ...patch } : s)) }))
  const addServer = () =>
    setDraft((d) => ({ ...d, servers: [...d.servers, { name: '', url: '', role: 'backup', node_id: '', auto_failover: null }] }))
  const removeServer = (i) => setDraft((d) => ({ ...d, servers: d.servers.filter((_, j) => j !== i) }))

  const submit = async () => {
    const found = validateHaSetup(draft)
    setErrors(found)
    if (Object.keys(found).length) return
    try {
      const plan = await flow.build(() => api.dhcp.haSetupPlan(family, setupBody(draft)), { rethrow: true })
      if (plan) onClose()
    } catch (err) {
      const byField = {}
      for (const e of err?.errors || []) byField[e.field] = e.message
      setErrors({ ...byField, _form: err.message })
    }
  }

  const message = (key) => (key ? t(key, { role: term(errors.role || ''), mode: term(draft.mode) }) : undefined)
  const roles = Object.keys(MODE_ROLES[draft.mode] || {})

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
      <div className="grid gap-3 sm:grid-cols-[220px_1fr] items-end">
        <NativeSelect
          label={t('ha.mode')}
          value={draft.mode}
          onChange={(mode) => setDraft((d) => withMode(d, mode))}
          options={MODES.map((m) => ({ value: m, label: term(m) }))}
          testId="ha-setup-mode"
        />
        <p className="text-2xs text-text-tertiary pb-1.5">{t(`ha.setup.modeHint.${draft.mode}`)}</p>
      </div>
      <div className="space-y-2" data-testid="ha-setup-servers">
        {draft.servers.map((s, i) => (
          <div key={i} className="grid gap-2 sm:grid-cols-[minmax(0,0.8fr)_minmax(0,1.4fr)_minmax(0,0.8fr)_minmax(0,1fr)_auto] items-start rounded-md border border-border p-2" data-testid="ha-setup-server">
            <Input label={t('fields.server')} value={s.name} onChange={(e) => setServer(i, { name: e.target.value })} error={message(errors[`servers[${i}].name`])} data-testid="ha-setup-name" />
            <Input
              label={t('ha.setup.url')}
              value={s.url}
              onChange={(e) => setServer(i, { url: e.target.value })}
              placeholder="http://192.0.2.11:8001/"
              error={message(errors[`servers[${i}].url`])}
              data-testid="ha-setup-url"
            />
            <div>
              <NativeSelect
                label={t('ha.setup.role')}
                value={s.role}
                onChange={(role) => setServer(i, { role })}
                options={roles.map((r) => ({ value: r, label: term(r) }))}
                testId="ha-setup-role"
              />
              {errors[`servers[${i}].role`] && <p className="text-2xs status-danger-text mt-1">{message(errors[`servers[${i}].role`])}</p>}
            </div>
            <div>
              <NativeSelect
                label={t('fields.node')}
                value={s.node_id || ''}
                onChange={(node_id) => setServer(i, { node_id })}
                options={[{ value: '', label: t('ha.setup.noNode') }, ...dhcpNodes.map((n) => ({ value: n.peer.id, label: n.peer.name }))]}
                testId="ha-setup-node"
              />
              {errors[`servers[${i}].node_id`] && <p className="text-2xs status-danger-text mt-1">{message(errors[`servers[${i}].node_id`])}</p>}
            </div>
            <Button
              type="button"
              variant="ghost"
              size="xs"
              className="sm:mt-5"
              onClick={() => removeServer(i)}
              disabled={draft.servers.length <= 2}
              aria-label={t('ha.setup.remove', { name: s.name || i + 1 })}
              data-testid="ha-setup-remove"
            >
              <Trash size={13} />
            </Button>
          </div>
        ))}
      </div>
      <div className="flex flex-wrap items-center gap-3">
        <Button type="button" variant="secondary" size="xs" onClick={addServer} data-testid="ha-setup-add">
          <Plus size={12} />
          {t('ha.setup.addBackup')}
        </Button>
        <span className="text-2xs text-text-tertiary">{t('ha.setup.backupHint')}</span>
      </div>
      {errors.servers && (
        <p className="text-xs status-danger-text" data-testid="ha-setup-error">
          {message(errors.servers)}
        </p>
      )}
      {errors._form && <p className="text-xs status-danger-text">{errors._form}</p>}
    </FormModal>
  )
}
