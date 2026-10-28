// SPDX-License-Identifier: Apache-2.0
// One archive destination: another node, a folder the administrator mounts, or an SFTP server
// with a pinned host key. The SSH key is typed here and sent once; the form only shows whether one
// is stored and can clear it. "Test" writes, reads back and deletes a probe file from this node.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Plugs, Trash } from '@phosphor-icons/react'
import { FormModal, Input, Textarea, Select, ToggleSwitch, Button } from '../../../components'
import { api } from '../../../services/api'
import { errorMessage } from '../../../services/apiClient'
import { useNotification } from '../../../contexts/NotificationContext'
import { DESTINATION_TYPES, destinationBody, destinationErrors, destinationParams, formFromDestination, serverFieldErrors, serverMoved } from './archivesForm'

export function TestResult({ result, testId = 'archives-dest-test-result' }) {
  const { t } = useTranslation('archives')
  if (!result) return null
  return (
    <div role="status" className="space-y-0.5" data-testid={testId} data-ok={String(Boolean(result.ok))}>
      <p className={result.ok ? 'text-xs status-success-text' : 'text-xs status-danger-text break-words'}>
        {result.ok ? t('test.ok') : t('test.failed', { error: result.error || '-' })}
      </p>
      {(result.targets || []).length > 1 && (
        <ul className="text-2xs text-text-secondary">
          {result.targets.map((x) => (
            <li key={x.label}>{x.ok ? '✓' : '✗'} {x.label}{x.error ? `: ${x.error}` : ''}{x.note ? ` (${x.note})` : ''}</li>
          ))}
        </ul>
      )}
    </div>
  )
}

export default function DestinationDialog({ open, onClose, destination, nodes = [], onSaved }) {
  const { t } = useTranslation(['archives', 'common'])
  const { showError } = useNotification()
  const editing = Boolean(destination?.id)
  const [form, setForm] = useState(() => formFromDestination(destination || {}))
  const [touched, setTouched] = useState(false)
  const [server, setServer] = useState({})
  const [busy, setBusy] = useState(false)
  const [testing, setTesting] = useState(false)
  const [result, setResult] = useState(null)
  const set = (patch) => {
    setForm((f) => ({ ...f, ...patch }))
    setServer({})
    setResult(null)
  }
  const local = destinationErrors(form, destination)
  const errors = touched ? { ...local, ...server } : server
  const err = (field) => {
    const v = errors[field]
    if (!v) return undefined
    return t(`errors.${v}`, { defaultValue: v })
  }

  const submit = async () => {
    setTouched(true)
    if (Object.keys(local).length) return
    setBusy(true)
    try {
      const body = destinationBody(form, { editing })
      const saved = editing ? await api.archives.updateDestination(destination.id, body) : await api.archives.createDestination(body)
      onSaved(saved)
    } catch (e) {
      const fields = serverFieldErrors(e)
      if (Object.keys(fields).length) setServer(fields)
      else showError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  const test = async () => {
    setTesting(true)
    const body = { type: form.type, name: form.name.trim() || 'test', params: destinationParams(form) }
    if (editing) body.scope = destination.id
    if (form.type === 'sftp' && form.sshKey.trim()) body.secrets = { ssh_key: form.sshKey }
    const out = await api.archives.testDestination(body).catch((e) => ({ ok: false, error: errorMessage(e) }))
    setResult(out)
    setTesting(false)
  }

  const nodeToggle = (id) => set({ nodeIds: form.nodeIds.includes(id) ? form.nodeIds.filter((x) => x !== id) : [...form.nodeIds, id] })
  const moved = serverMoved(form, destination)
  return (
    <FormModal
      open={open}
      onClose={onClose}
      title={editing ? t('dest.editTitle', { name: destination.name }) : t('dest.addTitle')}
      onSubmit={submit}
      loading={busy}
      size="lg"
      testId="archives-dest-dialog"
    >
      {!editing && (
        <Select
          label={t('dest.type')}
          value={form.type}
          onChange={(type) => set({ type })}
          options={DESTINATION_TYPES.map((v) => ({ value: v, label: t(`types.${v}`) }))}
          id="archives-dest-type"
        />
      )}
      <p className="text-2xs text-text-tertiary">{t(`dest.help.${form.type}`)}</p>
      <Input label={t('dest.name')} value={form.name} onChange={(e) => set({ name: e.target.value })} error={err('name')} data-testid="archives-dest-name" />
      {form.type === 'peer' && (
        <div className="space-y-1" data-testid="archives-dest-nodes">
          <span className="block text-xs font-medium text-text-secondary">{t('dest.nodes')}</span>
          <div className="flex flex-wrap gap-1.5">
            {nodes.map((n) => (
              <button
                key={n.id}
                type="button"
                aria-pressed={form.nodeIds.includes(n.id)}
                onClick={() => nodeToggle(n.id)}
                className={`px-2 py-0.5 rounded-md border text-xs ${form.nodeIds.includes(n.id) ? 'border-accent-primary bg-accent-primary-op15 text-text-primary' : 'border-border text-text-secondary hover:bg-bg-tertiary'}`}
              >
                {n.name}
              </button>
            ))}
          </div>
          <p className="text-2xs text-text-tertiary">{t('dest.nodesHelp')}</p>
          {err('nodeIds') && <p className="text-2xs status-danger-text">{err('nodeIds')}</p>}
        </div>
      )}
      {form.type === 'mounted' && (
        <Input label={t('dest.path')} value={form.path} onChange={(e) => set({ path: e.target.value })} placeholder="/mnt/backup/pelagos" error={err('path')} helperText={t('dest.mountedHelp')} data-testid="archives-dest-path" />
      )}
      {form.type === 'sftp' && (
        <>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <Input className="sm:col-span-2" label={t('dest.host')} value={form.host} onChange={(e) => set({ host: e.target.value })} placeholder="backup.example.lan" error={err('host')} data-testid="archives-dest-host" />
            <Input label={t('dest.port')} value={form.port} onChange={(e) => set({ port: e.target.value })} inputMode="numeric" error={err('port')} data-testid="archives-dest-port" />
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <Input label={t('dest.username')} value={form.username} onChange={(e) => set({ username: e.target.value })} error={err('username')} data-testid="archives-dest-username" />
            <Input label={t('dest.remotePath')} value={form.path} onChange={(e) => set({ path: e.target.value })} placeholder="archives" error={err('path')} data-testid="archives-dest-path" />
          </div>
          <Input label={t('dest.fingerprint')} value={form.fingerprint} onChange={(e) => set({ fingerprint: e.target.value })} placeholder="SHA256:..." error={err('fingerprint')} helperText={t('dest.fingerprintHelp')} data-testid="archives-dest-fingerprint" />
          <div className="space-y-1">
            <Textarea
              label={form.keyStored && !form.clearKey && !moved ? t('dest.sshKeyStored') : t('dest.sshKey')}
              value={form.sshKey}
              onChange={(e) => set({ sshKey: e.target.value })}
              rows={4}
              placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
              error={err('sshKey')}
              className="font-mono text-2xs"
              spellCheck={false}
              autoComplete="off"
              data-testid="archives-dest-key"
            />
            <p className="text-2xs text-text-tertiary">{t('dest.sshKeyHelp')}</p>
            {form.keyStored && !form.sshKey && (
              <Button size="xs" variant="ghost" onClick={() => set({ clearKey: !form.clearKey })} data-testid="archives-dest-key-clear">
                <Trash size={12} />
                {form.clearKey ? t('dest.keyUndoClear') : t('dest.keyClear')}
              </Button>
            )}
          </div>
        </>
      )}
      <div className="space-y-2">
        <ToggleSwitch checked={form.customKeep} onChange={(customKeep) => set({ customKeep })} label={t('dest.customKeep')} description={t('dest.customKeepHelp')} size="sm" />
        {form.customKeep && (
          <div className="grid grid-cols-3 gap-3" data-testid="archives-dest-keep">
            {['daily', 'weekly', 'monthly'].map((k) => (
              <Input key={k} label={t(`dest.keep.${k}`)} value={form.keep[k]} onChange={(e) => set({ keep: { ...form.keep, [k]: e.target.value } })} inputMode="numeric" error={err(`keep.${k}`)} />
            ))}
          </div>
        )}
      </div>
      <ToggleSwitch checked={form.enabled} onChange={(enabled) => set({ enabled })} label={t('dest.enabled')} size="sm" />
      <div className="flex flex-wrap items-center gap-2 border-t border-border pt-3">
        <Button size="sm" variant="secondary" onClick={test} loading={testing} disabled={Object.keys(local).some((k) => k !== 'sshKey' && k !== 'name')} data-testid="archives-dest-test">
          <Plugs size={14} />
          {t('actions.test')}
        </Button>
        <span className="text-2xs text-text-tertiary flex-1 min-w-0">{t('test.help')}</span>
      </div>
      <TestResult result={result} />
    </FormModal>
  )
}
