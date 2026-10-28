// SPDX-License-Identifier: Apache-2.0
// Administration > Backups (architecture section 23): the archive key (the cluster identity, shown
// once, and operator keys), each node's last and next archive, schedule and retention, the
// destinations with their test, the archives every node holds (download, upload) and the restore
// wizard. Scheduling stays refused until a key exists.
import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  Archive, Key, Plus, PencilSimple, Trash, Pause, Play, Plugs, DownloadSimple, UploadSimple, ClockCounterClockwise,
  ArrowsClockwise, Warning, Copy, Broom, ShieldCheck,
} from '@phosphor-icons/react'
import {
  PageLayout, Card, Button, Badge, LoadingSpinner, ConfirmDialog, DataTable, FormModal, Modal, Input, Textarea, ToggleSwitch, StatusBadge,
} from '../../../components'
import { useApi, usePaginatedApi, useWsTopic } from '../../../hooks'
import { useNotification } from '../../../contexts/NotificationContext'
import { api } from '../../../services/api'
import { errorMessage } from '../../../services/apiClient'
import { downloadBlob, formatDate } from '../../../lib/utils'
import DestinationDialog, { TestResult } from './DestinationDialog'
import RestoreWizard from './RestoreWizard'
import { RECIPIENT_RE, SETTING_GROUPS, destinationTarget, formatBytes, settingsChanges, settingsErrors, settingsForm } from './archivesForm'

function Field({ label, children, testId }) {
  return (
    <div className="min-w-0" data-testid={testId}>
      <dt className="text-2xs uppercase tracking-wider text-text-tertiary">{label}</dt>
      <dd className="text-sm text-text-primary break-words">{children}</dd>
    </div>
  )
}

function CardTitle({ icon: Icon, children, actions }) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      {Icon && <Icon size={16} className="text-text-tertiary" />}
      <h3 className="ui-card-title text-sm font-semibold text-text-primary flex-1 min-w-0">{children}</h3>
      {actions}
    </div>
  )
}

// The cluster identity, once: copy it or save it as a file before closing.
function IdentityOnce({ identity, onClose }) {
  const { t } = useTranslation('archives')
  const [saved, setSaved] = useState(false)
  const copy = () => navigator.clipboard?.writeText(identity).catch(() => {})
  const save = () => downloadBlob(new Blob([`${identity}\n`], { type: 'text/plain' }), 'pelagos-archive-identity.txt')
  return (
    <Modal open onClose={saved ? onClose : undefined} title={t('key.onceTitle')} size="md">
      <div className="p-4 space-y-3" data-testid="archives-identity-once">
        <p role="alert" className="text-xs status-danger-text font-semibold">{t('key.onceWarning')}</p>
        <pre className="font-mono text-2xs bg-bg-tertiary rounded-md p-2 break-all whitespace-pre-wrap select-all" data-testid="archives-identity-value">{identity}</pre>
        <div className="flex flex-wrap gap-2">
          <Button size="sm" variant="secondary" onClick={copy}><Copy size={14} />{t('key.copy')}</Button>
          <Button size="sm" variant="secondary" onClick={save}><DownloadSimple size={14} />{t('key.saveFile')}</Button>
        </div>
        <label className="flex items-start gap-2 text-xs">
          <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} data-testid="archives-identity-saved" />
          <span>{t('key.savedAck')}</span>
        </label>
        <div className="flex justify-end">
          <Button size="sm" disabled={!saved} onClick={onClose} data-testid="archives-identity-close">{t('key.done')}</Button>
        </div>
      </div>
    </Modal>
  )
}

function PasswordDialog({ op, onClose, onDone }) {
  const { t } = useTranslation(['archives', 'common'])
  const [password, setPassword] = useState('')
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const submit = async () => {
    setBusy(true)
    setError(null)
    try {
      onDone(await api.archives.identity({ op, password }))
    } catch (e) {
      setError(e.code === 'invalid_credentials' ? t('key.wrongPassword') : errorMessage(e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <FormModal open onClose={onClose} title={t(`key.${op}Title`)} onSubmit={submit} submitLabel={t(`key.${op}`)} loading={busy} disabled={!password} testId="archives-password-dialog">
      <p className="text-xs text-text-secondary">{t(`key.${op}Help`)}</p>
      <Input label={t('key.password')} type="password" value={password} onChange={(e) => setPassword(e.target.value)} error={error} autoComplete="current-password" data-testid="archives-password" />
    </FormModal>
  )
}

function KeyCard({ data, onChanged }) {
  const { t } = useTranslation(['archives', 'common'])
  const { showSuccess, showError } = useNotification()
  const [asking, setAsking] = useState(null) // generate | rotate
  const [shown, setShown] = useState(null)
  const [adding, setAdding] = useState(false)
  const [recipient, setRecipient] = useState('')
  const [label, setLabel] = useState('')
  const [removing, setRemoving] = useState(null)
  const [busy, setBusy] = useState(false)
  const identity = data.identity || {}
  const operators = (data.recipients || []).filter((r) => r.kind === 'operator')
  const cluster = (data.recipients || []).find((r) => r.kind === 'cluster')
  const recipientError = recipient && !RECIPIENT_RE.test(recipient.trim()) ? t('errors.recipient') : null
  const call = async (body, success) => {
    setBusy(true)
    try {
      const out = await api.archives.identity(body)
      if (success) showSuccess(success(out))
      onChanged()
      return out
    } catch (e) {
      showError(errorMessage(e))
      return null
    } finally {
      setBusy(false)
    }
  }
  const add = async () => {
    if (recipientError || !recipient.trim()) return
    if (await call({ op: 'add_recipient', recipient: recipient.trim(), label: label.trim() }, () => t('toast.recipientAdded'))) {
      setAdding(false)
      setRecipient('')
      setLabel('')
    }
  }
  const remove = async () => {
    if (await call({ op: 'remove_recipient', recipient: removing.recipient }, () => t('toast.recipientRemoved'))) setRemoving(null)
  }
  const prune = () => call({ op: 'prune_retired' }, (out) => (out.dropped?.length ? t('toast.pruned', { count: out.dropped.length }) : t('toast.prunedNone', { reason: out.kept_because || '-' })))
  return (
    <Card className="p-4 space-y-3" hover={false} data-testid="archives-key">
      <CardTitle
        icon={Key}
        actions={cluster ? (
          <Button size="sm" variant="secondary" onClick={() => setAsking('rotate')} data-testid="archives-key-rotate"><ArrowsClockwise size={14} />{t('key.rotate')}</Button>
        ) : (
          <Button size="sm" onClick={() => setAsking('generate')} data-testid="archives-key-generate"><Key size={14} />{t('key.generate')}</Button>
        )}
      >
        {t('key.title')}
      </CardTitle>
      {!cluster && !operators.length && (
        <p role="alert" className="text-xs status-danger-text flex items-start gap-1.5" data-testid="archives-no-key"><Warning size={14} className="shrink-0 mt-0.5" />{t('key.none')}</p>
      )}
      {cluster && (
        <dl className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <Field label={t('key.recipient')} testId="archives-key-recipient"><span className="font-mono text-2xs break-all">{cluster.recipient}</span></Field>
          <Field label={t('key.stored')}>{identity.stored ? t('key.storedYes') : t('key.storedNo')}</Field>
          <Field label={t('key.shownAt')}>{cluster.downloaded_at ? formatDate(cluster.downloaded_at) : t('key.never')}</Field>
        </dl>
      )}
      <p className="text-2xs text-text-tertiary">{t('key.help')}</p>
      {identity.retired?.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 text-xs" data-testid="archives-retired">
          <span className="text-text-secondary">{t('key.retired', { count: identity.retired.length })}</span>
          <Button size="xs" variant="ghost" onClick={prune} loading={busy} data-testid="archives-prune"><Broom size={12} />{t('key.prune')}</Button>
        </div>
      )}
      <div className="space-y-1.5">
        <div className="flex items-center gap-2">
          <h4 className="text-xs font-semibold text-text-secondary flex-1">{t('key.operators')}</h4>
          <Button size="xs" variant="ghost" onClick={() => setAdding((a) => !a)} data-testid="archives-recipient-add"><Plus size={12} />{t('key.addOperator')}</Button>
        </div>
        <p className="text-2xs text-text-tertiary">{t('key.operatorsHelp')}</p>
        {operators.map((r) => (
          <div key={r.recipient} className="flex flex-wrap items-center gap-2 text-xs" data-testid="archives-recipient">
            <span className="font-medium">{r.label || '-'}</span>
            <span className="font-mono text-2xs text-text-secondary break-all flex-1 min-w-0">{r.recipient}</span>
            <Button size="xs" variant="ghost" onClick={() => setRemoving(r)} aria-label={t('key.removeOperator', { label: r.label || r.recipient })}><Trash size={12} /></Button>
          </div>
        ))}
        {adding && (
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 items-end" data-testid="archives-recipient-form">
            <Input className="sm:col-span-2" label={t('key.operatorKey')} value={recipient} onChange={(e) => setRecipient(e.target.value)} placeholder="age1..." error={recipientError} data-testid="archives-recipient-key" />
            <Input label={t('key.label')} value={label} onChange={(e) => setLabel(e.target.value)} data-testid="archives-recipient-label" />
            <div className="sm:col-span-3 flex justify-end">
              <Button size="sm" onClick={add} loading={busy} disabled={!recipient.trim() || Boolean(recipientError)} data-testid="archives-recipient-save">{t('key.addOperator')}</Button>
            </div>
          </div>
        )}
      </div>
      {asking && (
        <PasswordDialog
          op={asking}
          onClose={() => setAsking(null)}
          onDone={(out) => {
            setAsking(null)
            setShown(out.identity)
            onChanged()
          }}
        />
      )}
      {shown && <IdentityOnce identity={shown} onClose={() => setShown(null)} />}
      <ConfirmDialog
        open={Boolean(removing)}
        onOpenChange={(o) => !o && setRemoving(null)}
        onConfirm={remove}
        loading={busy}
        title={t('key.removeTitle')}
        message={t('key.removeBody', { label: removing?.label || removing?.recipient })}
        confirmLabel={t('actions.delete')}
      />
    </Card>
  )
}

// The job of "Back up now": one step per node, done when its archive is written.
function RunJob({ job, nameOf, onFinished }) {
  const { t } = useTranslation('archives')
  const [current, setCurrent] = useState(job)
  const finished = useRef(false)
  useWsTopic(current && !['done', 'failed'].includes(current.state) ? 'jobs' : null, (m) => {
    if (m.data?.id === current?.id) setCurrent(m.data)
  })
  useEffect(() => {
    setCurrent(job)
    finished.current = false
  }, [job])
  useEffect(() => {
    if (!current || ['done', 'failed'].includes(current.state)) return undefined
    const timer = setInterval(() => api.jobs.get(current.id).then(setCurrent).catch(() => {}), 2000)
    return () => clearInterval(timer)
  }, [current])
  useEffect(() => {
    if (current && ['done', 'failed'].includes(current.state) && !finished.current) {
      finished.current = true
      onFinished?.(current)
    }
  }, [current, onFinished])
  const steps = (current?.steps || []).filter((s) => s.name.startsWith('archive:'))
  return (
    <div className="rounded-lg border border-border p-3 space-y-1" data-testid="archives-run-job" data-state={current?.state}>
      <div className="flex items-center gap-2 text-xs">
        <StatusBadge status={current?.state} />
        <span className="text-text-secondary">{t('run.progress', { percent: current?.progress ?? 0 })}</span>
      </div>
      {steps.map((s) => (
        <p key={s.name} className="text-xs flex flex-wrap gap-2" data-testid="archives-run-step" data-state={s.state}>
          <span className="font-medium">{s.node_id ? nameOf(s.node_id) : s.name.slice('archive:'.length)}</span>
          <span className={s.state === 'failed' ? 'status-danger-text' : 'text-text-secondary'}>
            {s.state === 'done' ? t('run.made', { size: formatBytes(s.output?.size), complete: s.output?.complete === false ? t('run.incomplete') : '' }) : s.state === 'failed' ? String(s.output || '') : t(`run.state.${s.state}`, { defaultValue: s.state })}
          </span>
        </p>
      ))}
      {current?.error && <p className="text-xs status-danger-text">{current.error}</p>}
    </div>
  )
}

function NodesCard({ nodes, canRun, onRun, running }) {
  const { t } = useTranslation('archives')
  return (
    <Card className="p-4 space-y-3" hover={false} data-testid="archives-nodes">
      <CardTitle icon={ClockCounterClockwise}>{t('nodes.title')}</CardTitle>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        {nodes.map((n) => {
          const failing = n.last_error || Object.values(n.errors || {}).some(Boolean)
          return (
            <div key={n.node_id} className="ui-subpanel border border-border rounded-lg p-3 space-y-2" data-testid="archives-node" data-node={n.node_id}>
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-sm font-semibold">{n.name}</span>
                {!n.reachable ? <Badge variant="secondary" size="sm">{t('nodes.unreachable')}</Badge>
                  : n.running ? <Badge variant="info" size="sm">{t('nodes.running')}</Badge>
                    : failing ? <Badge variant="danger" size="sm">{t('nodes.failing')}</Badge>
                      : n.last_success ? <Badge variant="success" size="sm">{t('nodes.ok')}</Badge>
                        : <Badge variant="secondary" size="sm">{t('nodes.none')}</Badge>}
                {n.complete === false && <Badge variant="warning" size="sm">{t('nodes.incomplete')}</Badge>}
                <Button size="xs" variant="ghost" className="ml-auto" disabled={!canRun || !n.reachable || running} onClick={() => onRun([n.node_id])} data-testid="archives-node-run">
                  <Play size={12} />{t('actions.runOne')}
                </Button>
              </div>
              {n.reachable ? (
                <dl className="grid grid-cols-2 gap-2">
                  <Field label={t('nodes.lastSuccess')}>{n.last_success ? formatDate(n.last_success) : t('nodes.never')}</Field>
                  <Field label={t('nodes.size')}>{formatBytes(n.last_archive?.size)}</Field>
                  <Field label={t('nodes.next')}>{n.next_run ? formatDate(n.next_run) : t('nodes.notScheduled')}</Field>
                  <Field label={t('nodes.testRestore')}>
                    {n.test_restore ? (n.test_restore.ok === false ? <span className="status-danger-text">{t('nodes.testFailed')}</span> : n.test_restore.ok ? t('nodes.testOk', { when: formatDate(n.test_restore.at) }) : t('nodes.testSkipped')) : '-'}
                  </Field>
                </dl>
              ) : (
                <p className="text-xs text-text-tertiary">{n.error}</p>
              )}
              {n.last_error && <p className="text-xs status-danger-text break-words" data-testid="archives-node-error">{n.last_error}</p>}
              {Object.entries(n.errors || {}).filter(([k, v]) => k !== 'local' && v).map(([k, v]) => (
                <p key={k} className="text-xs status-warning-text break-words">{t('nodes.destError', { dest: k, error: v })}</p>
              ))}
              {n.unreadable?.length > 0 && <p className="text-2xs status-warning-text">{t('nodes.unreadable', { files: n.unreadable.slice(0, 5).join(', '), count: n.unreadable.length })}</p>}
            </div>
          )
        })}
      </div>
    </Card>
  )
}

function ScheduleCard({ settings, hasKey, onSaved }) {
  const { t } = useTranslation(['archives', 'common'])
  const { showSuccess, showError } = useNotification()
  const [form, setForm] = useState(() => settingsForm(settings))
  const [server, setServer] = useState({})
  const [busy, setBusy] = useState(false)
  useEffect(() => setForm(settingsForm(settings)), [settings])
  const errors = settingsErrors(form)
  const changes = settingsChanges(form, settings)
  const err = (k) => {
    const e = server[k] || errors[k]
    if (!e) return undefined
    return typeof e === 'string' ? t(`errors.${e}`, { defaultValue: e }) : t(`errors.${e.code}`, e)
  }
  const save = async (patch) => {
    setBusy(true)
    setServer({})
    try {
      await api.archives.updateSettings(patch)
      showSuccess(t('toast.settings'))
      onSaved()
    } catch (e) {
      const fields = Object.fromEntries((e.errors || []).map((x) => [x.field, x.message]))
      if (Object.keys(fields).length) setServer(fields)
      showError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }
  const input = (k) => (
    <Input key={k} label={t(`settings.${k}`)} value={form[k]} onChange={(e) => setForm((f) => ({ ...f, [k]: e.target.value }))} error={err(k)} inputMode={k === 'start_time' ? undefined : 'numeric'} data-testid={`archives-setting-${k}`} />
  )
  return (
    <Card className="p-4 space-y-3" hover={false} data-testid="archives-schedule">
      <CardTitle icon={ClockCounterClockwise}>{t('settings.title')}</CardTitle>
      <div data-testid="archives-schedule-toggle">
        <ToggleSwitch
          checked={Boolean(settings.schedule_enabled)}
          onChange={(on) => save({ schedule_enabled: on })}
          disabled={busy || (!settings.schedule_enabled && !hasKey)}
          label={t('settings.schedule_enabled')}
          description={!hasKey && !settings.schedule_enabled ? t('settings.needKey') : t('settings.scheduleHelp')}
        />
        {server.schedule_enabled && <p className="text-2xs status-danger-text">{t('settings.needKey')}</p>}
      </div>
      {Object.entries(SETTING_GROUPS).map(([group, keys]) => (
        <div key={group} className="space-y-2">
          <h4 className="text-xs font-semibold text-text-secondary">{t(`settings.groups.${group}`)}</h4>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            {keys.map((k) => (typeof form[k] === 'boolean' ? (
              <div key={k} className="pt-5"><ToggleSwitch checked={form[k]} onChange={(v) => setForm((f) => ({ ...f, [k]: v }))} label={t(`settings.${k}`)} size="sm" /></div>
            ) : input(k)))}
          </div>
        </div>
      ))}
      <p className="text-2xs text-text-tertiary">{t('settings.help')}</p>
      {Object.keys(changes).length > 0 && (
        <div className="flex justify-end gap-2">
          <Button size="sm" variant="secondary" onClick={() => setForm(settingsForm(settings))}>{t('common:actions.cancel')}</Button>
          <Button size="sm" loading={busy} disabled={Object.keys(errors).length > 0} onClick={() => save(changes)} data-testid="archives-settings-save">{t('actions.saveSettings')}</Button>
        </div>
      )}
    </Card>
  )
}

function DestinationsCard({ destinations, nodes, nameOf, onChanged }) {
  const { t } = useTranslation(['archives', 'common'])
  const { showSuccess, showError } = useNotification()
  const [editing, setEditing] = useState(null)
  const [deleting, setDeleting] = useState(null)
  const [busy, setBusy] = useState(false)
  const [testing, setTesting] = useState({})
  const [results, setResults] = useState({})
  const test = async (d) => {
    setTesting((s) => ({ ...s, [d.id]: true }))
    const out = await api.archives.testDestination({ destination_id: d.id }).catch((e) => ({ ok: false, error: errorMessage(e) }))
    setTesting((s) => ({ ...s, [d.id]: false }))
    setResults((r) => ({ ...r, [d.id]: out }))
  }
  const toggle = async (d) => {
    try {
      await api.archives.updateDestination(d.id, { enabled: !d.enabled })
      onChanged()
    } catch (e) {
      showError(errorMessage(e))
    }
  }
  const doDelete = async () => {
    setBusy(true)
    try {
      await api.archives.deleteDestination(deleting.id)
      showSuccess(t('toast.destDeleted', { name: deleting.name }))
      setDeleting(null)
      onChanged()
    } catch (e) {
      showError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Card className="p-4 space-y-3" hover={false} data-testid="archives-destinations">
      <CardTitle icon={Archive} actions={<Button size="sm" onClick={() => setEditing({})} data-testid="archives-dest-add"><Plus size={14} />{t('dest.add')}</Button>}>
        {t('dest.title')}
      </CardTitle>
      <p className="text-2xs text-text-tertiary">{t('dest.localHelp')}</p>
      {destinations.length === 0 && <p className="text-xs text-text-secondary" data-testid="archives-dest-empty">{t('dest.empty')}</p>}
      {destinations.map((d) => (
        <div key={d.id} className="ui-subpanel border border-border rounded-lg p-3 space-y-1.5" data-testid="archives-dest" data-dest={d.id}>
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-sm font-semibold">{d.name}</span>
            <Badge variant="info" size="sm">{t(`types.${d.type}`, { defaultValue: d.type })}</Badge>
            {!d.enabled && <Badge variant="secondary" size="sm">{t('dest.disabled')}</Badge>}
            {d.status?.length > 0 && <Badge variant="danger" size="sm">{t('dest.failing')}</Badge>}
            {d.type === 'sftp' && !d.secrets?.ssh_key && <Badge variant="warning" size="sm">{t('dest.noKey')}</Badge>}
            <div className="ml-auto flex flex-wrap gap-1.5">
              <Button size="sm" variant="secondary" onClick={() => test(d)} loading={Boolean(testing[d.id])} data-testid="archives-dest-card-test"><Plugs size={14} />{t('actions.test')}</Button>
              <Button size="sm" variant="secondary" onClick={() => setEditing(d)} data-testid="archives-dest-edit"><PencilSimple size={14} />{t('actions.edit')}</Button>
              <Button size="sm" variant="ghost" onClick={() => toggle(d)} data-testid="archives-dest-toggle">{d.enabled ? <Pause size={14} /> : <Play size={14} />}{d.enabled ? t('actions.disable') : t('actions.enable')}</Button>
              <Button size="sm" variant="ghost" onClick={() => setDeleting(d)} data-testid="archives-dest-delete"><Trash size={14} />{t('actions.delete')}</Button>
            </div>
          </div>
          <p className="text-xs text-text-secondary font-mono break-all">{destinationTarget(d, nameOf) || t('dest.everyOther')}</p>
          <p className="text-2xs text-text-tertiary">{d.keep ? t('dest.keepValue', d.keep) : t('dest.keepDefault')}</p>
          {d.error && <p className="text-xs status-danger-text">{d.error}</p>}
          {(d.status || []).map((s) => (
            <p key={s.node_id} className="text-xs status-danger-text break-words">{t('dest.statusLine', { node: nameOf(s.node_id), count: s.failures, error: s.error || '-' })}</p>
          ))}
          <TestResult result={results[d.id]} testId="archives-dest-card-result" />
        </div>
      ))}
      {editing && (
        <DestinationDialog
          open
          destination={editing.id ? editing : null}
          nodes={nodes.map((n) => ({ id: n.node_id, name: n.name }))}
          onClose={() => setEditing(null)}
          onSaved={(d) => {
            setEditing(null)
            showSuccess(t('toast.destSaved', { name: d?.name || '' }))
            onChanged()
          }}
        />
      )}
      <ConfirmDialog
        open={Boolean(deleting)}
        onOpenChange={(o) => !o && setDeleting(null)}
        onConfirm={doDelete}
        loading={busy}
        title={t('dest.deleteTitle', { name: deleting?.name })}
        message={t('dest.deleteBody')}
        confirmLabel={t('actions.delete')}
      />
    </Card>
  )
}

function UploadDialog({ onClose, onDone }) {
  const { t } = useTranslation(['archives', 'common'])
  const [file, setFile] = useState(null)
  const [identity, setIdentity] = useState('')
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const submit = async () => {
    setBusy(true)
    setError(null)
    try {
      onDone(await api.archives.upload(file, identity.trim() || null))
    } catch (e) {
      setError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <FormModal open onClose={onClose} title={t('upload.title')} onSubmit={submit} submitLabel={t('upload.submit')} loading={busy} disabled={!file} testId="archives-upload-dialog">
      <p className="text-xs text-text-secondary">{t('upload.help')}</p>
      <input type="file" accept=".age" onChange={(e) => setFile(e.target.files?.[0] || null)} className="text-xs" aria-label={t('upload.file')} data-testid="archives-upload-file" />
      <Textarea label={t('upload.identity')} value={identity} onChange={(e) => setIdentity(e.target.value)} rows={2} className="font-mono text-2xs" spellCheck={false} autoComplete="off" />
      {error && <p className="text-xs status-danger-text break-words" role="alert">{error}</p>}
    </FormModal>
  )
}

function ArchivesTable({ nodes, destinations, nameOf, reloadKey, onRestore }) {
  const { t } = useTranslation('archives')
  const { showError } = useNotification()
  const [nodeId, setNodeId] = useState('')
  const [destinationId, setDestinationId] = useState('')
  const [uploading, setUploading] = useState(false)
  const filters = useMemo(() => Object.fromEntries(Object.entries({ node_id: nodeId, destination_id: destinationId, _: reloadKey }).filter(([, v]) => v)), [nodeId, destinationId, reloadKey])
  const list = usePaginatedApi(({ _, ...q }) => api.archives.list(q), { perPage: 25, filters })
  const download = async (row) => {
    try {
      downloadBlob(await api.archives.download(row.id), row.filename || `${row.id}.tar.gz.age`)
    } catch (e) {
      showError(errorMessage(e))
    }
  }
  const destName = (id) => (id === 'local' ? t('dest.local') : id === 'upload' ? t('dest.uploaded') : destinations.find((d) => d.id === id)?.name || id)
  const columns = [
    { key: 'created_at', label: t('list.created'), render: (r) => <span className="whitespace-nowrap text-xs">{formatDate(r.created_at)}</span> },
    { key: 'node_id', label: t('list.node'), render: (r) => r.node_name || nameOf(r.node_id) },
    { key: 'size', label: t('list.size'), render: (r) => <span className="text-xs whitespace-nowrap">{formatBytes(r.size)}</span> },
    { key: 'complete', label: t('list.state'), render: (r) => (r.complete ? <Badge variant="success" size="sm">{t('list.complete')}</Badge> : <Badge variant="warning" size="sm">{t('list.incomplete')}</Badge>) },
    { key: 'destinations', label: t('list.destinations'), render: (r) => <span className="text-xs">{(r.destinations || []).map(destName).join(', ')}</span> },
    { key: 'verified_at', label: t('list.verified'), render: (r) => (r.verified_at ? <ShieldCheck size={14} className="status-success-text" aria-label={t('list.verifiedAt', { when: formatDate(r.verified_at) })} /> : '') },
    {
      key: 'actions',
      label: '',
      render: (r) => (
        <span className="flex gap-1 justify-end">
          <Button size="xs" variant="ghost" onClick={(e) => { e.stopPropagation(); download(r) }} aria-label={t('list.download')} data-testid="archives-download"><DownloadSimple size={12} /></Button>
          <Button size="xs" variant="secondary" onClick={(e) => { e.stopPropagation(); onRestore(r) }} data-testid="archives-restore-open"><ClockCounterClockwise size={12} />{t('list.restore')}</Button>
        </span>
      ),
    },
  ]
  const option = (value, label) => ({ value, label })
  const unreachable = list.meta?.unreachable || []
  return (
    <Card className="p-4 space-y-2" hover={false} data-testid="archives-list">
      <CardTitle icon={Archive} actions={<Button size="sm" variant="secondary" onClick={() => setUploading(true)} data-testid="archives-upload"><UploadSimple size={14} />{t('upload.open')}</Button>}>
        {t('list.title')}
      </CardTitle>
      {unreachable.length > 0 && <p className="text-xs status-warning-text">{t('list.unreachable', { nodes: unreachable.map(nameOf).join(', ') })}</p>}
      <DataTable
        columns={columns}
        rows={list.items}
        rowKey="id"
        loading={list.loading && !list.data}
        error={list.error}
        onRetry={list.refetch}
        onRowClick={onRestore}
        filters={[
          { key: 'node_id', label: t('list.node'), value: nodeId, onChange: setNodeId, options: nodes.map((n) => option(n.node_id, n.name)) },
          { key: 'destination_id', label: t('list.destination'), value: destinationId, onChange: setDestinationId, options: [option('local', t('dest.local')), ...destinations.map((d) => option(d.id, d.name)), option('upload', t('dest.uploaded'))] },
        ]}
        emptyTitle={t('list.empty')}
        pagination={{ page: list.page, perPage: list.perPage, total: list.total, onPageChange: list.setPage, onPerPageChange: list.setPerPage }}
        testId="archives-table"
      />
      {uploading && (
        <UploadDialog
          onClose={() => setUploading(false)}
          onDone={() => {
            setUploading(false)
            list.refetch()
          }}
        />
      )}
    </Card>
  )
}

export default function ArchivesPage() {
  const { t } = useTranslation(['archives', 'common'])
  const { showError } = useNotification()
  const overviewQ = useApi(() => api.archives.overview(), [])
  const data = overviewQ.data
  const [job, setJob] = useState(null)
  const [reloadKey, setReloadKey] = useState(0)
  const [restoring, setRestoring] = useState(null)
  const nodes = useMemo(() => data?.nodes || [], [data])
  const nameOf = (id) => nodes.find((n) => n.node_id === id)?.name || id
  const hasKey = (data?.recipients || []).length > 0
  useWsTopic('system', (m) => m?.event === 'archive' && overviewQ.refetch())

  const runNow = async (nodeIds) => {
    try {
      setJob(await api.archives.run(nodeIds))
    } catch (e) {
      showError(errorMessage(e))
    }
  }
  const running = Boolean(job && !['done', 'failed'].includes(job.state))

  return (
    <PageLayout
      icon={Archive}
      title={t('title')}
      subtitle={t('subtitle')}
      testId="page-admin-archives"
      actions={
        <Button size="sm" onClick={() => runNow(null)} disabled={!data || !hasKey || running} data-testid="archives-run">
          <Play size={14} />
          {t('actions.run')}
        </Button>
      }
    >
      {!data ? (
        overviewQ.error ? <p className="text-sm status-danger-text" role="alert">{errorMessage(overviewQ.error)}</p> : <div className="flex justify-center py-12"><LoadingSpinner size="md" /></div>
      ) : (
        <div className="space-y-4 max-w-6xl">
          {job && (
            <RunJob
              job={job}
              nameOf={nameOf}
              onFinished={() => {
                overviewQ.refetch()
                setReloadKey((k) => k + 1)
              }}
            />
          )}
          <KeyCard data={data} onChanged={overviewQ.refetch} />
          <NodesCard nodes={nodes} canRun={hasKey} running={running} onRun={runNow} />
          <ScheduleCard settings={data.settings || {}} hasKey={hasKey} onSaved={overviewQ.refetch} />
          <DestinationsCard destinations={data.destinations || []} nodes={nodes} nameOf={nameOf} onChanged={overviewQ.refetch} />
          <ArchivesTable nodes={nodes} destinations={data.destinations || []} nameOf={nameOf} reloadKey={reloadKey} onRestore={setRestoring} />
        </div>
      )}
      {restoring && (
        <RestoreWizard
          open
          archive={restoring}
          nodes={nodes.map((n) => ({ id: n.node_id, name: n.name }))}
          nameOf={nameOf}
          onClose={() => setRestoring(null)}
          onDone={() => overviewQ.refetch()}
        />
      )}
    </PageLayout>
  )
}
