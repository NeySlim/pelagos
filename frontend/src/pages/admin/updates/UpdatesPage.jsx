// SPDX-License-Identifier: Apache-2.0
// Administration > Updates (design 13.6, architecture section 29): the version of every node, the
// releases available (source, date, notes, signature) with upload and check, the preview and the
// rollout followed across the restart of the node under the page, the engine packages of the
// distribution, the history of past rollouts and the release source settings.
import { useCallback, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import {
  ArrowCircleUp, ArrowsClockwise, UploadSimple, Package, ClockCounterClockwise, Gear, ArrowCounterClockwise, Cube, Warning, CaretRight,
} from '@phosphor-icons/react'
import { PageLayout, Card, Button, Badge, LoadingSpinner, DataTable, Input, ToggleSwitch, StatusBadge, FormSelect } from '../../../components'
import { useApi, usePaginatedApi, useWsTopic, useNodeNames } from '../../../hooks'
import { useNotification } from '../../../contexts/NotificationContext'
import { api } from '../../../services/api'
import { errorMessage } from '../../../services/apiClient'
import { formatDate } from '../../../lib/utils'
import { cn } from '../../../lib/utils'
import { ReleaseNotes } from './ReleaseNotes'
import { RolloutPanel } from './RolloutPanel'
import { SignatureBadge, UpdatePreview } from './UpdatePreview'
import { useRolloutWatch } from './useRolloutWatch'
import {
  SETTING_NUMBERS, compareVersions, engineKey, engineSelection, isActive, nodesBehind, previousVersion, settingsChanges, settingsErrors, settingsForm,
} from './updatesLib'

function CardTitle({ icon: Icon, children, actions }) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      {Icon && <Icon size={16} className="text-text-tertiary" />}
      <h3 className="text-sm font-semibold text-text-primary flex-1 min-w-0">{children}</h3>
      {actions}
    </div>
  )
}

function NodesCard({ nodes }) {
  const { t } = useTranslation('updates')
  const columns = [
    { key: 'name', label: t('nodes.name'), render: (n) => n.name || n.node_id },
    { key: 'version', label: t('nodes.version'), render: (n) => <span className="font-mono">{n.version || '-'}</span> },
    { key: 'arch', label: t('nodes.arch'), render: (n) => `${n.package_format || '-'} ${n.arch || ''}` },
    { key: 'previous_kept', label: t('nodes.previous'), render: (n) => (n.previous_kept ? <span className="font-mono">{n.previous_kept}</span> : <span className="text-text-tertiary">{t('nodes.noPrevious')}</span>) },
    { key: 'reachable', label: t('nodes.reachable'), render: (n) => <StatusBadge status={n.reachable === false ? 'offline' : 'online'} /> },
  ]
  return (
    <Card className="p-4 space-y-3" hover={false} data-testid="updates-nodes">
      <CardTitle icon={Cube}>{t('nodes.title')}</CardTitle>
      <DataTable columns={columns} rows={nodes} rowKey="node_id" dense testId="updates-nodes-table" />
      {nodes.length > 0 && nodes.every((n) => !n.previous_kept) && <p className="text-2xs text-text-tertiary" data-testid="updates-no-previous">{t('nodes.firstPassage')}</p>}
    </Card>
  )
}

function ReleaseRow({ release, nodes, blocked, onPrepare }) {
  const { t } = useTranslation('updates')
  const [open, setOpen] = useState(false)
  const behind = nodesBehind(nodes, release.version)
  const tooOld = release.min_upgrade_from ? nodes.filter((n) => n.version && compareVersions(n.version, release.min_upgrade_from) < 0) : []
  return (
    <li className="py-3 border-t border-border first:border-t-0 space-y-2" data-testid="updates-release" data-version={release.version}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm font-semibold font-mono text-text-primary">{release.version}</span>
        <SignatureBadge signature={release.signature} keyId={release.key_id} />
        <Badge variant="outline" size="sm">{t(`sources.${release.source}`, { defaultValue: release.source })}</Badge>
        <span className="text-2xs text-text-tertiary">{formatDate(release.published_at)}</span>
        {behind.length === 0 && <Badge variant="success" size="sm">{t('available.installed')}</Badge>}
        <span className="ml-auto" />
        {behind.length > 0 && (
          <Button size="sm" onClick={() => onPrepare(release)} disabled={blocked} data-testid="updates-prepare">
            <ArrowCircleUp size={14} />{t('actions.prepare')}
          </Button>
        )}
      </div>
      {behind.length > 0 && <p className="text-2xs text-text-secondary">{t('available.behind', { nodes: behind.map((n) => n.name || n.node_id).join(', '), count: behind.length })}</p>}
      {tooOld.length > 0 && <p className="text-2xs status-warning-text">{t('available.minUpgrade', { version: release.min_upgrade_from, nodes: tooOld.map((n) => n.name || n.node_id).join(', ') })}</p>}
      {release.signature !== 'valid' && <p className="text-2xs status-warning-text" data-testid="updates-release-unsigned">{t(release.signature === 'unknown_key' ? 'preview.unknownKey' : 'preview.unsigned', { version: release.version, key: release.key_id || '?' })}</p>}
      {release.notes && (
        <div>
          <button type="button" onClick={() => setOpen((o) => !o)} aria-expanded={open} className="text-xs text-accent-primary flex items-center gap-1" data-testid="updates-notes-toggle">
            <CaretRight size={10} className={cn('fx-chev', open && 'is-open')} />{t('available.notes')}
          </button>
          {open && <div className="mt-2 pl-3 border-l border-border"><ReleaseNotes text={release.notes} /></div>}
        </div>
      )}
    </li>
  )
}

function AvailableCard({ data, blocked, onPrepare, onChanged }) {
  const { t } = useTranslation('updates')
  const { showSuccess, showError } = useNotification()
  const [busy, setBusy] = useState(null)
  const fileRef = useRef(null)
  const check = async () => {
    setBusy('check')
    try {
      const out = await api.updates.check()
      if (out?.error) showError(out.error)
      else showSuccess(t('toast.checked'))
      onChanged()
    } catch (e) {
      showError(errorMessage(e))
    } finally {
      setBusy(null)
    }
  }
  const upload = async (files) => {
    if (!files?.length) return
    setBusy('upload')
    try {
      const out = await api.updates.upload([...files])
      showSuccess(t(out.signed ? 'toast.uploaded' : 'toast.uploadedUnsigned', { version: out.version, signature: t(`signature.${out.signature}`) }))
      onChanged()
    } catch (e) {
      showError(errorMessage(e))
    } finally {
      setBusy(null)
      if (fileRef.current) fileRef.current.value = ''
    }
  }
  const releases = data.available || []
  return (
    <Card className="p-4 space-y-3" hover={false} data-testid="updates-available">
      <CardTitle
        icon={Package}
        actions={(
          <>
            <Button size="sm" variant="secondary" onClick={check} loading={busy === 'check'} data-testid="updates-check"><ArrowsClockwise size={14} />{t('actions.check')}</Button>
            <Button size="sm" variant="secondary" onClick={() => fileRef.current?.click()} loading={busy === 'upload'} data-testid="updates-upload"><UploadSimple size={14} />{t('actions.upload')}</Button>
            <input ref={fileRef} type="file" multiple className="hidden" onChange={(e) => upload(e.target.files)} data-testid="updates-upload-input" aria-label={t('actions.upload')} />
          </>
        )}
      >
        {t('available.title')}
      </CardTitle>
      <p className="text-2xs text-text-tertiary">
        {t('available.checkedAt', { date: data.checked_at ? formatDate(data.checked_at) : t('available.never') })} {t('available.uploadHelp')}
      </p>
      {releases.length === 0 ? (
        <p className="text-xs text-text-tertiary italic" data-testid="updates-none">{t('available.none')}</p>
      ) : (
        <ul>{releases.map((r) => <ReleaseRow key={r.version} release={r} nodes={data.nodes || []} blocked={blocked} onPrepare={onPrepare} />)}</ul>
      )}
      {blocked && <p className="text-2xs text-text-tertiary">{t('available.blocked')}</p>}
    </Card>
  )
}

function RollbackCard({ nodes, blocked, onPrepare }) {
  const { t } = useTranslation('updates')
  const previous = previousVersion(nodes)
  if (!previous) return null
  return (
    <Card className="p-4 space-y-2" hover={false} data-testid="updates-cluster-rollback">
      <CardTitle
        icon={ArrowCounterClockwise}
        actions={<Button size="sm" variant="secondary" disabled={blocked} onClick={() => onPrepare({ kind: 'rollback', version: previous })} data-testid="updates-prepare-rollback">{t('actions.goBack', { version: previous })}</Button>}
      >
        {t('clusterRollback.title')}
      </CardTitle>
      <p className="text-2xs text-text-tertiary">{t('clusterRollback.help', { version: previous })}</p>
    </Card>
  )
}

function DockerCard({ docker }) {
  const { t } = useTranslation('updates')
  return (
    <Card className="p-4 space-y-2" hover={false} data-testid="updates-docker">
      <CardTitle icon={Cube}>{t('docker.title')}</CardTitle>
      <p className="text-xs text-text-secondary">{t('docker.help', { image: docker.image, version: docker.version })}</p>
      <pre className="font-mono text-2xs bg-bg-tertiary rounded-md p-2 overflow-x-auto">{docker.command || 'docker compose pull && docker compose up -d'}</pre>
    </Card>
  )
}

function EnginesTab({ engines, nodeName, blocked, onPrepare }) {
  const { t } = useTranslation('updates')
  const [picked, setPicked] = useState([])
  const toggle = (k) => setPicked((p) => (p.includes(k) ? p.filter((x) => x !== k) : [...p, k]))
  const selection = engineSelection(engines, picked)
  const columns = [
    {
      key: 'pick',
      label: '',
      render: (e) => (e.candidate ? (
        <input type="checkbox" checked={picked.includes(engineKey(e))} onChange={() => toggle(engineKey(e))} aria-label={t('engines.pick', { package: e.package, node: nodeName(e.node_id) })} data-testid="updates-engine-pick" />
      ) : null),
    },
    { key: 'node_id', label: t('engines.node'), render: (e) => nodeName(e.node_id) },
    { key: 'engine', label: t('engines.engine') },
    { key: 'package', label: t('engines.package'), render: (e) => <span className="font-mono">{e.package}</span> },
    { key: 'installed', label: t('engines.installed'), render: (e) => <span className="font-mono">{e.installed || '-'}</span> },
    { key: 'candidate', label: t('engines.candidate'), render: (e) => (e.candidate ? <span className="font-mono">{e.candidate}</span> : <span className="text-text-tertiary">{t('engines.upToDate')}</span>) },
    {
      key: 'cves',
      label: t('engines.cves'),
      render: (e) => (e.cves?.length ? (
        <span className="flex flex-wrap gap-1">{e.cves.map((c) => <Badge key={c} variant="danger" size="sm" className="font-mono">{c}</Badge>)}</span>
      ) : '-'),
    },
    {
      key: 'act',
      label: '',
      render: (e) => (e.candidate ? (
        <Button size="xs" variant="secondary" disabled={blocked} onClick={() => onPrepare({ kind: 'engine_packages', packages: [e.package], node_ids: [e.node_id] })} data-testid="updates-engine-update">{t('actions.update')}</Button>
      ) : null),
    },
  ]
  return (
    <Card className="p-4 space-y-3" hover={false} data-testid="updates-engines">
      <CardTitle
        icon={Package}
        actions={<Button size="sm" disabled={blocked || !selection.packages.length} onClick={() => onPrepare({ kind: 'engine_packages', ...selection })} data-testid="updates-engines-update">{t('actions.updateSelected', { count: selection.packages.length })}</Button>}
      >
        {t('engines.title')}
      </CardTitle>
      <p className="text-2xs text-text-tertiary">{t('engines.help')} <Link to="/install/kea-migration" className="text-accent-primary">{t('engines.migrationLink')}</Link></p>
      <DataTable columns={columns} rows={engines} rowKey={engineKey} dense emptyTitle={t('engines.none')} testId="updates-engines-table" />
    </Card>
  )
}

function HistoryTab({ nodeName, reloadKey }) {
  const { t } = useTranslation('updates')
  const list = usePaginatedApi(({ reloadKey: _reload, ...q }) => api.updates.history(q), { perPage: 20, filters: { reloadKey } })
  const columns = [
    { key: 'created_at', label: t('history.date'), render: (h) => formatDate(h.created_at) },
    { key: 'kind', label: t('history.kind'), render: (h) => t(`kinds.${h.kind}`, { defaultValue: h.kind }) },
    { key: 'version', label: t('history.version'), render: (h) => <span className="font-mono">{h.version || '-'}</span> },
    { key: 'state', label: t('history.state'), render: (h) => <StatusBadge status={h.state} label={t(`rolloutStates.${h.state}`, { defaultValue: h.state })} /> },
    { key: 'created_by', label: t('history.by') },
    {
      key: 'nodes',
      label: t('history.nodes'),
      render: (h) => (
        <span className="flex flex-wrap gap-1">
          {(h.nodes || []).map((n) => (
            <Badge key={n.node_id} variant={n.state === 'done' ? 'success' : n.state === 'failed' ? 'danger' : n.state === 'rolled_back' ? 'warning' : 'outline'} size="sm" title={n.error || undefined}>
              {nodeName(n.node_id)} {t(`nodeStates.${n.state}`, { defaultValue: n.state })}
            </Badge>
          ))}
        </span>
      ),
    },
  ]
  // `reloadKey` is passed as a filter so a finished rollout refreshes the list; the API ignores it.
  return (
    <Card className="p-4 space-y-3" hover={false} data-testid="updates-history">
      <CardTitle icon={ClockCounterClockwise}>{t('history.title')}</CardTitle>
      <DataTable
        columns={columns}
        rows={list.items}
        loading={list.loading}
        error={list.error ? errorMessage(list.error) : null}
        onRetry={list.refetch}
        emptyTitle={t('history.none')}
        pagination={{ page: list.page, perPage: list.perPage, total: list.total, onPageChange: list.setPage, onPerPageChange: list.setPerPage }}
        testId="updates-history-table"
      />
    </Card>
  )
}

function SourceTab({ settings, onSaved }) {
  const { t } = useTranslation(['updates', 'common'])
  const { showSuccess, showError } = useNotification()
  const [form, setForm] = useState(() => settingsForm(settings))
  const [token, setToken] = useState('')
  const [busy, setBusy] = useState(false)
  const [server, setServer] = useState({})
  const [base, setBase] = useState(settings)
  if (base !== settings) {
    setBase(settings)
    setForm(settingsForm(settings))
  }
  const errors = settingsErrors(form)
  const changes = settingsChanges(form, settings)
  const err = (k) => {
    if (server[k]) return server[k]
    const e = errors[k]
    return e ? t(`errors.${e.code}`, e) : undefined
  }
  const save = async (patch) => {
    setBusy(true)
    setServer({})
    try {
      await api.updates.saveSettings(patch)
      setToken('')
      showSuccess(t('toast.settings'))
      onSaved()
    } catch (e) {
      const fields = Object.fromEntries((e.errors || []).map((x) => [x.field, x.message]))
      setServer(fields)
      showError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }
  const set = (k) => (v) => setForm((f) => ({ ...f, [k]: v }))
  return (
    <Card className="p-4 space-y-4" hover={false} data-testid="updates-source">
      <CardTitle icon={Gear}>{t('source.title')}</CardTitle>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <FormSelect
          label={t('source.source')}
          value={form.source}
          onChange={set('source')}
          options={['upload', 'github', 'repository'].map((v) => ({ value: v, label: t(`sources.${v}`) }))}
          id="updates-setting-source"
        />
        <Input label={t('source.repository')} value={form.github_repository} placeholder="owner/name" onChange={(e) => set('github_repository')(e.target.value)} error={err('github_repository')} data-testid="updates-setting-github_repository" />
      </div>
      <p className="text-2xs text-text-tertiary">{t(`source.help.${form.source}`)}</p>
      <div className="grid grid-cols-1 md:grid-cols-[1fr_auto] gap-2 items-end" data-testid="updates-token">
        <Input
          label={t('source.token')}
          type="password"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          autoComplete="off"
          helperText={settings.github_token_stored ? t('source.tokenStored') : t('source.tokenHelp')}
          data-testid="updates-setting-token"
        />
        <div className="flex gap-2">
          <Button size="sm" variant="secondary" disabled={!token} loading={busy} onClick={() => save({ github_token: token })} data-testid="updates-token-save">{t('source.tokenSave')}</Button>
          {settings.github_token_stored && <Button size="sm" variant="ghost" loading={busy} onClick={() => save({ github_token: null })} data-testid="updates-token-remove">{t('source.tokenRemove')}</Button>}
        </div>
      </div>
      <div className="grid grid-cols-2 lg:grid-cols-3 gap-3">
        {Object.keys(SETTING_NUMBERS).map((k) => (
          <Input key={k} label={t(`source.fields.${k}`)} value={form[k]} inputMode="numeric" onChange={(e) => set(k)(e.target.value)} error={err(k)} data-testid={`updates-setting-${k}`} />
        ))}
      </div>
      <div className="flex flex-wrap gap-6">
        <ToggleSwitch checked={form.check_enabled} onChange={set('check_enabled')} size="sm" label={t('source.fields.check_enabled')} />
        <ToggleSwitch checked={form.auto_rollback_enabled} onChange={set('auto_rollback_enabled')} size="sm" label={t('source.fields.auto_rollback_enabled')} description={t('preview.autoRollbackHelp')} />
      </div>
      {Object.keys(changes).length > 0 && (
        <div className="flex justify-end gap-2">
          <Button size="sm" variant="secondary" onClick={() => setForm(settingsForm(settings))}>{t('common:actions.cancel')}</Button>
          <Button size="sm" loading={busy} disabled={Object.keys(errors).length > 0} onClick={() => save(changes)} data-testid="updates-settings-save">{t('actions.save')}</Button>
        </div>
      )}
    </Card>
  )
}

export default function UpdatesPage() {
  const { t } = useTranslation(['updates', 'common'])
  const [tab, setTab] = useState('pelagos')
  const [preview, setPreview] = useState(null) // {request, release}
  const [historyKey, setHistoryKey] = useState(0)
  const [dismissed, setDismissed] = useState(null)
  const fetchedName = useNodeNames()
  const overviewQ = useApi(() => api.updates.overview(), [])
  const data = overviewQ.data
  const refetch = overviewQ.refetch
  const finished = useCallback(() => {
    refetch()
    setHistoryKey((k) => k + 1)
  }, [refetch])
  const watch = useRolloutWatch(data?.rollout || null, { onFinished: finished, onReconnected: refetch })
  const rollout = watch.rollout
  // An update.* audit entry means a node moved: read the rollout now instead of at the next poll.
  useWsTopic(isActive(rollout) ? 'audit' : null, (m) => {
    if (String(m?.data?.action || '').startsWith('update.')) watch.refresh()
  })

  const names = useMemo(() => Object.fromEntries((data?.nodes || []).map((n) => [n.node_id, n.name])), [data])
  const nodeName = useCallback((id) => names[id] || fetchedName(id), [names, fetchedName])
  const blocked = isActive(rollout)

  const prepareRelease = (release) => setPreview({ request: { kind: 'pelagos', version: release.version }, release })
  const prepare = (request) => setPreview({ request, release: null })
  const applied = async () => {
    setPreview(null)
    setDismissed(null)
    const out = await refetch()
    if (out?.rollout) watch.setRollout(out.rollout)
    else watch.refresh()
  }

  if (overviewQ.loading && !data) return <PageLayout icon={ArrowCircleUp} title={t('title')} subtitle={t('subtitle')}><LoadingSpinner /></PageLayout>

  const tabs = [
    { id: 'pelagos', label: t('tabs.pelagos'), icon: ArrowCircleUp },
    { id: 'engines', label: t('tabs.engines'), icon: Package },
    { id: 'history', label: t('tabs.history'), icon: ClockCounterClockwise },
    { id: 'source', label: t('tabs.source'), icon: Gear },
  ]
  const showRollout = rollout && rollout.id !== dismissed

  return (
    <PageLayout icon={ArrowCircleUp} title={t('title')} subtitle={t('subtitle')} tabs={tabs} activeTab={tab} onTabChange={setTab} testId="updates-page">
      <div className="space-y-4">
        {overviewQ.error && !data && (
          <p role="alert" className="text-sm status-danger-text flex items-center gap-2"><Warning size={14} />{errorMessage(overviewQ.error)}</p>
        )}
        {showRollout && (
          <RolloutPanel
            rollout={rollout}
            connection={watch.connection}
            lostAt={watch.lostAt}
            nodeName={nodeName}
            onChanged={(out) => {
              if (out) watch.setRollout(out)
              finished()
            }}
            onDismiss={() => setDismissed(rollout.id)}
          />
        )}
        {data && tab === 'pelagos' && (
          <>
            <AvailableCard data={data} blocked={blocked} onPrepare={prepareRelease} onChanged={refetch} />
            <NodesCard nodes={data.nodes || []} />
            <RollbackCard nodes={data.nodes || []} blocked={blocked} onPrepare={prepare} />
            {data.docker && <DockerCard docker={data.docker} />}
          </>
        )}
        {data && tab === 'engines' && <EnginesTab engines={data.engines || []} nodeName={nodeName} blocked={blocked} onPrepare={prepare} />}
        {tab === 'history' && <HistoryTab nodeName={nodeName} reloadKey={historyKey} />}
        {data && tab === 'source' && <SourceTab settings={data.settings || {}} onSaved={refetch} />}
      </div>
      {preview && (
        <UpdatePreview
          request={preview.request}
          release={preview.release}
          autoRollbackDefault={data?.settings?.auto_rollback_enabled ?? true}
          nodeName={nodeName}
          onClose={() => setPreview(null)}
          onApplied={applied}
        />
      )}
    </PageLayout>
  )
}
