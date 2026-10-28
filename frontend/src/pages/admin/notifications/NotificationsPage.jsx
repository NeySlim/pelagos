// SPDX-License-Identifier: Apache-2.0
// Administration > Notifications (architecture section 22): which node sends now, the global
// mute, the channels with their state and a real test send, the sender order, the failing
// channel alerts and the history of sent and failed batches read from the audit.
import { useEffect, useMemo, useState } from 'react'
import { useSearchParams, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import {
  BellRinging, Plus, PaperPlaneTilt, PencilSimple, Trash, Pause, Play, SpeakerSlash, SpeakerHigh,
  ArrowUp, ArrowDown, ArrowSquareOut, Warning,
} from '@phosphor-icons/react'
import { PageLayout, Card, Button, Badge, LoadingSpinner, ConfirmDialog, DataTable, FormModal, Modal, Select, Textarea } from '../../../components'
import { useApi, usePaginatedApi, useWsTopic, useNodeNames } from '../../../hooks'
import { usePermission } from '../../../hooks/usePermission'
import { useNotification } from '../../../contexts/NotificationContext'
import { useMessage } from '../../../i18n/message'
import { api } from '../../../services/api'
import { errorMessage } from '../../../services/apiClient'
import { formatDate } from '../../../lib/utils'
import ChannelDialog from './ChannelDialog'
import { MUTE_PRESETS, channelTarget, muteUntil } from './notifyForm'

const STATE_BADGE = { ok: 'success', failing: 'danger', disabled: 'secondary' }

function Field({ label, children, testId }) {
  return (
    <div className="min-w-0" data-testid={testId}>
      <dt className="text-2xs uppercase tracking-wider text-text-tertiary">{label}</dt>
      <dd className="text-sm text-text-primary break-words">{children}</dd>
    </div>
  )
}

function StatusCard({ data, nameOf, onMute, onUnmute }) {
  const { t } = useTranslation('notifications')
  const { sender, mute, queue, settings } = data
  return (
    <Card className="p-4 space-y-3" hover={false} data-testid="notify-status">
      <dl className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <Field label={t('status.sender')} testId="notify-sender">
          {sender?.node_id ? nameOf(sender.node_id) : t('status.noSender')}
          {sender?.since && <span className="block text-2xs text-text-tertiary">{t('status.since', { when: formatDate(sender.since) })}</span>}
        </Field>
        <Field label={t('status.pending')}>{queue?.pending ?? 0}</Field>
        <Field label={t('status.failing')}>
          <span className={queue?.failing ? 'status-danger-text font-semibold' : undefined} data-testid="notify-queue-failing">{queue?.failing ?? 0}</span>
        </Field>
        <Field label={t('status.mute')} testId="notify-mute-state">
          {mute ? t('status.mutedUntil', { when: formatDate(mute.until) }) : t('status.notMuted')}
        </Field>
      </dl>
      {settings?.dispatch_enabled === false && <p className="text-xs status-warning-text" data-testid="notify-dispatch-off">{t('status.dispatchOff')}</p>}
      {mute ? (
        <div className="flex flex-wrap items-center gap-2 rounded-lg border status-warning-bg status-warning-border px-3 py-2" data-testid="notify-mute-banner">
          <SpeakerSlash size={16} className="status-warning-text" />
          <p className="text-xs text-text-primary flex-1 min-w-0">{t('mute.active', { until: formatDate(mute.until), by: mute.by || '-', comment: mute.comment })}</p>
          <Button size="sm" variant="secondary" onClick={onUnmute} data-testid="notify-unmute"><SpeakerHigh size={14} />{t('mute.lift')}</Button>
        </div>
      ) : (
        <div className="flex flex-wrap items-center gap-2">
          <Button size="sm" variant="secondary" onClick={onMute} data-testid="notify-mute"><SpeakerSlash size={14} />{t('mute.set')}</Button>
          <p className="text-2xs text-text-tertiary">{t('mute.help')}</p>
        </div>
      )}
      <p className="text-2xs text-text-tertiary">{t('status.splitNote')}</p>
    </Card>
  )
}

// Open notification_failed alerts, each with a link to the alert.
function FailingAlerts({ alerts }) {
  const { t } = useTranslation('notifications')
  const msg = useMessage()
  const navigate = useNavigate()
  if (!alerts.length) return null
  return (
    <div role="status" className="rounded-lg border status-danger-bg status-danger-border px-3 py-2 space-y-1" data-testid="notify-failed-alerts">
      <p className="text-xs font-semibold status-danger-text flex items-center gap-1.5"><Warning size={14} />{t('failed.title', { count: alerts.length })}</p>
      {alerts.map((a) => (
        <div key={a.id} className="flex flex-wrap items-center gap-2 text-xs" data-testid="notify-failed-alert">
          <span className="flex-1 min-w-0 text-text-primary">{msg(a.title_message, a.title)}</span>
          <Button size="xs" variant="ghost" onClick={() => navigate(`/alerts?alert=${encodeURIComponent(a.id)}`)} data-testid="notify-failed-open"><ArrowSquareOut size={12} />{t('failed.open')}</Button>
        </div>
      ))}
    </div>
  )
}

function ChannelCard({ channel, highlight, onTest, onEdit, onToggle, onDelete, testing, result }) {
  const { t } = useTranslation('notifications')
  const st = channel.status || { state: channel.enabled ? 'ok' : 'disabled' }
  return (
    <Card className={`p-4 space-y-2 ${highlight ? 'ring-2 ring-accent-primary' : ''}`} hover={false} data-testid="notify-channel" data-channel={channel.id} data-state={st.state}>
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="ui-card-title text-sm font-semibold text-text-primary">{channel.name}</h3>
        <Badge variant="info" size="sm">{t(`types.${channel.type}`, { defaultValue: channel.type })}</Badge>
        <Badge variant={STATE_BADGE[st.state] || 'secondary'} size="sm" data-testid="notify-channel-state">
          {st.state === 'failing' && st.since ? t('state.failingSince', { when: formatDate(st.since) }) : t(`state.${st.state}`, { defaultValue: st.state })}
        </Badge>
        <Badge variant="outline" size="sm">{channel.language?.toUpperCase()}</Badge>
        <div className="ml-auto flex flex-wrap gap-1.5">
          <Button size="sm" variant="secondary" onClick={onTest} loading={testing} disabled={!channel.enabled} data-testid="notify-channel-test"><PaperPlaneTilt size={14} />{t('actions.test')}</Button>
          <Button size="sm" variant="secondary" onClick={onEdit} data-testid="notify-channel-edit"><PencilSimple size={14} />{t('actions.edit')}</Button>
          <Button size="sm" variant="ghost" onClick={onToggle} data-testid="notify-channel-toggle">
            {channel.enabled ? <Pause size={14} /> : <Play size={14} />}
            {channel.enabled ? t('actions.disable') : t('actions.enable')}
          </Button>
          <Button size="sm" variant="ghost" onClick={onDelete} data-testid="notify-channel-delete"><Trash size={14} />{t('actions.delete')}</Button>
        </div>
      </div>
      <dl className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <Field label={t('card.target')}><span className="font-mono text-xs">{channelTarget(channel) || '-'}</span></Field>
        <Field label={t('card.lastSent')}>{st.last_sent_at ? formatDate(st.last_sent_at) : t('card.never')}</Field>
        <Field label={t('card.filter')}>{t('card.filterValue', { severity: t(`severity.${channel.filters?.severity_min || 'warning'}`) })}</Field>
        <Field label={t('card.quiet')}>{channel.schedule?.quiet ? `${channel.schedule.quiet.start} - ${channel.schedule.quiet.end} (${channel.schedule.quiet.timezone})` : t('card.none')}</Field>
      </dl>
      {(channel.warnings || []).map((w) => (
        <p key={`${w.field}-${w.message}`} className="text-xs status-warning-text" data-testid="notify-channel-warning">{t('card.warning', { field: w.field, message: w.message })}</p>
      ))}
      {st.last_error && <p className="text-xs status-danger-text break-words" data-testid="notify-channel-error">{st.last_error}</p>}
      {result && (
        <p className={result.ok ? 'text-xs status-success-text' : 'text-xs status-danger-text'} role="status" data-testid="notify-channel-test-result" data-ok={String(Boolean(result.ok))}>
          {result.ok ? t('test.ok', { node: result.node_name || result.node_id || '-', ms: result.duration_ms ?? '-', status: result.status ?? '-' }) : t('test.failed', { error: result.error || '-', status: result.status ?? '-' })}
        </p>
      )}
    </Card>
  )
}

function OrderCard({ order, nameOf, senderId, onSave }) {
  const { t } = useTranslation('notifications')
  const [list, setList] = useState(order)
  const [busy, setBusy] = useState(false)
  useEffect(() => setList(order), [order])
  const move = (i, d) => setList((l) => {
    const next = [...l]
    ;[next[i], next[i + d]] = [next[i + d], next[i]]
    return next
  })
  const changed = list.join() !== order.join()
  const save = async () => {
    setBusy(true)
    try {
      await onSave(list)
    } finally {
      setBusy(false)
    }
  }
  return (
    <Card className="p-4 space-y-2" hover={false} data-testid="notify-order">
      <h3 className="ui-card-title text-sm font-semibold text-text-primary">{t('order.title')}</h3>
      <p className="text-xs text-text-secondary">{t('order.help')}</p>
      <ol className="space-y-1">
        {list.map((id, i) => (
          <li key={id} className="flex items-center gap-2 text-sm" data-testid="notify-order-node" data-node={id}>
            <span className="w-5 text-text-tertiary text-xs">{i + 1}.</span>
            <span className="font-medium">{nameOf(id)}</span>
            {id === senderId && <Badge variant="success" size="sm">{t('order.sending')}</Badge>}
            <span className="ml-auto flex gap-1">
              <Button size="xs" variant="ghost" disabled={i === 0} onClick={() => move(i, -1)} aria-label={t('order.up', { node: nameOf(id) })} data-testid="notify-order-up"><ArrowUp size={12} /></Button>
              <Button size="xs" variant="ghost" disabled={i === list.length - 1} onClick={() => move(i, 1)} aria-label={t('order.down', { node: nameOf(id) })} data-testid="notify-order-down"><ArrowDown size={12} /></Button>
            </span>
          </li>
        ))}
      </ol>
      {changed && (
        <div className="flex gap-2 justify-end">
          <Button size="sm" variant="secondary" onClick={() => setList(order)}>{t('common:actions.cancel')}</Button>
          <Button size="sm" loading={busy} onClick={save} data-testid="notify-order-save">{t('order.save')}</Button>
        </div>
      )}
    </Card>
  )
}

function MuteDialog({ open, onClose, onDone }) {
  const { t } = useTranslation(['notifications', 'common'])
  const { showError } = useNotification()
  const [hours, setHours] = useState('2')
  const [comment, setComment] = useState('')
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const submit = async () => {
    if (!comment.trim()) {
      setError(t('errors.required'))
      return
    }
    setBusy(true)
    try {
      await api.notifications.mute(muteUntil(Number(hours)), comment.trim())
      onDone()
    } catch (e) {
      showError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <FormModal open={open} onClose={onClose} title={t('mute.title')} onSubmit={submit} submitLabel={t('mute.set')} loading={busy} testId="notify-mute-dialog">
      <div className="space-y-3">
        <p className="text-xs text-text-secondary">{t('mute.dialogHelp')}</p>
        <Select label={t('mute.duration')} value={hours} onChange={setHours} options={MUTE_PRESETS.map((h) => ({ value: String(h), label: t('mute.hours', { count: h }) }))} id="notify-mute-hours" />
        <Textarea label={t('mute.comment')} value={comment} onChange={(e) => { setComment(e.target.value); setError(null) }} error={error} rows={2} data-testid="notify-mute-comment" />
      </div>
    </FormModal>
  )
}

function HistoryCard({ channels, nameOf }) {
  const { t } = useTranslation(['notifications', 'dashboard'])
  const [channelId, setChannelId] = useState('')
  const [result, setResult] = useState('')
  const [detail, setDetail] = useState(null)
  const navigate = useNavigate()
  const filters = useMemo(() => Object.fromEntries(Object.entries({ channel_id: channelId, result }).filter(([, v]) => v)), [channelId, result])
  const list = usePaginatedApi((q) => api.notifications.history(q), { perPage: 25, filters })
  useWsTopic('system', (m) => m?.event === 'notify' && list.refetch())
  const channelName = (h) => channels.find((c) => c.id === h.channel_id)?.name || h.channel_name || h.channel_id
  const eventsText = (h) => {
    const count = t('history.eventCount', { count: (h.events || []).length })
    return h.reason && h.reason !== 'events' ? `${t(`history.reasons.${h.reason}`, { defaultValue: h.reason })}, ${count}` : count
  }
  const columns = [
    { key: 'ts', label: t('history.when'), render: (h) => <span className="whitespace-nowrap text-xs">{formatDate(h.ts)}</span> },
    { key: 'channel_id', label: t('history.channel'), render: (h) => channelName(h) },
    { key: 'node_id', label: t('history.node'), render: (h) => nameOf(h.node_id) },
    { key: 'events', label: t('history.events'), render: (h) => <span className="text-xs">{eventsText(h)}</span> },
    { key: 'result', label: t('history.result'), render: (h) => <Badge variant={h.result === 'ok' ? 'success' : 'danger'} size="sm">{t(`history.results.${h.result}`, { defaultValue: h.result })}</Badge> },
    { key: 'error', label: t('history.error'), truncate: true, render: (h) => <span className="text-xs status-danger-text">{h.error || ''}</span> },
    { key: 'duration_ms', label: t('history.duration'), render: (h) => <span className="text-xs text-text-tertiary whitespace-nowrap">{h.duration_ms != null ? `${h.duration_ms} ms` : ''}{h.status ? ` (${h.status})` : ''}</span> },
  ]
  const option = (value, label) => ({ value, label })
  return (
    <Card className="p-4 space-y-2" hover={false} data-testid="notify-history">
      <h3 className="ui-card-title text-sm font-semibold text-text-primary">{t('history.title')}</h3>
      <DataTable
        columns={columns}
        rows={list.items}
        rowKey="id"
        loading={list.loading && !list.data}
        error={list.error}
        onRetry={list.refetch}
        onRowClick={setDetail}
        filters={[
          { key: 'channel_id', label: t('history.channel'), value: channelId, onChange: setChannelId, options: channels.map((c) => option(c.id, c.name)) },
          { key: 'result', label: t('history.result'), value: result, onChange: setResult, options: ['ok', 'failed'].map((r) => option(r, t(`history.results.${r}`))) },
        ]}
        emptyTitle={t('history.empty')}
        pagination={{ page: list.page, perPage: list.perPage, total: list.total, onPageChange: list.setPage, onPerPageChange: list.setPerPage }}
        testId="notify-history-table"
      />
      <Modal open={Boolean(detail)} onClose={() => setDetail(null)} title={t('history.detail')}>
        {detail && (
          <div className="p-4 space-y-3" data-testid="notify-history-detail">
            <dl className="grid grid-cols-2 gap-3">
              <Field label={t('history.when')}>{formatDate(detail.ts)}</Field>
              <Field label={t('history.channel')}>{channelName(detail)}</Field>
              <Field label={t('history.node')}>{nameOf(detail.node_id)}</Field>
              <Field label={t('history.result')}>{t(`history.results.${detail.result}`, { defaultValue: detail.result })}{detail.status ? ` (${detail.status})` : ''}</Field>
              <Field label={t('history.reason')}>{t(`history.reasons.${detail.reason || 'events'}`, { defaultValue: detail.reason })}</Field>
              <Field label={t('history.batch')}><span className="font-mono text-2xs">{detail.batch_id || detail.id}</span></Field>
            </dl>
            {detail.error && <p className="text-xs status-danger-text break-words">{detail.error}</p>}
            <ul className="space-y-1">
              {(detail.events || []).map((e, i) => (
                <li key={`${e.alert_id || 'test'}-${i}`} className="flex flex-wrap items-center gap-2 text-xs">
                  <Badge variant="outline" size="sm">{t(`events.${e.event}`, { defaultValue: e.event })}</Badge>
                  {e.severity && <Badge variant={e.severity === 'critical' ? 'danger' : e.severity === 'warning' ? 'warning' : 'secondary'} size="sm">{t(`severity.${e.severity}`)}</Badge>}
                  {e.kind && <span>{t(`dashboard:kinds.${e.kind}`, { defaultValue: e.kind })}</span>}
                  {e.alert_id && <Button size="xs" variant="ghost" onClick={() => navigate(`/alerts?alert=${encodeURIComponent(e.alert_id)}`)}><ArrowSquareOut size={12} />{t('failed.open')}</Button>}
                </li>
              ))}
            </ul>
          </div>
        )}
      </Modal>
    </Card>
  )
}

export default function NotificationsPage() {
  const { t } = useTranslation(['notifications', 'common'])
  const { showSuccess, showError } = useNotification()
  const { hasPermission } = usePermission()
  const nameOf = useNodeNames()
  const [params] = useSearchParams()
  const focus = params.get('channel')
  const overviewQ = useApi(() => api.notifications.overview(), [])
  const canReadAlerts = hasPermission('read:alerts')
  const failedQ = useApi(
    () => (canReadAlerts ? api.alerts.list({ kind: 'notification_failed', state: 'open', per_page: 50 }).catch(() => null) : Promise.resolve(null)),
    [canReadAlerts],
  )
  const data = overviewQ.data
  const [editing, setEditing] = useState(null) // channel, or {} for a new one
  const [deleting, setDeleting] = useState(null)
  const [muteOpen, setMuteOpen] = useState(false)
  const [unmuting, setUnmuting] = useState(false)
  const [testing, setTesting] = useState({})
  const [results, setResults] = useState({})
  const [busy, setBusy] = useState(false)

  useWsTopic('system', (m) => m?.event === 'notify' && overviewQ.refetch())
  useWsTopic('alerts', () => failedQ.refetch())

  useEffect(() => {
    if (!focus || !data) return
    document.querySelector(`[data-channel="${CSS.escape(focus)}"]`)?.scrollIntoView?.({ block: 'center' })
  }, [focus, data])

  const reload = () => {
    overviewQ.refetch()
    failedQ.refetch()
  }
  const run = async (fn, success) => {
    try {
      await fn()
      if (success) showSuccess(success)
      reload()
      return true
    } catch (e) {
      showError(errorMessage(e))
      return false
    }
  }
  const testChannel = async (c) => {
    setTesting((s) => ({ ...s, [c.id]: true }))
    const out = await api.notifications.test({ channel_id: c.id }).catch((e) => ({ ok: false, error: errorMessage(e) }))
    setTesting((s) => ({ ...s, [c.id]: false }))
    setResults((r) => ({ ...r, [c.id]: { ...out, node_name: out.node_id ? nameOf(out.node_id) : null } }))
  }
  const toggle = (c) => run(() => api.notifications.updateChannel(c.id, { enabled: !c.enabled }), c.enabled ? t('toast.disabled', { name: c.name }) : t('toast.enabled', { name: c.name }))
  const doDelete = async () => {
    setBusy(true)
    if (await run(() => api.notifications.deleteChannel(deleting.id), t('toast.deleted', { name: deleting.name }))) setDeleting(null)
    setBusy(false)
  }
  const doUnmute = async () => {
    setBusy(true)
    if (await run(() => api.notifications.unmute(), t('toast.unmuted'))) setUnmuting(false)
    setBusy(false)
  }

  const order = data?.sender?.order || []
  const nodes = order.map((id) => ({ id, name: nameOf(id) }))
  const channels = data?.channels || []
  const failedAlerts = failedQ.data?.items || []

  return (
    <PageLayout
      icon={BellRinging}
      title={t('title')}
      subtitle={t('subtitle')}
      testId="page-admin-notifications"
      actions={
        <Button size="sm" onClick={() => setEditing({})} disabled={!data} data-testid="notify-add">
          <Plus size={14} />
          {t('actions.add')}
        </Button>
      }
    >
      {!data ? (
        overviewQ.error ? <p className="text-sm status-danger-text" role="alert">{errorMessage(overviewQ.error)}</p> : <div className="flex justify-center py-12"><LoadingSpinner size="md" /></div>
      ) : (
        <div className="space-y-4 max-w-6xl">
          <StatusCard data={data} nameOf={nameOf} onMute={() => setMuteOpen(true)} onUnmute={() => setUnmuting(true)} />
          <FailingAlerts alerts={failedAlerts} />
          {channels.length === 0 ? (
            <Card className="p-6 text-center space-y-2" hover={false} data-testid="notify-empty">
              <p className="text-sm text-text-primary">{t('empty.title')}</p>
              <p className="text-xs text-text-secondary">{t('empty.help')}</p>
            </Card>
          ) : (
            channels.map((c) => (
              <ChannelCard
                key={c.id}
                channel={c}
                highlight={focus === c.id}
                testing={Boolean(testing[c.id])}
                result={results[c.id]}
                onTest={() => testChannel(c)}
                onEdit={() => setEditing(c)}
                onToggle={() => toggle(c)}
                onDelete={() => setDeleting(c)}
              />
            ))
          )}
          {order.length > 1 && (
            <OrderCard order={order} nameOf={nameOf} senderId={data.sender?.node_id} onSave={(ids) => run(() => api.notifications.setOrder(ids), t('toast.order'))} />
          )}
          <HistoryCard channels={channels} nameOf={nameOf} />
        </div>
      )}
      {editing && (
        <ChannelDialog
          open
          channel={editing.id ? editing : null}
          nodes={nodes}
          onClose={() => setEditing(null)}
          onSaved={(c) => {
            setEditing(null)
            showSuccess(t('toast.saved', { name: c?.name || '' }))
            reload()
          }}
        />
      )}
      {muteOpen && (
        <MuteDialog
          open
          onClose={() => setMuteOpen(false)}
          onDone={() => {
            setMuteOpen(false)
            showSuccess(t('toast.muted'))
            reload()
          }}
        />
      )}
      <ConfirmDialog
        open={Boolean(deleting)}
        onOpenChange={(o) => !o && setDeleting(null)}
        onConfirm={doDelete}
        loading={busy}
        title={t('delete.title', { name: deleting?.name })}
        message={t('delete.body')}
        confirmLabel={t('actions.delete')}
      />
      <ConfirmDialog
        open={unmuting}
        onOpenChange={setUnmuting}
        onConfirm={doUnmute}
        loading={busy}
        variant="primary"
        title={t('mute.liftTitle')}
        message={t('mute.liftBody')}
        confirmLabel={t('mute.lift')}
      />
    </PageLayout>
  )
}
