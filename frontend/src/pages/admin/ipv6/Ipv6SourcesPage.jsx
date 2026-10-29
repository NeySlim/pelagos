// SPDX-License-Identifier: Apache-2.0
// Administration > IPv6 sources (architecture section 27): the neighbor tables of the nodes,
// the OPNsense sources with their key and a test, the last poll of every source on every node,
// and the watched prefixes (listed ones and the effective list with where each comes from).
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Globe, Plus, PencilSimple, Trash, Pause, Play, PlugsConnected } from '@phosphor-icons/react'
import { PageLayout, Card, Button, Badge, LoadingSpinner, ConfirmDialog, DataTable, Textarea } from '../../../components'
import { useApi, useNodeNames } from '../../../hooks'
import { useNotification } from '../../../contexts/NotificationContext'
import { api } from '../../../services/api'
import { errorMessage } from '../../../services/apiClient'
import { formatDate, formatRelativeTime } from '../../../lib/utils'
import SourceDialog from './SourceDialog'
import { prefixProblem, removeBody, splitList, toggleBody } from './ipv6Form'

const FROM_VARIANT = { setting: 'primary', reverse_zone: 'teal', dhcpv6: 'violet', interface: 'gray' }

function Field({ label, children, testId }) {
  return (
    <div className="min-w-0" data-testid={testId}>
      <dt className="text-2xs uppercase tracking-wider text-text-tertiary">{label}</dt>
      <dd className="text-sm text-text-primary break-words">{children}</dd>
    </div>
  )
}

function PrefixesCard({ data, onSaved }) {
  const { t } = useTranslation(['ipv6', 'common'])
  const { showError, showSuccess } = useNotification()
  const [text, setText] = useState((data.prefixes || []).join('\n'))
  const [busy, setBusy] = useState(false)
  // Resync on a content change only: every write answers a new prefixes array.
  const saved = (data.prefixes || []).join('\n')
  useEffect(() => setText(saved), [saved])
  const list = splitList(text)
  const bad = list.map((p) => [p, prefixProblem(p)]).find(([, problem]) => problem)
  const dirty = list.join('\n') !== (data.prefixes || []).join('\n')

  const save = async () => {
    if (bad) return
    setBusy(true)
    try {
      onSaved(await api.ipv6.update({ prefixes: list }))
      showSuccess(t('prefixes.saved'))
    } catch (e) {
      showError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card className="p-4 space-y-3" hover={false} data-testid="ipv6-prefixes">
      <h3 className="text-sm font-semibold text-text-primary">{t('prefixes.title')}</h3>
      <p className="text-xs text-text-secondary">{t('prefixes.help')}</p>
      <div className="grid gap-4 lg:grid-cols-2">
        <div className="space-y-2">
          <Textarea
            label={t('prefixes.listed')}
            rows={4}
            value={text}
            onChange={(e) => setText(e.target.value)}
            className="font-mono text-xs"
            placeholder="2001:db8:1::/64"
            helperText={bad ? undefined : t('prefixes.listedHelp')}
            error={bad ? t(`prefixes.errors.${bad[1]}`, { prefix: bad[0] }) : undefined}
            data-testid="ipv6-prefixes-input"
          />
          <Button size="sm" onClick={save} loading={busy} disabled={!dirty || Boolean(bad)} data-testid="ipv6-prefixes-save">
            {t('common:actions.save')}
          </Button>
        </div>
        <div className="space-y-1">
          <span className="block text-xs font-medium text-text-secondary">{t('prefixes.effective')}</span>
          {(data.effective_prefixes || []).length === 0 ? (
            <p className="text-xs text-text-tertiary" data-testid="ipv6-prefixes-none">{t('prefixes.none')}</p>
          ) : (
            <ul className="space-y-1" data-testid="ipv6-effective">
              {data.effective_prefixes.map((p) => (
                <li key={`${p.prefix}|${p.from}`} className="flex flex-wrap items-center gap-2" data-from={p.from}>
                  <span className="font-mono text-xs">{p.prefix}</span>
                  <Badge variant={FROM_VARIANT[p.from] || 'gray'} size="sm">{t(`prefixes.from.${p.from}`, { defaultValue: p.from })}</Badge>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </Card>
  )
}

export default function Ipv6SourcesPage() {
  const { t } = useTranslation(['ipv6', 'common'])
  const { showError, showSuccess } = useNotification()
  const nameOf = useNodeNames()
  const overview = useApi(() => api.ipv6.settings(), [])
  const [data, setData] = useState(null)
  const [editing, setEditing] = useState(null)
  const [removing, setRemoving] = useState(null)
  const [testing, setTesting] = useState({})
  useEffect(() => {
    if (overview.data) setData(overview.data)
  }, [overview.data])

  const sources = data?.sources || []
  const status = data?.status || []
  const settings = data?.settings || {}
  const sourceName = (s) => (s.source_id ? sources.find((x) => x.id === s.source_id)?.name || s.source_id : t(`source.${s.source}`, { defaultValue: s.source }))

  const write = async (body, message) => {
    try {
      setData(await api.ipv6.update(body))
      if (message) showSuccess(message)
    } catch (e) {
      showError(errorMessage(e))
    }
  }

  const runTest = async (source) => {
    setTesting((m) => ({ ...m, [source.id]: { running: true } }))
    const out = await api.ipv6.testSource({ source_id: source.id }).catch((e) => ({ ok: false, error: errorMessage(e) }))
    setTesting((m) => ({ ...m, [source.id]: out }))
  }

  const sourceColumns = [
    {
      key: 'name',
      label: t('sources.name'),
      render: (s) => (
        <span className="inline-flex flex-col">
          <span className="font-medium">{s.name}</span>
          <span className="text-2xs text-text-tertiary">{t(`sources.types.${s.type}`, { defaultValue: s.type })}</span>
        </span>
      ),
    },
    { key: 'url', label: t('sources.url'), mono: true, render: (s) => s.url },
    {
      key: 'state',
      label: t('sources.state'),
      render: (s) => {
        const last = status.find((x) => x.source_id === s.id)
        const tested = testing[s.id]
        return (
          <span className="inline-flex flex-col gap-1" data-testid="ipv6-source-state">
            <span className="inline-flex flex-wrap gap-1">
              <Badge variant={s.enabled ? 'success' : 'secondary'} size="sm">{s.enabled ? t('sources.on') : t('sources.off')}</Badge>
              {!(s.secrets?.api_key && s.secrets?.api_secret) && <Badge variant="warning" size="sm" data-testid="ipv6-source-nokey">{t('sources.noKey')}</Badge>}
              {last?.error && <Badge variant="danger" size="sm" title={last.error}>{t('sources.failing')}</Badge>}
            </span>
            {tested && !tested.running && (
              <span className={tested.ok ? 'text-2xs status-success-text' : 'text-2xs status-danger-text'} data-testid="ipv6-source-row-test" data-ok={String(Boolean(tested.ok))}>
                {tested.ok ? t('sources.testOk', { entries: tested.entries ?? 0, node: nameOf(tested.node_id) }) : t('sources.testFailed', { error: tested.error || '-' })}
              </span>
            )}
          </span>
        )
      },
    },
    {
      key: 'actions',
      label: '',
      align: 'right',
      render: (s) => (
        <span className="inline-flex gap-1">
          <Button size="xs" variant="ghost" onClick={() => runTest(s)} loading={testing[s.id]?.running} title={t('sources.test')} data-testid="ipv6-source-row-test-button">
            <PlugsConnected size={12} />
          </Button>
          <Button size="xs" variant="ghost" onClick={() => write(toggleBody(sources, s.id, !s.enabled))} title={s.enabled ? t('sources.disable') : t('sources.enable')} data-testid="ipv6-source-toggle">
            {s.enabled ? <Pause size={12} /> : <Play size={12} />}
          </Button>
          <Button size="xs" variant="ghost" onClick={() => setEditing(s)} title={t('common:actions.edit')} data-testid="ipv6-source-edit">
            <PencilSimple size={12} />
          </Button>
          <Button size="xs" variant="ghost" onClick={() => setRemoving(s)} title={t('common:actions.delete')} data-testid="ipv6-source-delete">
            <Trash size={12} />
          </Button>
        </span>
      ),
    },
  ]

  const statusColumns = [
    { key: 'source', label: t('status.source'), render: (s) => sourceName(s) },
    { key: 'node', label: t('status.node'), render: (s) => nameOf(s.node_id) },
    { key: 'last_poll', label: t('status.lastPoll'), render: (s) => (s.last_poll ? <span title={formatDate(s.last_poll)}>{formatRelativeTime(s.last_poll, t)}</span> : '-') },
    { key: 'entries', label: t('status.entries'), align: 'right', render: (s) => s.entries ?? 0 },
    {
      key: 'error',
      label: t('status.error'),
      render: (s) => (s.error ? <span className="text-xs status-danger-text break-words" data-testid="ipv6-status-error">{s.error}</span> : <Badge variant="success" size="sm">{t('status.ok')}</Badge>),
    },
  ]

  return (
    <PageLayout
      icon={Globe}
      title={t('admin.title')}
      subtitle={t('admin.subtitle')}
      testId="page-admin-ipv6"
      actions={
        <Button size="sm" onClick={() => setEditing({})} disabled={!data} data-testid="ipv6-source-add">
          <Plus size={14} />
          {t('sources.add')}
        </Button>
      }
    >
      {!data ? (
        overview.error ? (
          <Card className="p-4" hover={false}>
            <p className="text-sm status-danger-text" role="alert">{errorMessage(overview.error)}</p>
            <Button size="sm" variant="secondary" className="mt-2" onClick={overview.refetch}>{t('common:actions.retry')}</Button>
          </Card>
        ) : (
          <LoadingSpinner />
        )
      ) : (
        <div className="space-y-4">
          <Card className="p-4 space-y-3" hover={false} data-testid="ipv6-observation">
            <dl className="grid grid-cols-2 lg:grid-cols-4 gap-3">
              <Field label={t('admin.neighbors')} testId="ipv6-neighbors">
                {settings.neighbors_enabled === false ? t('sources.off') : t('sources.on')}
              </Field>
              <Field label={t('admin.pollSeconds')}>{settings.poll_seconds ?? '-'}</Field>
              <Field label={t('admin.stableDays')}>{settings.stable_min_days ?? '-'}</Field>
              <Field label={t('admin.staleDays')}>{settings.stale_days ?? '-'}</Field>
            </dl>
            <p className="text-2xs text-text-tertiary">
              {t('admin.settingsHelp')}{' '}
              <Link to="/admin/settings" className="underline">{t('admin.settingsLink')}</Link>
            </p>
          </Card>

          <DataTable
            title={t('sources.title')}
            columns={sourceColumns}
            rows={sources}
            rowKey="id"
            emptyTitle={t('sources.empty')}
            emptyDescription={t('sources.emptyHelp')}
            emptyIcon={PlugsConnected}
            testId="ipv6-sources"
          />

          <DataTable
            title={t('status.title')}
            columns={statusColumns}
            rows={status.map((s, i) => ({ ...s, _key: `${s.source}|${s.source_id || ''}|${s.node_id}|${i}` }))}
            rowKey="_key"
            dense
            emptyTitle={t('status.empty')}
            testId="ipv6-status"
          />

          <PrefixesCard data={data} onSaved={setData} />
        </div>
      )}
      {editing && (
        <SourceDialog
          source={editing.id ? editing : null}
          sources={sources}
          onClose={() => setEditing(null)}
          onSaved={(out) => {
            setData(out)
            setEditing(null)
            showSuccess(t('sources.saved'))
          }}
        />
      )}
      <ConfirmDialog
        open={Boolean(removing)}
        onOpenChange={(open) => !open && setRemoving(null)}
        title={t('sources.removeTitle', { name: removing?.name || '' })}
        message={t('sources.removeMessage')}
        confirmLabel={t('common:actions.delete')}
        onConfirm={async () => {
          const target = removing
          setRemoving(null)
          await write(removeBody(sources, target.id), t('sources.removed'))
        }}
      />
    </PageLayout>
  )
}
