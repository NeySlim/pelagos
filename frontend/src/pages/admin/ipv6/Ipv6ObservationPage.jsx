// SPDX-License-Identifier: Apache-2.0
// Administration > IPv6 observation (architecture section 27): the generic sources (neighbor
// tables of the nodes, DHCPv6 leases), the last poll of every source on every node, and the
// watched prefixes (listed ones and the effective list with where each comes from).
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Globe } from '@phosphor-icons/react'
import { PageLayout, Card, Button, Badge, LoadingSpinner, DataTable, Textarea } from '../../../components'
import { useApi, useNodeNames } from '../../../hooks'
import { useNotification } from '../../../contexts/NotificationContext'
import { api } from '../../../services/api'
import { errorMessage } from '../../../services/apiClient'
import { formatDate, formatRelativeTime } from '../../../lib/utils'
import { prefixProblem, splitList } from './ipv6Form'

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

export default function Ipv6ObservationPage() {
  const { t } = useTranslation(['ipv6', 'common'])
  const nameOf = useNodeNames()
  const overview = useApi(() => api.ipv6.settings(), [])
  const [data, setData] = useState(null)
  useEffect(() => {
    if (overview.data) setData(overview.data)
  }, [overview.data])

  const status = data?.status || []
  const settings = data?.settings || {}
  const sourceName = (s) => t(`source.${s.source}`, { defaultValue: s.source })

  const statusColumns = [
    { key: 'source', label: t('status.source'), render: (s) => sourceName(s) },
    { key: 'node', label: t('status.node'), render: (s) => nameOf(s.node_id) },
    { key: 'last_poll', label: t('status.lastPoll'), render: (s) => (s.last_poll ? <span title={formatDate(s.last_poll)}>{formatRelativeTime(s.last_poll, t)}</span> : '-') },
    { key: 'entries', label: t('status.entries'), align: 'right', render: (s) => s.entries ?? 0 },
    {
      key: 'error',
      label: t('status.error'),
      // problem: the server's reason a poll gives nothing usable (empty, unwatched, late, never polled).
      render: (s) => {
        const text = s.error || s.problem
        if (!text) return <Badge variant="success" size="sm">{t('status.ok')}</Badge>
        const tone = s.error ? 'status-danger-text' : 'status-warning-text'
        return <span className={`text-xs ${tone} break-words`} data-testid={s.error ? 'ipv6-status-error' : 'ipv6-status-problem'}>{text}</span>
      },
    },
  ]

  return (
    <PageLayout
      icon={Globe}
      title={t('admin.title')}
      subtitle={t('admin.subtitle')}
      testId="page-admin-ipv6"
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
            <p className="text-xs text-text-secondary">{t('admin.sourcesHelp')}</p>
            <dl className="grid grid-cols-2 lg:grid-cols-4 gap-3">
              <Field label={t('admin.neighbors')} testId="ipv6-neighbors">
                {settings.neighbors_enabled === false ? t('admin.off') : t('admin.on')}
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
    </PageLayout>
  )
}
