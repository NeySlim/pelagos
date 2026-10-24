// SPDX-License-Identifier: Apache-2.0
// Nodes and replication: cluster members with liveness, versions and modules,
// the replication state seen from this node, sync and removal of a peer, and the
// enrollment token dialog. Node status is live through the `nodes` topic.
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { HardDrives, Key, ArrowsClockwise, CheckCircle, Warning, Trash } from '@phosphor-icons/react'
import { Badge } from '../../components/Badge'
import { Button } from '../../components/Button'
import { Card } from '../../components/Card'
import { ConfirmDialog } from '../../components/ConfirmDialog'
import { DataTable } from '../../components/DataTable'
import { useNotification } from '../../contexts/NotificationContext'
import { useApi } from '../../hooks/useApi'
import { usePermission } from '../../hooks/usePermission'
import { useWsTopic } from '../../hooks/useWebSocket'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { formatDate, formatRelativeTime } from '../../lib/utils'
import { StatusBadge } from '../../components/StatusBadge'
import { AreaPage, SectionError } from '../dhcp/ui'
import { resetNodeNameCache } from '../dhcp/hooks'
import { EnrollTokenDialog } from './EnrollTokenDialog'

const MODULES = ['bind', 'kea4', 'kea6', 'd2']

export default function NodesPage() {
  const { t } = useTranslation(['nodes', 'common'])
  const { hasPermission } = usePermission()
  const isAdmin = hasPermission('admin:nodes')
  const { showSuccess, showError } = useNotification()
  const nodes = useApi(() => api.nodes.list(), [])
  const replication = useApi(() => api.nodes.replication(), [])
  const [enrolling, setEnrolling] = useState(false)
  const [removing, setRemoving] = useState(null)
  const [busy, setBusy] = useState(null)
  const refresh = () => {
    resetNodeNameCache()
    nodes.refetch()
    replication.refetch()
  }

  useWsTopic('nodes', (msg) => {
    const next = msg?.data
    if (!next?.peer?.id) return
    nodes.setData((cur) => (cur?.items ? { ...cur, items: cur.items.map((n) => (n.peer.id === next.peer.id ? next : n)) } : cur))
  })

  const items = useMemo(() => nodes.data?.items || [], [nodes.data])
  const self = items.find((n) => n.is_self)
  const peers = replication.data?.peers || []
  const nameOf = (id) => items.find((n) => n.peer.id === id)?.peer.name || id

  const sync = async (node) => {
    setBusy(node.peer.id)
    try {
      const res = await api.nodes.sync(node.peer.id)
      showSuccess(t('sync.done', { name: node.peer.name, n: res?.audit_added ?? 0 }) + (res?.config_adopted ? ` ${t('sync.adopted')}` : ''))
      refresh()
    } catch (err) {
      showError(errorMessage(err))
    } finally {
      setBusy(null)
    }
  }

  const remove = async () => {
    const node = removing
    setBusy(node.peer.id)
    try {
      await api.nodes.remove(node.peer.id)
      showSuccess(t('remove.done', { name: node.peer.name }))
      setRemoving(null)
      refresh()
    } catch (err) {
      showError(errorMessage(err))
    } finally {
      setBusy(null)
    }
  }

  const columns = [
    {
      key: 'name',
      label: t('fields.name'),
      sortable: true,
      sortValue: (n) => n.peer.name,
      render: (n) => (
        <span className="inline-flex items-center gap-1.5">
          <span className="font-medium">{n.peer.name}</span>
          {n.is_self && <Badge variant="primary" size="sm">{t('list.self')}</Badge>}
        </span>
      ),
    },
    { key: 'status', label: t('fields.status'), render: (n) => <StatusBadge status={n.status} /> },
    { key: 'version', label: t('fields.version'), mono: true },
    {
      key: 'config_version',
      label: t('fields.configVersion'),
      mono: true,
      render: (n) => (
        <span className={self && n.config_version !== self.config_version ? 'status-warning-text' : undefined}>{n.config_version ?? '-'}</span>
      ),
    },
    { key: 'audit_count', label: t('fields.auditCount'), mono: true },
    {
      key: 'modules',
      label: t('fields.modules'),
      render: (n) => (
        <span className="inline-flex flex-wrap gap-1">
          {MODULES.filter((m) => n.peer.modules?.[m]).map((m) => (
            <Badge key={m} variant={m === 'bind' ? 'primary' : 'purple'} size="sm">
              {t(`modules.${m}`)}
            </Badge>
          ))}
        </span>
      ),
    },
    { key: 'last_seen', label: t('fields.lastSeen'), render: (n) => <span title={formatDate(n.last_seen)}>{n.is_self ? '-' : formatRelativeTime(n.last_seen)}</span> },
    {
      key: 'url',
      label: t('fields.url'),
      className: 'font-mono text-2xs break-all',
      render: (n) =>
        n.peer.web_url && !n.is_self ? (
          <a href={n.peer.web_url} className="text-accent-primary hover:underline" onClick={(e) => e.stopPropagation()} target="_blank" rel="noreferrer">
            {n.peer.web_url}
          </a>
        ) : (
          n.peer.url
        ),
    },
    ...(isAdmin
      ? [{
          key: 'actions',
          label: '',
          align: 'right',
          render: (n) =>
            n.is_self ? null : (
              <span className="inline-flex gap-1">
                <Button variant="ghost" size="xs" onClick={() => sync(n)} loading={busy === n.peer.id} title={t('sync.button')} data-testid="node-sync">
                  <ArrowsClockwise size={13} />
                  {t('sync.button')}
                </Button>
                <Button variant="ghost" size="xs" onClick={() => setRemoving(n)} title={t('remove.button')} aria-label={t('remove.button')} data-testid="node-remove">
                  <Trash size={13} className="status-danger-text" />
                </Button>
              </span>
            ),
        }]
      : []),
  ]

  const peerColumns = [
    { key: 'node_id', label: t('fields.peer'), render: (p) => nameOf(p.node_id) },
    {
      key: 'reachable',
      label: t('fields.reachable'),
      render: (p) => <StatusBadge status={p.reachable ? 'online' : 'offline'} />,
    },
    {
      key: 'config_version',
      label: t('fields.configVersion'),
      mono: true,
      render: (p) => (
        <span className={self && p.config_version !== self.config_version ? 'status-warning-text' : undefined}>
          {p.config_version ?? '-'}
          {self && p.config_version !== null && p.config_version !== self.config_version && <span className="text-text-tertiary"> ({t('replication.local', { v: self.config_version })})</span>}
        </span>
      ),
    },
    {
      key: 'audit_count',
      label: t('fields.auditCount'),
      mono: true,
      render: (p) => (
        <span className={self && p.audit_count !== self.audit_count ? 'status-warning-text' : undefined}>
          {p.audit_count ?? '-'}
        </span>
      ),
    },
    { key: 'last_seen', label: t('fields.lastSeen'), render: (p) => <span title={formatDate(p.last_seen)}>{formatRelativeTime(p.last_seen)}</span> },
    { key: 'error', label: t('fields.error'), truncate: true, render: (p) => (p.error ? <span className="status-danger-text">{p.error}</span> : '') },
  ]

  const inSync = peers.every((p) => p.reachable && self && p.config_version === self.config_version && p.audit_count === self.audit_count)

  return (
    <AreaPage
      ns="nodes"
      page="list"
      icon={HardDrives}
      onRefresh={refresh}
      loading={nodes.loading}
      actions={
        isAdmin && (
          <Button size="sm" onClick={() => setEnrolling(true)} data-testid="enroll-open">
            <Key size={14} />
            {t('enroll.button')}
          </Button>
        )
      }
    >
      <div className="space-y-4">
        <DataTable
          columns={columns}
          rows={items}
          rowKey={(n) => n.peer.id}
          loading={nodes.loading}
          error={nodes.error}
          onRetry={nodes.refetch}
          clientSort
          emptyTitle={t('list.empty')}
          emptyIcon={HardDrives}
          testId="nodes-table"
        />
        <Card className="p-3 space-y-3" hover={false} data-testid="replication">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="ui-card-title text-sm font-semibold text-text-primary">{t('replication.title')}</h3>
            {replication.data && <StatusBadge status={replication.data.state} />}
            {replication.data && peers.length > 0 && (
              <Badge variant={inSync ? 'success' : 'warning'} size="sm" icon={inSync ? CheckCircle : Warning} data-testid="replication-sync">
                {inSync ? t('replication.inSync') : t('replication.behind')}
              </Badge>
            )}
            {self && (
              <span className="ml-auto text-2xs text-text-tertiary font-mono" title={self.peer.cert_fingerprint}>
                {t('replication.fingerprint', { fp: `${String(self.peer.cert_fingerprint).slice(0, 16)}...` })}
              </span>
            )}
          </div>
          <SectionError error={replication.error} onRetry={replication.refetch} />
          {replication.data && peers.length === 0 ? (
            <p className="text-xs text-text-tertiary">{t('replication.alone')}</p>
          ) : (
            <DataTable
              columns={peerColumns}
              rows={peers}
              rowKey="node_id"
              loading={replication.loading}
              dense
              testId="replication-peers"
            />
          )}
          <p className="text-2xs text-text-tertiary">{t('replication.hint')}</p>
        </Card>
      </div>
      {enrolling && <EnrollTokenDialog onClose={() => setEnrolling(false)} />}
      <ConfirmDialog
        open={Boolean(removing)}
        onOpenChange={(o) => !o && setRemoving(null)}
        onConfirm={remove}
        title={t('remove.title', { name: removing?.peer.name })}
        message={t('remove.message')}
        confirmLabel={t('remove.button')}
        typeToConfirm={removing?.peer.name}
        loading={Boolean(busy)}
      />
    </AreaPage>
  )
}
