// SPDX-License-Identifier: Apache-2.0
// DNSSEC, read only (design section 4, phase 1): zones with a dnssec-policy,
// key states from rndc dnssec -status on the chosen node, DS records to hand
// to the parent, and the resolver's dnssec-validation setting.
import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useSearchParams, Link } from 'react-router-dom'
import { ShieldCheck, ShieldSlash, ArrowsClockwise, Copy, Check } from '@phosphor-icons/react'
import { PageLayout } from '../../components/PageLayout'
import { Card } from '../../components/Card'
import { Button } from '../../components/Button'
import { Badge } from '../../components/Badge'
import { DataTable } from '../../components/DataTable'
import { EmptyState } from '../../components/EmptyState'
import { LoadingSpinner } from '../../components/LoadingSpinner'
import { Select } from '../../components/ui/Select'
import { useApi } from '../../hooks/useApi'
import { useClipboard } from '../../hooks/useClipboard'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import { formatDate, cn } from '../../lib/utils'
import { KeyValue } from './common'
import { useNodeNames, zoneHref } from './helpers'

const KEY_STATE_VARIANT = { omnipresent: 'success', rumoured: 'warning', unretentive: 'warning', hidden: 'gray' }

function ZoneStatusPanel({ zone, view, nodeId, nameOf }) {
  const { t } = useTranslation(['dns', 'common'])
  const { copy, isCopied } = useClipboard()
  const { data, error, loading, refetch } = useApi(() => api.dns.dnssec(zone, { view: view || undefined, node_id: nodeId || undefined }), [zone, view, nodeId])
  const status = data?.status
  if (loading && !data) {
    return (
      <div className="flex justify-center py-12">
        <LoadingSpinner size="md" />
      </div>
    )
  }
  if (error) return <EmptyState icon={ShieldSlash} title={errorMessage(error)} action={{ label: t('common:actions.retry'), onClick: refetch }} />
  if (!status?.signed) return <EmptyState icon={ShieldSlash} title={t('dnssec.unsigned')} description={t('dnssec.unsignedHelp')} />
  return (
    <div className="space-y-4" data-testid="dnssec-status">
      <Card className="p-4" hover={false}>
        <dl className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <KeyValue label={t('detail.dnssecPolicy')} mono>{status.policy}</KeyValue>
          <KeyValue label={t('dnssec.nextResign')}>{status.next_resign ? formatDate(status.next_resign) : null}</KeyValue>
          <KeyValue label={t('dnssec.readOn')}>{nameOf(data.node_id)}</KeyValue>
        </dl>
      </Card>
      <DataTable
        title={t('dnssec.keys')}
        columns={[
          { key: 'tag', label: t('dnssec.tag'), mono: true },
          { key: 'role', label: t('dnssec.role'), render: (k) => <Badge variant={k.role === 'KSK' || k.role === 'CSK' ? 'primary' : 'secondary'} size="sm">{k.role}</Badge> },
          { key: 'algorithm', label: t('keys.algorithm'), mono: true },
          { key: 'state', label: t('dnssec.state'), render: (k) => <Badge variant={KEY_STATE_VARIANT[k.state] || 'default'} size="sm" dot>{k.state}</Badge> },
          { key: 'published', label: t('dnssec.published'), render: (k) => formatDate(k.published) },
          { key: 'next_rollover', label: t('dnssec.nextRollover'), render: (k) => (k.next_rollover ? formatDate(k.next_rollover) : t('dnssec.noRollover')) },
        ]}
        rows={status.keys || []}
        rowKey="tag"
        dense
        testId="dnssec-keys"
      />
      {status.ds?.length > 0 && (
        <Card className="p-4 space-y-2" hover={false}>
          <p className="text-2xs uppercase tracking-wider text-text-tertiary">{t('dnssec.ds')}</p>
          {status.ds.map((ds) => (
            <div key={ds} className="flex items-start gap-2">
              <code className="flex-1 text-xs font-mono text-text-primary break-all">
                {zone} IN DS {ds}
              </code>
              <Button variant="ghost" size="xs" onClick={() => copy(`${zone} IN DS ${ds}`, ds)} aria-label={t('common:actions.copy')}>
                {isCopied(ds) ? <Check size={13} className="status-success-text" /> : <Copy size={13} />}
              </Button>
            </div>
          ))}
        </Card>
      )}
    </div>
  )
}

export default function DnssecPage() {
  const { t } = useTranslation(['dns', 'common'])
  const [search, setSearch] = useSearchParams()
  const { nodes, nameOf } = useNodeNames()
  const [nodeId, setNodeId] = useState('')
  const zones = useApi(() => api.dns.zones(), [])
  const resolver = useApi(() => api.dns.resolver().catch(() => null), [])
  const list = useMemo(
    () => (zones.data?.items || []).filter((it) => it.zone.kind !== 'forward').sort((a, b) => Number(Boolean(b.zone.dnssec_policy)) - Number(Boolean(a.zone.dnssec_policy)) || a.zone.name.localeCompare(b.zone.name)),
    [zones.data],
  )
  const selectedName = search.get('zone')
  const selected = list.find((it) => it.zone.name === selectedName || it.zone.name === `${selectedName}.`) || list.find((it) => it.zone.dnssec_policy)

  useEffect(() => {
    if (!selectedName && selected) setSearch({ zone: selected.zone.name }, { replace: true })
  }, [selectedName, selected, setSearch])

  return (
    <PageLayout
      icon={ShieldCheck}
      title={t('pages.dnssec.title')}
      subtitle={t('pages.dnssec.subtitle')}
      testId="page-dns-dnssec"
      actions={
        <Button variant="secondary" size="sm" onClick={zones.refetch}>
          <ArrowsClockwise size={14} />
          {t('common:actions.refresh')}
        </Button>
      }
    >
      <div className="grid grid-cols-1 lg:grid-cols-[18rem_1fr] gap-4">
        <div className="space-y-3">
          <Card className="p-3" hover={false}>
            <KeyValue label={t('resolver.dnssecValidation')} mono>{resolver.data?.dnssec_validation}</KeyValue>
          </Card>
          <Card className="p-1 overflow-hidden" hover={false} data-testid="dnssec-zones">
            {zones.loading && !zones.data ? (
              <div className="flex justify-center py-6">
                <LoadingSpinner size="sm" />
              </div>
            ) : (
              <ul>
                {list.map((it) => {
                  const active = selected?.zone.name === it.zone.name
                  return (
                    <li key={`${it.zone.view}/${it.zone.name}`}>
                      <button
                        type="button"
                        onClick={() => setSearch({ zone: it.zone.name })}
                        className={cn('w-full flex items-center gap-2 px-2 py-1.5 rounded text-left text-xs', active ? 'bg-accent-primary-op10 text-text-primary' : 'text-text-secondary hover:bg-tertiary-op40')}
                      >
                        {it.zone.dnssec_policy ? <ShieldCheck size={14} className="text-accent-primary shrink-0" /> : <ShieldSlash size={14} className="text-text-tertiary shrink-0" />}
                        <span className="font-mono truncate flex-1">{it.zone.name}</span>
                        {it.zone.dnssec_policy && <span className="text-2xs text-text-tertiary">{it.zone.dnssec_policy}</span>}
                      </button>
                    </li>
                  )
                })}
              </ul>
            )}
          </Card>
        </div>
        <div className="space-y-3 min-w-0">
          {selected ? (
            <>
              <div className="flex flex-wrap items-center gap-2">
                <Link to={zoneHref(selected.zone.name, selected.zone.view)} className="font-mono text-sm text-accent-primary hover:underline">
                  {selected.zone.name}
                </Link>
                <Select
                  size="sm"
                  variant="filter"
                  className="ml-auto"
                  value={nodeId}
                  onChange={setNodeId}
                  options={[{ value: '', label: t('dnssec.thisNode') }, ...nodes.map((n) => ({ value: n.peer.id, label: n.peer.name }))]}
                />
              </div>
              <ZoneStatusPanel zone={selected.zone.name} view={selected.zone.view !== '_default' ? selected.zone.view : undefined} nodeId={nodeId} nameOf={nameOf} />
            </>
          ) : (
            !zones.loading && <EmptyState icon={ShieldSlash} title={t('dnssec.noZones')} />
          )}
        </div>
      </div>
    </PageLayout>
  )
}
