// SPDX-License-Identifier: Apache-2.0
// RPZ: subscriptions to public lists by category, exceptions and rewrite activity, and the policy
// zones of the response-policy statement with their rule count (the zone's records) and the catalog
// zones. Hand-written RPZ rules are ordinary records edited from the zone page (design section 4).
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { Prohibit, ArrowsClockwise, BookOpen, Funnel, ListChecks, ChartBar, Stack } from '@phosphor-icons/react'
import { PageLayout } from '../../components/PageLayout'
import { DataTable } from '../../components/DataTable'
import { Button } from '../../components/Button'
import { Badge } from '../../components/Badge'
import { useApi } from '../../hooks/useApi'
import { LoadingSpinner } from '../../components/LoadingSpinner'
import { EmptyState } from '../../components/EmptyState'
import { usePermission } from '../../hooks/usePermission'
import { useNotification } from '../../contexts/NotificationContext'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'
import RpzCatalog from './RpzCatalog'
import RpzExceptions from './RpzExceptions'
import RpzActivity from './RpzActivity'
import { ListValue, SourceBadge } from './common'
import { zoneHref, catalogRow, usePlanFlow } from './helpers'

const POLICY_VARIANT = { given: 'gray', disabled: 'gray', passthru: 'success', drop: 'danger', nxdomain: 'danger', nodata: 'warning', tcp_only: 'warning', cname: 'info' }

// Rule count = RRsets of the zone minus SOA and NS; null when the zone is not served here.
async function loadRpz() {
  const { items } = await api.dns.rpz()
  return Promise.all(
    items.map(async (item) => {
      // A policy zone named in response-policy but not declared here has no records to count.
      if (item.configured === false) return { ...item, rules: null, local: false }
      // Subscription zones hold whole public lists: their size is on the subscriptions tab.
      if (item.zone.endsWith('.rpz.invalid.')) return { ...item, rules: null, local: false, subscription: true }
      try {
        // Paginated totals (per_page=1): exact whatever the zone size.
        const count = (type) => api.dns.records(item.zone, { per_page: 1, type }).then((res) => res.total ?? (res.items || []).length)
        const [all, soa, ns] = await Promise.all([count(undefined), count('SOA'), count('NS')])
        const rules = Math.max(0, all - soa - ns)
        return { ...item, rules, local: true }
      } catch {
        return { ...item, rules: null, local: false }
      }
    }),
  )
}

function PolicyZones() {
  const { t } = useTranslation(['dns', 'common'])
  const navigate = useNavigate()
  const rpz = useApi(loadRpz, [])
  const catalogs = useApi(() => api.dns.catalogZones(), [])
  const refetch = () => {
    rpz.refetch()
    catalogs.refetch()
  }

  return (
    <div className="space-y-4" data-testid="rpz-zones">
      <div className="flex justify-end">
        <Button variant="secondary" size="sm" onClick={refetch}>
          <ArrowsClockwise size={14} />
          {t('common:actions.refresh')}
        </Button>
      </div>
        <DataTable
          title={t('rpz.policyZones')}
          columns={[
            { key: 'zone', label: t('zones.name'), render: (r) => <span className="font-mono text-xs">{r.zone}</span> },
            { key: 'policy', label: t('rpz.policy'), render: (r) => <Badge variant={POLICY_VARIANT[r.policy] || 'default'} size="sm">{t(`rpz.policies.${r.policy}`, { defaultValue: r.policy })}</Badge> },
            { key: 'rules', label: t('rpz.rules'), align: 'right', mono: true, render: (r) => (r.subscription ? <span className="text-text-tertiary">{t('rpzsub.managedZone')}</span> : r.rules === null ? <span className="text-text-tertiary">{t('rpz.remote')}</span> : r.rules) },
            { key: 'source', label: t('zones.source'), render: (r) => <SourceBadge source={r.source} /> },
          ]}
          rows={rpz.data || []}
          rowKey="zone"
          loading={rpz.loading && !rpz.data}
          error={rpz.error}
          onRetry={rpz.refetch}
          onRowClick={(r) => r.local && navigate(zoneHref(r.zone))}
          emptyTitle={t('rpz.empty')}
          emptyDescription={t('rpz.emptyHelp')}
          testId="rpz-table"
        />
        <DataTable
          title={t('rpz.catalogZones')}
          columns={[
            { key: 'zone', label: t('zones.name'), render: (r) => <span className="inline-flex items-center gap-1.5 font-mono text-xs"><BookOpen size={13} className="text-accent-primary" />{r.zone}</span> },
            { key: 'default_primaries', label: t('rpz.defaultPrimaries'), render: (r) => <ListValue items={r.default_primaries} /> },
            { key: 'member_count', label: t('rpz.members'), align: 'right', mono: true },
            { key: 'source', label: t('zones.source'), render: (r) => <SourceBadge source={r.source} /> },
          ]}
          rows={(catalogs.data?.items || []).map(catalogRow)}
          rowKey={(r) => `${r.view || '_default'}/${r.zone}/${r.role || 'consumer'}`}
          onRowClick={() => navigate('/dns/catalogs')}
          loading={catalogs.loading && !catalogs.data}
          error={catalogs.error}
          onRetry={catalogs.refetch}
          emptyTitle={t('rpz.noCatalogs')}
          testId="catalog-table"
        />
    </div>
  )
}

export default function RpzPage() {
  const { t } = useTranslation(['dns', 'common'])
  const { hasPermission } = usePermission()
  const { showError } = useNotification()
  const [tab, setTab] = useState('catalog')
  const overview = useApi(() => api.dns.rpzOverview(), [])
  const flow = usePlanFlow({ onDone: overview.refetch, onError: showError })
  const canWrite = hasPermission('write:dns.config')

  let content
  if (overview.loading && !overview.data) {
    content = (
      <div className="flex justify-center py-12">
        <LoadingSpinner size="md" />
      </div>
    )
  } else if (overview.error && tab !== 'zones') {
    content = <EmptyState icon={Prohibit} title={errorMessage(overview.error)} action={{ label: t('common:actions.retry'), onClick: overview.refetch }} />
  } else if (tab === 'catalog') {
    content = <RpzCatalog overview={overview.data} flow={flow} canWrite={canWrite} refetch={overview.refetch} />
  } else if (tab === 'exceptions') {
    content = <RpzExceptions overview={overview.data} canWrite={canWrite} refetch={overview.refetch} />
  } else if (tab === 'activity') {
    content = <RpzActivity canWrite={canWrite} />
  } else {
    content = <PolicyZones />
  }

  return (
    <PageLayout
      icon={Prohibit}
      title={t('pages.rpz.title')}
      subtitle={t('pages.rpz.subtitle')}
      testId="page-dns-rpz"
      tabs={[
        { id: 'catalog', label: t('rpzsub.tabs.catalog'), icon: ListChecks },
        { id: 'exceptions', label: t('rpzsub.tabs.exceptions'), icon: Funnel },
        { id: 'activity', label: t('rpzsub.tabs.activity'), icon: ChartBar },
        { id: 'zones', label: t('rpzsub.tabs.zones'), icon: Stack },
      ]}
      activeTab={tab}
      onTabChange={setTab}
      actions={
        tab !== 'zones' ? (
          <Button variant="secondary" size="sm" onClick={overview.refetch}>
            <ArrowsClockwise size={14} />
            {t('common:actions.refresh')}
          </Button>
        ) : null
      }
    >
      {content}
      {flow.modal}
    </PageLayout>
  )
}
