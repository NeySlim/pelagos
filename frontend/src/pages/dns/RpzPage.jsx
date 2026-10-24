// SPDX-License-Identifier: Apache-2.0
// Response policy zones from the response-policy statement, with their rule
// count (the zone's records), and catalog zones. RPZ rules are ordinary
// records edited from the zone page (design section 4).
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { Prohibit, ArrowsClockwise, BookOpen } from '@phosphor-icons/react'
import { PageLayout } from '../../components/PageLayout'
import { DataTable } from '../../components/DataTable'
import { Button } from '../../components/Button'
import { Badge } from '../../components/Badge'
import { useApi } from '../../hooks/useApi'
import { api } from '../../services/api'
import { ListValue, SourceBadge } from './common'
import { zoneHref } from './helpers'

const POLICY_VARIANT = { given: 'gray', disabled: 'gray', passthru: 'success', drop: 'danger', nxdomain: 'danger', nodata: 'warning', tcp_only: 'warning', cname: 'info' }

// Rule count = RRsets of the zone minus SOA and NS; null when the zone is not served here.
async function loadRpz() {
  const { items } = await api.dns.rpz()
  return Promise.all(
    items.map(async (item) => {
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

export default function RpzPage() {
  const { t } = useTranslation(['dns', 'common'])
  const navigate = useNavigate()
  const rpz = useApi(loadRpz, [])
  const catalogs = useApi(() => api.dns.catalogZones(), [])
  const refetch = () => {
    rpz.refetch()
    catalogs.refetch()
  }

  return (
    <PageLayout
      icon={Prohibit}
      title={t('pages.rpz.title')}
      subtitle={t('pages.rpz.subtitle')}
      testId="page-dns-rpz"
      actions={
        <Button variant="secondary" size="sm" onClick={refetch}>
          <ArrowsClockwise size={14} />
          {t('common:actions.refresh')}
        </Button>
      }
    >
      <div className="space-y-4">
        <DataTable
          title={t('rpz.policyZones')}
          columns={[
            { key: 'zone', label: t('zones.name'), render: (r) => <span className="font-mono text-xs">{r.zone}</span> },
            { key: 'policy', label: t('rpz.policy'), render: (r) => <Badge variant={POLICY_VARIANT[r.policy] || 'default'} size="sm">{t(`rpz.policies.${r.policy}`, { defaultValue: r.policy })}</Badge> },
            { key: 'rules', label: t('rpz.rules'), align: 'right', mono: true, render: (r) => (r.rules === null ? <span className="text-text-tertiary">{t('rpz.remote')}</span> : r.rules) },
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
          rows={catalogs.data?.items || []}
          rowKey="zone"
          loading={catalogs.loading && !catalogs.data}
          error={catalogs.error}
          onRetry={catalogs.refetch}
          emptyTitle={t('rpz.noCatalogs')}
          testId="catalog-table"
        />
      </div>
    </PageLayout>
  )
}
