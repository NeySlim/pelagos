// SPDX-License-Identifier: Apache-2.0
// Hosts > IPv6 (read only, release 0.2.2): one row per MAC with its observed addresses and
// their class, the AAAA and PTR it has, the proposal, and an exception per host or address.
// Filter and zone live in the URL (?tab=ipv6&filter=&zone=) so alert links land on them.
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useSearchParams } from 'react-router-dom'
import { Globe, ProhibitInset, ShieldSlash, Shuffle, Warning } from '@phosphor-icons/react'
import { Badge } from '../../components/Badge'
import { Button } from '../../components/Button'
import { DataTable } from '../../components/DataTable'
import { useNodeNames } from '../../hooks/useNodeNames'
import { usePaginatedApi } from '../../hooks/useApi'
import { usePermission } from '../../hooks/usePermission'
import { api } from '../../services/api'
import { cn, formatDate, formatRelativeTime } from '../../lib/utils'
import { Ipv6ExceptionDialog } from './Ipv6ExceptionDialog'
import { CLASS_VARIANT, FILTERS, exceptionTargets, staleAaaa, unavailableLines, validFilter } from './ipv6'

function Chip({ active, onClick, children, testId, value }) {
  return (
    <button
      type="button"
      onClick={onClick}
      data-testid={testId}
      data-value={value}
      aria-pressed={active}
      className={cn(
        'inline-flex items-center gap-1 px-2.5 py-1 rounded-full border text-xs transition-colors',
        active ? 'border-accent-pro status-purple-border bg-tertiary-op60 text-text-primary' : 'border-border text-text-secondary hover:bg-tertiary-op40',
      )}
    >
      {children}
    </button>
  )
}

export function Ipv6Panel({ zoneOptions = [], refreshKey = 0 }) {
  const { t } = useTranslation(['ipv6', 'hosts', 'dhcp', 'common'])
  const [params, setParams] = useSearchParams()
  const { hasPermission } = usePermission()
  const nameOf = useNodeNames()
  const filter = validFilter(params.get('filter'))
  const zone = params.get('zone') || ''
  const [excepting, setExcepting] = useState(null)
  const canExcept = hasPermission('write:alerts')

  const hosts = usePaginatedApi((p) => api.ipv6.hosts(p), { perPage: 50, filters: { filter: filter || undefined, zone: zone || undefined } })
  const { refetch } = hosts
  useEffect(() => {
    if (refreshKey) refetch()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refreshKey])

  const update = (next) => {
    const q = new URLSearchParams(params)
    for (const [k, v] of Object.entries(next)) {
      if (v) q.set(k, v)
      else q.delete(k)
    }
    setParams(q, { replace: true })
  }

  const unavailable = unavailableLines(hosts.meta?.unavailable, nameOf)
  const engineErrors = Object.entries(hosts.meta?.errors || {}).map(([source, detail]) => `${source}: ${detail}`)

  const columns = [
    {
      key: 'name',
      label: t('columns.host'),
      render: (h) => (
        <span className="inline-flex flex-col gap-1 min-w-0">
          <span className="font-medium break-words">{h.name || <span className="text-text-tertiary italic">{t('unknownHost')}</span>}</span>
          <span className="inline-flex flex-wrap gap-1">
            {h.mac_random && (
              <Badge variant="warning" size="sm" icon={Shuffle} title={t('randomMacHelp')} data-testid="ipv6-random-mac">
                {t('randomMac')}
              </Badge>
            )}
            {h.excepted && (
              <Badge variant="gray" size="sm" icon={ShieldSlash} title={t('exceptedHelp')} data-testid="ipv6-excepted">
                {t('excepted')}
              </Badge>
            )}
          </span>
        </span>
      ),
    },
    { key: 'mac', label: t('dhcp:fields.mac'), mono: true, render: (h) => h.mac || '-' },
    { key: 'ipv4', label: t('columns.ipv4'), mono: true, render: (h) => (h.ipv4?.length ? h.ipv4.join(', ') : '-') },
    {
      key: 'observed',
      label: t('columns.observed'),
      render: (h) => (!h.observed?.length ? <span className="text-text-tertiary" data-testid="ipv6-not-observed">{t('notObserved')}</span> : (
        <ul className="space-y-1" data-testid="ipv6-observed">
          {h.observed.map((o) => (
            <li key={o.address} className="flex flex-wrap items-center gap-1.5" data-address={o.address} data-class={o.class}>
              <span className="font-mono text-xs break-all">{o.address}</span>
              <Badge variant={CLASS_VARIANT[o.class] || 'gray'} size="sm" title={t(`classHelp.${o.class}`, { defaultValue: '' })} data-testid="ipv6-class">
                {t(`class.${o.class}`, { defaultValue: o.class })}
              </Badge>
              <span className="text-2xs text-text-tertiary" title={t('seen', { first: formatDate(o.first_seen), last: formatDate(o.last_seen) })}>
                {(o.sources || []).map((s) => t(`source.${s}`, { defaultValue: s })).join(', ')} · {formatRelativeTime(o.last_seen, t)}
              </span>
            </li>
          ))}
        </ul>
      )),
    },
    {
      key: 'records',
      label: t('columns.records'),
      render: (h) => {
        const stale = new Set(staleAaaa(h))
        const lastSeen = new Map((h.observed || []).map((o) => [o.address, o.last_seen]))
        // ptr_missing: the AAAA the ptr_mismatch check flags (a PTR to another name is not one).
        const missing = new Set(h.ptr_missing || [])
        const ptr = new Set((h.ptr || []).filter((a) => !missing.has(a)))
        if (!h.aaaa?.length) return <span className="text-text-tertiary" data-testid="ipv6-no-aaaa">{t('noAaaa')}</span>
        return (
          <ul className="space-y-1" data-testid="ipv6-records">
            {h.aaaa.map((a) => (
              <li key={a} className="flex flex-wrap items-center gap-1.5" data-address={a}>
                <span className="font-mono text-xs break-all">{a}</span>
                <Badge variant={ptr.has(a) ? 'teal' : 'warning'} size="sm" data-testid="ipv6-ptr" data-present={String(ptr.has(a))}>
                  {ptr.has(a) ? 'PTR' : t('noPtr')}
                </Badge>
                {stale.has(a) && (
                  <Badge
                    variant="warning"
                    size="sm"
                    icon={Warning}
                    title={lastSeen.get(a) ? t('staleSeen', { last: formatDate(lastSeen.get(a)) }) : t('staleNever')}
                    data-testid="ipv6-stale"
                  >
                    {t('staleRecord')}
                  </Badge>
                )}
              </li>
            ))}
          </ul>
        )
      },
    },
    {
      key: 'proposal',
      label: t('columns.proposal'),
      render: (h) =>
        h.proposal ? (
          <span className="inline-flex flex-col text-xs" data-testid="ipv6-proposal">
            <span className="font-mono break-all">{h.proposal.address}</span>
            <span className="text-text-secondary break-all">
              {h.proposal.name} {h.proposal.reverse_zone ? '' : <span className="status-warning-text">({t('noReverseZone')})</span>}
            </span>
          </span>
        ) : (
          <span className="text-text-tertiary">-</span>
        ),
    },
    ...(canExcept
      ? [{
          key: 'actions',
          label: '',
          align: 'right',
          render: (h) =>
            exceptionTargets(h).length ? (
              <Button size="xs" variant="ghost" onClick={(e) => { e.stopPropagation(); setExcepting(h) }} data-testid="ipv6-except">
                <ProhibitInset size={12} />
                {t('exception.button')}
              </Button>
            ) : null,
        }]
      : []),
  ]

  return (
    <div className="space-y-3" data-testid="hosts-ipv6">
      <div className="flex flex-wrap items-center gap-2" data-testid="ipv6-filters">
        <Chip active={!filter} onClick={() => update({ filter: '' })} testId="ipv6-filter" value="">
          {t('filters.all')}
        </Chip>
        {FILTERS.map((f) => (
          <Chip key={f} active={filter === f} onClick={() => update({ filter: f })} testId="ipv6-filter" value={f}>
            {t(`filters.${f}`)}
          </Chip>
        ))}
        <span className="ml-auto text-xs text-text-tertiary" data-testid="ipv6-total">
          {t('total', { n: hosts.total })}
        </span>
      </div>
      {unavailable.length > 0 && (
        <p role="status" className="rounded-lg border status-warning-bg status-warning-border px-3 py-2 text-xs status-warning-text" data-testid="ipv6-unavailable">
          {t('unavailable', { sources: unavailable.join('; ') })}
        </p>
      )}
      {engineErrors.length > 0 && (
        <p role="status" className="rounded-lg border status-warning-bg status-warning-border px-3 py-2 text-xs status-warning-text" data-testid="ipv6-errors">
          {t('hosts:list.partialSources', { sources: engineErrors.join('; ') })}
        </p>
      )}
      <DataTable
        columns={columns}
        rows={hosts.items}
        rowKey="host_key"
        loading={hosts.loading}
        error={hosts.error}
        onRetry={hosts.refetch}
        filters={zoneOptions.length ? [{ key: 'zone', label: t('hosts:fields.zone'), value: zone, onChange: (v) => update({ zone: v }), options: zoneOptions, placeholder: t('hosts:list.allZones') }] : []}
        rowClassName={(h) => (h.excepted ? 'opacity-70' : undefined)}
        pagination={{ page: hosts.page, perPage: hosts.perPage, total: hosts.total, onPageChange: hosts.setPage, onPerPageChange: hosts.setPerPage }}
        emptyTitle={filter ? t(`empty.${filter}`) : t('empty.all')}
        emptyDescription={filter ? undefined : t('empty.allHelp')}
        emptyIcon={Globe}
        testId="ipv6-table"
      />
      <p className="text-2xs text-text-tertiary">
        {t('footer')}{' '}
        {hasPermission('admin:settings') && (
          <Link to="/admin/ipv6" className="underline" data-testid="ipv6-sources-link">{t('sourcesLink')}</Link>
        )}{' '}
        {hasPermission('read:alerts') && (
          <Link to="/alerts/exceptions" className="underline" data-testid="ipv6-exceptions-link">{t('exceptionsLink')}</Link>
        )}
      </p>
      <Ipv6ExceptionDialog row={excepting} onClose={() => setExcepting(null)} onDone={hosts.refetch} />
    </div>
  )
}

export default Ipv6Panel
