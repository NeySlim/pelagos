// SPDX-License-Identifier: Apache-2.0
// DNS > Resolver > Health (architecture section 25): readings per node, history, root and TLD
// probes, thresholds against what was observed, the active fallback banner, and the fallback
// and extension forms.
import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ArrowCounterClockwise, Clock, Heartbeat, Lifebuoy, ShieldCheck } from '@phosphor-icons/react'
import { Card } from '../../components/Card'
import { Button } from '../../components/Button'
import { Badge } from '../../components/Badge'
import { DataTable } from '../../components/DataTable'
import { FormModal } from '../../components/FormModal'
import { Input } from '../../components/Input'
import { TrendAreaChart } from '../../components/DashboardChart'
import { StatusDot } from '../../components/motion'
import { Select } from '../../components/ui/Select'
import ToggleSwitch from '../../components/ui/ToggleSwitch'
import TagsInput from '../../components/ui/TagsInput'
import { useApi } from '../../hooks/useApi'
import { api } from '../../services/api'
import { cn, formatDate, formatRelativeTime } from '../../lib/utils'
import {
  CHART_METRICS, CUSTOM_PRESET, DEFAULT_MAX_HOURS, RANGES, applyPreset, chartRows, fallbackBody, fallbackDefaults, fallbackErrors,
  fallbackStatus, hourChoices, nodeReadings, remaining, rootRows, rootsAnswering, seriesQuery, validAddress,
} from './resolverHealth'

const TONE_TEXT = { danger: 'status-danger-text', warning: 'status-warning-text', success: 'text-text-primary', neutral: 'text-text-primary' }
const CHART_COLORS = ['primary', 'pro', 'warning', 'success', 'danger']

function useFormatValue() {
  const { t, i18n } = useTranslation('dns')
  return (value, unit) => {
    if (value === null || value === undefined) return '-'
    const n = new Intl.NumberFormat(i18n.language, { maximumFractionDigits: value >= 100 ? 0 : value >= 10 ? 1 : 2 }).format(value)
    return t(`resolverHealth.units.${unit}`, { value: n })
  }
}

function Readings({ entry, thresholds }) {
  const { t } = useTranslation('dns')
  const fmt = useFormatValue()
  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2">
      {nodeReadings(entry, thresholds).map((r) => (
        <div key={r.key} className="ui-subpanel rounded-lg border border-border px-3 py-2 min-w-0" data-testid={`resolver-reading-${r.key}`} data-tone={r.tone}>
          <div className="ui-label text-2xs uppercase tracking-wider text-text-tertiary truncate">{t(`resolverHealth.readings.${r.key}`)}</div>
          <div className={cn('text-lg font-semibold tabular-nums leading-tight', TONE_TEXT[r.tone])}>{fmt(r.value, r.unit)}</div>
        </div>
      ))}
    </div>
  )
}

function ProbeState({ ok, lastFailure }) {
  const { t } = useTranslation('dns')
  return (
    <span className="inline-flex items-center gap-1.5">
      <StatusDot tone={ok ? 'success' : 'danger'} />
      <span className={ok ? 'text-text-secondary' : 'status-danger-text'}>{ok ? t('resolverHealth.probes.ok') : t('resolverHealth.probes.failing')}</span>
      {lastFailure && !ok && <span className="text-text-tertiary text-2xs">{formatRelativeTime(lastFailure)}</span>}
    </span>
  )
}

function Probes({ entry }) {
  const { t } = useTranslation('dns')
  const fmt = useFormatValue()
  const roots = rootRows(entry)
  const addr = (p) => (p ? <span className={cn('font-mono text-2xs', p.ok ? 'text-text-secondary' : 'status-danger-text')}>{p.address}</span> : <span className="text-text-tertiary">-</span>)
  return (
    <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
      <DataTable
        title={t('resolverHealth.probes.roots')}
        columns={[
          { key: 'letter', label: t('resolverHealth.probes.letter'), mono: true },
          { key: 'v4', label: 'IPv4', render: (r) => addr(r.v4) },
          { key: 'v6', label: 'IPv6', render: (r) => addr(r.v6) },
          { key: 'rtt_ms', label: t('resolverHealth.probes.rtt'), render: (r) => fmt(r.rtt_ms, 'ms') },
          { key: 'ok', label: t('resolverHealth.probes.state'), render: (r) => <ProbeState ok={r.ok} lastFailure={r.last_failure} /> },
          { key: 'last_failure', label: t('resolverHealth.probes.lastFailure'), render: (r) => (r.last_failure ? formatDate(r.last_failure) : '-') },
        ]}
        rows={roots}
        rowKey="letter"
        dense
        emptyTitle={t('resolverHealth.probes.noRoots')}
        testId="resolver-roots"
      />
      <DataTable
        title={t('resolverHealth.probes.tlds')}
        columns={[
          {
            key: 'tld',
            label: t('resolverHealth.probes.tld'),
            render: (r) => (
              <span className="inline-flex items-center gap-1.5 font-mono text-xs">
                {r.tld}.
                {r.served && <Badge size="sm" variant="outline">{t('resolverHealth.probes.served')}</Badge>}
              </span>
            ),
          },
          { key: 'servers', label: t('resolverHealth.probes.servers') },
          { key: 'rtt_ms', label: t('resolverHealth.probes.rtt'), render: (r) => fmt(r.rtt_ms, 'ms') },
          { key: 'ok', label: t('resolverHealth.probes.state'), render: (r) => <ProbeState ok={r.ok} lastFailure={r.last_failure} /> },
          { key: 'last_failure', label: t('resolverHealth.probes.lastFailure'), render: (r) => (r.last_failure ? formatDate(r.last_failure) : '-') },
        ]}
        rows={entry?.tlds || []}
        rowKey="tld"
        dense
        emptyTitle={t('resolverHealth.probes.noTlds')}
        testId="resolver-tlds"
      />
    </div>
  )
}

function NodeHealth({ entry, thresholds, name }) {
  const { t } = useTranslation('dns')
  const roots = rootsAnswering(entry)
  const since = entry.probes_healthy_since
  return (
    <Card className="p-4 space-y-4" hover={false} data-testid="resolver-node" data-node={entry.node_id}>
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="ui-card-title ui-title-literal text-sm font-semibold text-text-primary">{name}</h3>
        {roots.total > 0 && (
          <Badge size="sm" variant={roots.ok === roots.total ? 'success' : roots.ok === 0 ? 'danger' : 'warning'} data-testid="resolver-roots-badge">
            {t('resolverHealth.rootsAnswering', { ok: roots.ok, total: roots.total })}
          </Badge>
        )}
        {since === 'unhealthy' && <Badge size="sm" variant="danger">{t('resolverHealth.unhealthy')}</Badge>}
        {since && since !== 'unhealthy' && since !== 'unknown' && <span className="text-2xs text-text-tertiary">{t('resolverHealth.healthySince', { when: formatRelativeTime(since) })}</span>}
        <span className="ml-auto text-2xs text-text-tertiary">{entry.sampled_at ? t('resolverHealth.sampled', { when: formatRelativeTime(entry.sampled_at) }) : null}</span>
      </div>
      {entry.error && (
        <p className="text-xs status-warning-text" data-testid="resolver-node-error">{t('resolverHealth.measureError', { error: entry.error })}</p>
      )}
      <Readings entry={entry} thresholds={thresholds} />
      <Probes entry={entry} />
    </Card>
  )
}

function History({ nodes, nameOf }) {
  const { t, i18n } = useTranslation('dns')
  const fmt = useFormatValue()
  const [metric, setMetric] = useState('latency_p95_ms')
  const [range, setRange] = useState('24h')
  const series = useApi(() => api.resolverHealth.series(seriesQuery(metric, range)), [metric, range])
  const rows = useMemo(() => chartRows(series.data?.series), [series.data])
  const ids = useMemo(() => [...new Set((series.data?.series || []).map((s) => s.key?.node_id).filter(Boolean))], [series.data])
  const lines = ids.map((id, i) => ({ key: id, label: nameOf(id), color: CHART_COLORS[i % CHART_COLORS.length] }))
  const xFormatter = (ts) => new Date(ts).toLocaleString(i18n.language, range === '7d' ? { day: '2-digit', month: 'short' } : { hour: '2-digit', minute: '2-digit' })
  const last = rows.length ? rows[rows.length - 1] : null
  return (
    <Card className="p-4 space-y-3" hover={false} data-testid="resolver-history">
      <div className="flex flex-wrap items-end gap-3">
        <h3 className="ui-card-title text-sm font-semibold text-text-primary mr-auto">{t('resolverHealth.history')}</h3>
        <div className="w-56">
          <Select
            ariaLabel={t('resolverHealth.metric')}
            value={metric}
            onChange={setMetric}
            size="sm"
            options={Object.keys(CHART_METRICS).map((m) => ({ value: m, label: t(`resolverHealth.metrics.${m}`) }))}
          />
        </div>
        <div className="inline-flex rounded-lg border border-border overflow-hidden" role="group" aria-label={t('resolverHealth.range')}>
          {Object.keys(RANGES).map((r) => (
            <button
              key={r}
              type="button"
              className={cn('px-2.5 py-1 text-xs', r === range ? 'bg-accent-primary-op15 text-accent-primary' : 'text-text-secondary hover:text-text-primary')}
              aria-pressed={r === range}
              onClick={() => setRange(r)}
              data-testid={`resolver-range-${r}`}
            >
              {t(`resolverHealth.ranges.${r}`)}
            </button>
          ))}
        </div>
      </div>
      {last && nodes.length > 0 && (
        <div className="flex flex-wrap gap-3 text-2xs text-text-tertiary">
          {ids.map((id) => (
            <span key={id}>
              {nameOf(id)}: <span className="font-mono text-text-primary">{fmt(last[id] ?? null, CHART_METRICS[metric])}</span>
            </span>
          ))}
        </div>
      )}
      <div className="h-48" data-testid="resolver-chart" data-points={rows.length}>
        <TrendAreaChart data={rows} series={lines} xFormatter={xFormatter} />
      </div>
    </Card>
  )
}

function Thresholds({ thresholds }) {
  const { t } = useTranslation('dns')
  const rows = Object.entries(thresholds || {}).map(([key, v]) => ({ key, ...v }))
  const fmt = (v) => (v === null || v === undefined ? '-' : String(v))
  return (
    <DataTable
      title={t('resolverHealth.thresholds.title')}
      columns={[
        { key: 'key', label: t('resolverHealth.thresholds.measure'), render: (r) => t(`resolverHealth.thresholds.keys.${r.key}`, { defaultValue: r.key }) },
        { key: 'warning', label: t('resolverHealth.thresholds.setting'), render: (r) => <span className="font-mono text-xs">{[r.info, r.warning, r.critical].filter((v) => v !== undefined && v !== null).join(' / ') || '-'}</span> },
        {
          key: 'observed_max_7d',
          label: t('resolverHealth.thresholds.observed'),
          render: (r) => {
            const limit = r.warning ?? r.info
            const over = r.observed_max_7d !== null && r.observed_max_7d !== undefined && limit !== undefined && r.observed_max_7d >= limit
            return <span className={cn('font-mono text-xs', over ? 'status-warning-text' : 'text-text-secondary')}>{fmt(r.observed_max_7d)}</span>
          },
        },
      ]}
      rows={rows}
      rowKey="key"
      dense
      testId="resolver-thresholds"
    />
  )
}

// Active fallback: forwarders, nodes, deadline, return and extension.
export function FallbackBanner({ fallback, returnReady, nameOf, canWrite, onReturn, onExtend, busy, autoReturn = true }) {
  const { t } = useTranslation('dns')
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 30000)
    return () => clearInterval(timer)
  }, [])
  const status = fallbackStatus(fallback, now)
  if (!status) return null
  const left = remaining(status.remainingMs)
  return (
    <div className="rounded-lg border border-border status-warning-bg px-4 py-3 space-y-2" role="status" data-testid="resolver-fallback-banner">
      <div className="flex flex-wrap items-center gap-2">
        <Lifebuoy size={18} className="status-warning-text shrink-0" weight="duotone" />
        <span className="font-semibold text-sm text-text-primary">{t('resolverHealth.banner.title')}</span>
        <Badge size="sm" variant="outline">forward {fallback.forward}</Badge>
        {fallback.tls_name && <Badge size="sm" variant="outline" icon={ShieldCheck}>{t('resolverHealth.banner.tls', { name: fallback.tls_name })}</Badge>}
        {fallback.manual_change && (
          <Badge size="sm" variant="danger" data-testid="resolver-fallback-manual">
            {fallback.manual_change_nodes?.length
              ? t('resolverHealth.banner.manual', { nodes: fallback.manual_change_nodes.map(nameOf).join(', ') })
              : t('resolverHealth.banner.manualAny')}
          </Badge>
        )}
        {returnReady && <Badge size="sm" variant="success" data-testid="resolver-fallback-ready">{t('resolverHealth.banner.ready')}</Badge>}
      </div>
      <dl className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
        <div className="min-w-0">
          <dt className="text-2xs uppercase tracking-wider text-text-tertiary">{t('resolverHealth.banner.forwarders')}</dt>
          <dd className="font-mono text-text-primary break-words" data-testid="resolver-fallback-forwarders">{fallback.forwarders.join(', ')}</dd>
        </div>
        <div className="min-w-0">
          <dt className="text-2xs uppercase tracking-wider text-text-tertiary">{t('resolverHealth.banner.nodes')}</dt>
          <dd className="text-text-primary">
            {status.pending.map(nameOf).join(', ') || '-'}
            {status.returned.length > 0 && <span className="text-text-tertiary"> {t('resolverHealth.banner.returned', { nodes: status.returned.map(nameOf).join(', ') })}</span>}
          </dd>
        </div>
        <div className="min-w-0">
          <dt className="text-2xs uppercase tracking-wider text-text-tertiary">{t('resolverHealth.banner.until')}</dt>
          <dd className="text-text-primary" data-testid="resolver-fallback-until">
            {formatDate(fallback.until)}{' '}
            <span className="text-text-tertiary">
              {status.overdue ? t(autoReturn ? 'resolverHealth.banner.overdue' : 'resolverHealth.banner.overdueManual') : left ? t('resolverHealth.banner.left', left) : null}
            </span>
          </dd>
        </div>
      </dl>
      <p className="text-2xs text-text-secondary" data-testid="resolver-fallback-started">
        {t('resolverHealth.banner.started', { by: fallback.by || '-', when: fallback.started_at ? formatDate(fallback.started_at) : '-' })}{' '}
        {t(autoReturn ? 'resolverHealth.banner.autoReturn' : 'resolverHealth.banner.noAutoReturn')}
      </p>
      {canWrite && (
        <div className="flex flex-wrap gap-2">
          <Button size="sm" onClick={onReturn} disabled={busy} data-testid="resolver-fallback-return">
            <ArrowCounterClockwise size={14} />
            {t('resolverHealth.banner.returnNow')}
          </Button>
          <Button size="sm" variant="secondary" onClick={onExtend} disabled={busy} data-testid="resolver-fallback-extend">
            <Clock size={14} />
            {t('resolverHealth.banner.extend')}
          </Button>
        </div>
      )}
    </div>
  )
}

// The fallback plan form: preset or own addresses, first or only, nodes, duration, DNS over TLS.
export function FallbackForm({ open, onClose, presets = [], nodes = [], nameOf, maxHours, onPlan, autoReturn = true }) {
  const { t } = useTranslation(['dns', 'common'])
  const nodeIds = nodes.map((n) => n.node_id)
  const answering = (list) => list.filter((n) => !n.unavailable).map((n) => n.node_id)
  const [form, setForm] = useState(() => fallbackDefaults(presets, answering(nodes), maxHours))
  const [busy, setBusy] = useState(false)
  const [touched, setTouched] = useState(false)
  useEffect(() => {
    if (open) {
      setForm(fallbackDefaults(presets, answering(nodes), maxHours))
      setTouched(false)
    }
    // Reset only when the form opens.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open])
  // fallback_max_hours can arrive after the form opened (?fallback=1): keep the duration within it.
  useEffect(() => {
    setForm((f) => (f.hours > maxHours ? { ...f, hours: Math.min(DEFAULT_MAX_HOURS, maxHours) } : f))
  }, [maxHours])
  const errors = fallbackErrors(form, maxHours)
  const invalid = Object.keys(errors).length > 0
  const preset = presets.find((p) => p.id === form.preset)
  const tlsPossible = form.preset === CUSTOM_PRESET || Boolean(preset?.tls_name)
  const set = (key) => (value) => setForm((f) => ({ ...f, [key]: value }))
  const toggleNode = (id) => setForm((f) => ({ ...f, node_ids: f.node_ids.includes(id) ? f.node_ids.filter((x) => x !== id) : [...f.node_ids, id] }))
  const err = (key) => (touched && errors[key] ? t(errors[key], { max: maxHours }) : undefined)

  const submit = async () => {
    setTouched(true)
    if (invalid) return
    setBusy(true)
    try {
      await onPlan(fallbackBody(form, nodeIds))
    } finally {
      setBusy(false)
    }
  }

  return (
    <FormModal open={open} onClose={onClose} title={t('resolverHealth.form.title')} onSubmit={submit} loading={busy} submitLabel={t('editor.buildPlan')} testId="resolver-fallback-form">
      <p className="text-xs text-text-secondary" data-testid="resolver-fallback-intro">{t(autoReturn ? 'resolverHealth.form.intro' : 'resolverHealth.form.introManual')}</p>
      <Select
        label={t('resolverHealth.form.preset')}
        value={form.preset}
        onChange={(id) => setForm((f) => applyPreset(f, presets, id))}
        options={[
          ...presets.map((p) => ({ value: p.id, label: p.filtering ? t('resolverHealth.form.presetFiltering', { name: p.name }) : p.name })),
          { value: CUSTOM_PRESET, label: t('resolverHealth.form.custom') },
        ]}
      />
      {preset && <p className="text-2xs text-text-tertiary -mt-2" data-testid="resolver-fallback-preset-note">{t(preset.filtering ? 'resolverHealth.form.filteringNote' : 'resolverHealth.form.noFilteringNote')}</p>}
      <div data-testid="resolver-fallback-forwarders-input">
        <TagsInput
          label={t('resolverHealth.form.forwarders')}
          value={form.forwarders}
          onChange={(v) => setForm((f) => ({ ...f, forwarders: v, preset: CUSTOM_PRESET }))}
          placeholder="192.0.2.53"
          helperText={err('forwarders') || t('resolverHealth.form.forwardersHelp')}
          validate={validAddress}
        />
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <Select
          label={t('resolverHealth.form.forward')}
          value={form.forward}
          onChange={set('forward')}
          options={[
            { value: 'first', label: t('resolverHealth.form.forwardFirst') },
            { value: 'only', label: t('resolverHealth.form.forwardOnly') },
          ]}
        />
        <Select
          label={t('resolverHealth.form.hours')}
          value={String(form.hours)}
          onChange={(v) => set('hours')(Number(v))}
          error={err('hours')}
          options={hourChoices(maxHours).map((h) => ({ value: String(h), label: t('resolverHealth.form.hoursValue', { hours: h }) }))}
        />
      </div>
      <fieldset className="space-y-1" data-testid="resolver-fallback-nodes">
        <legend className="text-xs font-medium text-text-secondary mb-1">{t('resolverHealth.form.nodes')}</legend>
        {nodes.map((n) => (
          <label key={n.node_id} className="flex items-center gap-2 text-sm text-text-primary">
            <input type="checkbox" checked={form.node_ids.includes(n.node_id)} onChange={() => toggleNode(n.node_id)} data-testid="resolver-fallback-node" />
            {nameOf(n.node_id)}
            {n.unavailable && <span className="text-2xs status-warning-text" data-testid="resolver-fallback-node-error">{n.error || t('resolverHealth.form.nodeSilent')}</span>}
          </label>
        ))}
        {err('node_ids') && <p className="text-xs status-danger-text">{err('node_ids')}</p>}
      </fieldset>
      {tlsPossible && (
        <ToggleSwitch
          checked={form.tls}
          onChange={set('tls')}
          label={t('resolverHealth.form.tls')}
          description={preset?.tls_name ? t('resolverHealth.form.tlsPreset', { name: preset.tls_name }) : t('resolverHealth.form.tlsHelp')}
        />
      )}
      {form.tls && form.preset === CUSTOM_PRESET && (
        <Input label={t('resolverHealth.form.tlsName')} value={form.tls_name} onChange={(e) => set('tls_name')(e.target.value)} placeholder="dns.example.net" error={err('tls_name')} data-testid="resolver-fallback-tls-name" />
      )}
      <p className="text-2xs text-text-tertiary">{t('resolverHealth.form.dnssecNote')}</p>
    </FormModal>
  )
}

// Moves the deadline: hours from now, up to fallback_max_hours.
export function ExtendForm({ open, onClose, maxHours, onExtend }) {
  const { t } = useTranslation(['dns', 'common'])
  const [hours, setHours] = useState(() => String(Math.min(4, maxHours)))
  const [busy, setBusy] = useState(false)
  const submit = async () => {
    setBusy(true)
    try {
      await onExtend(Number(hours))
    } finally {
      setBusy(false)
    }
  }
  return (
    <FormModal open={open} onClose={onClose} title={t('resolverHealth.extend.title')} onSubmit={submit} loading={busy} submitLabel={t('resolverHealth.extend.submit')} size="sm" testId="resolver-extend-form">
      <Select
        label={t('resolverHealth.extend.hours')}
        value={hours}
        onChange={setHours}
        options={hourChoices(maxHours).map((h) => ({ value: String(h), label: t('resolverHealth.form.hoursValue', { hours: h }) }))}
      />
      <p className="text-2xs text-text-tertiary">{t('resolverHealth.extend.help', { max: maxHours })}</p>
    </FormModal>
  )
}

// The health part of the resolver page: per node cards, history, thresholds.
export function ResolverHealthSection({ health, error, loading, nameOf, canSeries, onRetry }) {
  const { t } = useTranslation('dns')
  if (error) {
    return (
      <Card className="p-4 text-sm status-warning-text" hover={false} data-testid="resolver-health-error">
        {t('resolverHealth.loadError')}{' '}
        <button type="button" className="underline" onClick={onRetry}>{t('common:actions.retry')}</button>
      </Card>
    )
  }
  if (loading && !health) return null
  const nodes = health?.nodes || []
  return (
    <section className="space-y-4" data-testid="resolver-health">
      <h2 className="flex items-center gap-2 text-sm font-semibold text-text-primary">
        <Heartbeat size={16} className="text-accent-primary" weight="duotone" />
        {t('resolverHealth.title')}
      </h2>
      {(health?.unavailable || []).length > 0 && (
        <p className="text-xs status-warning-text" data-testid="resolver-health-unavailable">
          {t('resolverHealth.unavailable', { nodes: health.unavailable.map((u) => `${u.name || nameOf(u.node_id)}${u.error ? ` (${u.error})` : ''}`).join(', ') })}
        </p>
      )}
      {nodes.length === 0 ? (
        <Card className="p-4 text-sm text-text-tertiary" hover={false}>{t('resolverHealth.noNodes')}</Card>
      ) : (
        nodes.map((entry) => <NodeHealth key={entry.node_id} entry={entry} thresholds={health.thresholds} name={nameOf(entry.node_id)} />)
      )}
      {canSeries && nodes.length > 0 && <History nodes={nodes} nameOf={nameOf} />}
      <Thresholds thresholds={health?.thresholds} />
    </section>
  )
}
