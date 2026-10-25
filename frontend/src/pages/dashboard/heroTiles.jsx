// SPDX-License-Identifier: Apache-2.0
// Hero row of the dashboard: the cluster radar between a DNS panel (query rate as a
// stippled area, rcode sparklines) and a DHCP panel (lease rate, pool segments, HA
// pills). Live rates come from useLiveRates through DashboardPage (live.js).
import { useContext, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useNavigate } from 'react-router-dom'
import { Crosshair, Globe, Network, HardDrives, WarningDiamond, ArrowsLeftRight } from '@phosphor-icons/react'
import { AmbientDots, AmbientSpectrum, AmbientTile, AmbientWave, CountUp, IconButton, MiniHistogram, Readout, Ruler, ScaleBar, SegmentedProgress, StatChip, StatusDot, StippledAreaChart } from '../../components/motion'
import { cn } from '../../lib/utils'
import { TileFrame } from './tiles'
import { TileRefresh } from './tileRefresh'
import { ClusterRadar } from './ClusterRadar'
import { LIVE_CAPACITY, LIVE_INTERVAL_MS, LIVE_MIN_SLOTS, RCODES, latest, liveWindowLabel, liveWindowSeconds, share } from '../../lib/liveRates'
import { haTone, utilizationSegments } from './radarLayout'
import { dhcpFamily, poolThresholds } from './summary'
import { useElementSize } from '../../hooks/useElementSize'

const RCODE_TONE = { NOERROR: 'success', NXDOMAIN: 'warning', SERVFAIL: 'danger', REFUSED: 'neutral' }
const HISTOGRAM_BARS = 22

const fmt = (lang, digits = 1) => (v) => new Intl.NumberFormat(lang, { maximumFractionDigits: v < 10 ? digits : 0 }).format(v)
const timeOf = (lang) => (p) => (p?.t ? new Date(p.t).toLocaleTimeString(lang, { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '')

// Width of the value ruler: the chart keeps its own gutter so the ticks never cover data.
const RULER_WIDTH = 28
const SCALE_BASE = 60
const peakOf = (series) => series.reduce((m, p) => Math.max(m, p.v), 0)
const lastTime = (series) => series[series.length - 1]?.t

// Samples seen on a channel: the window size at mount, then one more per new sample.
function useSampleCount(series) {
  const t = lastTime(series)
  const seen = useRef(t)
  const [count, setCount] = useState(series.length)
  useEffect(() => {
    if (t === undefined || seen.current === t) return
    seen.current = t
    setCount((n) => n + 1)
  }, [t])
  return count
}

// Round reference of the scale bar: 10 s under a minute of window, then 1 min.
function scaleReference(windowSeconds, chartWidth, t) {
  const ref = windowSeconds < 60 ? 10 : 60
  const px = (ref / windowSeconds) * chartWidth
  return {
    ratio: Math.min(chartWidth, px) / SCALE_BASE,
    label: ref < 60 ? t('live.span.seconds', { seconds: ref }) : t('live.span.minutes', { minutes: 1 }),
  }
}

function LiveStatus({ active }) {
  const { t } = useTranslation('dashboard')
  return (
    <span className="inline-flex items-center gap-1.5 text-2xs text-text-tertiary" data-testid="tile-live">
      {t('live.label')}
      <StatusDot tone={active ? 'success' : 'neutral'} pulse={active} />
    </span>
  )
}

function Collecting() {
  const { t } = useTranslation('dashboard')
  return (
    <div className="flex items-center justify-center gap-2 text-xs text-text-tertiary h-full min-h-[3rem]" data-testid="tile-collecting">
      <StatusDot tone="primary" pulse />
      {t('live.collecting')}
    </div>
  )
}

function Label({ children, right }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-x-2 gap-y-0.5 mb-1.5">
      <span className="dash-label whitespace-nowrap">{children}</span>
      {right}
    </div>
  )
}

export function RadarTile({ summary, openAlerts, editing, live }) {
  const { t } = useTranslation(['dashboard', 'common'])
  const navigate = useNavigate()
  const [ref, size] = useElementSize()
  const nodes = summary?.nodes || []
  const zones = summary?.zones || []
  const ha = (summary?.ha || []).filter((h) => h.enabled !== false)
  const family = dhcpFamily(summary)
  const online = nodes.filter((n) => n.status === 'online').length
  const divergent = zones.filter((z) => z.divergent).length
  const compact = size.width > 0 && size.width < 560
  const pulses = useContext(TileRefresh)?.pulses
  return (
    <TileFrame
      id="radar"
      icon={Crosshair}
      title={t('tiles.radar.title')}
      editing={editing}
      status={<LiveStatus active={live?.dns.current !== null && live?.dns.current !== undefined} />}
      bodyClassName="p-0 overflow-hidden relative"
      className="dash-hero"
      ambient={<AmbientDots pulse={pulses?.radar} />}
    >
      <div ref={ref} className="absolute inset-0">
        <ClusterRadar
          nodes={nodes}
          zones={zones}
          ha={ha}
          alerts={openAlerts || []}
          rates={live?.dns.byNode || {}}
          totalRate={live?.dns.enabled ? live.dns.current : null}
          compact={compact}
        />
        {!compact && (
          <div className="absolute left-3 top-3 flex flex-col gap-2 pointer-events-none" data-testid="radar-chips">
            <StatChip icon={HardDrives} tone={online === nodes.length ? 'success' : 'danger'} label={t('tiles.radar.nodes')} value={t('tiles.radar.online', { online, total: nodes.length })} />
            <StatChip icon={Globe} tone={divergent ? 'warning' : 'success'} label={t('tiles.radar.zones')} value={t('tiles.radar.zonesValue', { total: zones.length, count: divergent })} />
          </div>
        )}
        {!compact && (
        <div className="absolute right-3 top-3 flex flex-col gap-2" data-testid="radar-controls">
          <IconButton icon={HardDrives} label={t('tiles.nodes.title')} onClick={() => navigate('/nodes')} />
          <IconButton icon={WarningDiamond} label={t('tiles.inconsistencies.title')} onClick={() => navigate('/alerts')} />
          <IconButton icon={Globe} label={t('tiles.zones.title')} onClick={() => navigate('/dns/zones')} />
          <IconButton icon={ArrowsLeftRight} label={t('tiles.ha.title')} onClick={() => navigate(`/dhcp/${family}/ha`)} />
        </div>
        )}
      </div>
    </TileFrame>
  )
}

export function DnsTile({ summary, editing, live }) {
  const { t, i18n } = useTranslation(['dashboard', 'common'])
  const dns = live?.dns
  const series = dns?.series || []
  const current = dns?.current
  const nx = share(dns?.rcodes, 'NXDOMAIN')
  const zones = summary?.zones || []
  const format = fmt(i18n.language)
  const [chartRef, chartSize] = useElementSize()
  const samples = useSampleCount(series)
  const peak = peakOf(series)
  const sampleRate = t('live.sampleRate', { rate: new Intl.NumberFormat(i18n.language).format(1000 / LIVE_INTERVAL_MS) })
  const chartWidth = Math.max(0, chartSize.width - RULER_WIDTH)
  const scale = series.length >= 2 ? scaleReference(liveWindowSeconds(series.length), chartWidth, t) : null
  return (
    <TileFrame
      id="dns"
      icon={Globe}
      title={t('tiles.dns.title')}
      link="/dns/instances"
      linkLabel={t('viewAll')}
      editing={editing}
      status={<LiveStatus active={current !== null && current !== undefined} />}
    >
      {!dns?.enabled ? (
        <p className="text-xs text-text-tertiary italic">{t('tiles.dns.none')}</p>
      ) : (
        <div className="flex flex-col gap-3 h-full">
          <div className="grid grid-cols-2 gap-2">
            <StatChip tone="primary" label={t('tiles.dns.rate')} value={current === null || current === undefined ? '-' : <CountUp value={current} format={format} />} className="dash-chip" data-testid="dns-rate" />
            <StatChip tone="warning" label={t('tiles.dns.nxdomain')} value={nx === null ? '-' : <CountUp value={nx} format={(v) => `${fmt(i18n.language)(v)} %`} />} className="dash-chip" />
          </div>
          <div className="dash-subpanel relative isolate flex-1 min-h-[120px] flex flex-col">
            {/* The wave sits inside the panel, under its content: the panel itself is opaque. */}
            <AmbientTile className="is-under">
              <AmbientWave rate={current ?? 0} peak={peak} tone="primary" />
            </AmbientTile>
            <Label right={<span className="text-3xs text-text-tertiary whitespace-nowrap">{t('tiles.dns.zones', { count: zones.length })}</span>}>
              {t('tiles.dns.chart')}
            </Label>
            <div ref={chartRef} className="relative flex-1 min-h-[64px]">
              <div className="absolute inset-y-0 left-0" style={{ right: RULER_WIDTH }}>
                {series.length < 2 ? (
                  <Collecting />
                ) : (
                  <StippledAreaChart
                    points={series.map((p) => ({ value: p.v, t: p.t }))}
                    capacity={LIVE_CAPACITY}
                    height={Math.max(64, chartSize.height)}
                    step={6}
                    label={t('tiles.dns.chartLabel', { rate: format(current ?? 0) })}
                    formatValue={(v) => t('tiles.dns.perSecond', { rate: format(v) })}
                    formatLabel={timeOf(i18n.language)}
                  />
                )}
              </div>
              {series.length >= 2 && <Ruler max={peak} cursor={current ?? undefined} inset={6} format={format} />}
              <Readout className="absolute left-2 top-0 pointer-events-none" channel="CH1" unit={t('live.readout.qps')} rate={sampleRate} count={samples} />
            </div>
            <div className="flex items-center justify-between text-3xs text-text-tertiary mt-1">
              <span>{liveWindowLabel(t, series.length)}</span>
              {scale && <ScaleBar ratio={scale.ratio} label={scale.label} />}
              <span>{t('live.now')}</span>
            </div>
          </div>
          <ul className="space-y-1.5" data-testid="dns-rcodes">
            {RCODES.map((r) => {
              const points = dns?.rcodes?.[r] || []
              const v = latest(points)
              return (
                <li key={r} className="dash-row" data-testid="dns-rcode">
                  <StatusDot tone={RCODE_TONE[r]} />
                  <span className="font-mono text-2xs text-text-secondary shrink-0">{r}</span>
                  <span className="text-xs text-text-primary tabular-nums flex-1 min-w-0 text-right truncate">{v === null ? '-' : t('tiles.dns.perSecond', { rate: format(v) })}</span>
                  <span className="shrink-0 flex justify-end">
                    <MiniHistogram data={points.slice(-HISTOGRAM_BARS).map((p) => p.v)} tone="primary" height={16} barWidth={2} gap={1} />
                  </span>
                </li>
              )
            })}
          </ul>
        </div>
      )}
    </TileFrame>
  )
}

export function DhcpTile({ summary, editing, live, thresholds, nameOf }) {
  const { t, i18n } = useTranslation(['dashboard', 'common'])
  const family = dhcpFamily(summary)
  const { warn, full } = poolThresholds(summary, thresholds)
  const pools = [...(summary?.pools || [])].sort((a, b) => b.percent - a.percent)
  const hot = pools.filter((p) => p.percent >= warn).length
  const ha = (summary?.ha || []).filter((h) => h.enabled !== false)
  const dhcp = live?.dhcp
  const series = dhcp?.series || []
  const current = dhcp?.current
  const format = fmt(i18n.language)
  const [ref, size] = useElementSize()
  const samples = useSampleCount(series)
  const sampleRate = t('live.sampleRate', { rate: new Intl.NumberFormat(i18n.language).format(1000 / LIVE_INTERVAL_MS) })
  // Bars widen to fill the panel until the window holds LIVE_CAPACITY points.
  const width = size.width || 240
  const bars = Math.max(LIVE_MIN_SLOTS, Math.min(LIVE_CAPACITY, Math.floor(width / 5), series.length))
  const slot = width / bars
  const barWidth = Math.max(2, Math.min(10, slot * 0.6))
  return (
    <TileFrame
      id="dhcp"
      icon={Network}
      title={t('tiles.dhcp.title')}
      link={`/dhcp/${family}/stats`}
      linkLabel={t('viewAll')}
      editing={editing}
      status={<LiveStatus active={current !== null && current !== undefined} />}
      ambient={<AmbientSpectrum values={series.length >= LIVE_MIN_SLOTS ? series.map((p) => p.v) : []} tone="pro" />}
    >
      <div className="flex flex-col gap-3 h-full">
        <div className="grid grid-cols-2 gap-2">
          <StatChip tone="pro" label={t('tiles.dhcp.rate')} value={current === null || current === undefined ? '-' : <CountUp value={current} format={format} />} className="dash-chip" data-testid="dhcp-rate" />
          <StatChip tone={hot ? 'warning' : 'success'} label={t('tiles.dhcp.hot')} value={<CountUp value={hot} />} className="dash-chip" />
        </div>
        <div className="dash-subpanel" ref={ref}>
          <Label right={<Readout channel="CH2" unit={t('live.readout.lps')} rate={sampleRate} count={samples} />}>{t('tiles.dhcp.chart')}</Label>
          {series.length < 2 ? (
            <div style={{ height: 34 }}>
              <Collecting />
            </div>
          ) : (
            <MiniHistogram
              data={[...Array(Math.max(0, bars - series.length)).fill(0), ...series.slice(-bars).map((p) => p.v)]}
              tone="pro"
              height={34}
              barWidth={barWidth}
              gap={slot - barWidth}
              className="w-full"
              label={t('tiles.dhcp.chartLabel', { rate: format(current ?? 0) })}
            />
          )}
        </div>
        {pools.length > 0 && (
          <div>
            <Label>{t('tiles.dhcp.pools')}</Label>
            <ul className="space-y-2">
              {pools.slice(0, 6).map((p) => (
                <li key={`${p.node_id}/${p.engine}/${p.subnet_id}/${p.pool}`} data-testid="dhcp-pool">
                  <div className="flex items-center gap-2 text-2xs mb-1">
                    <span className="font-mono text-text-secondary truncate flex-1 min-w-0" title={`${p.pool} (${p.subnet}, ${nameOf(p.node_id)})`}>{p.pool}</span>
                    <span className={cn('tabular-nums font-semibold', p.percent >= full ? 'status-danger-text' : p.percent >= warn ? 'status-warning-text' : 'text-text-primary')}>{Math.round(p.percent)}%</span>
                  </div>
                  <SegmentedProgress segments={utilizationSegments(p.percent, { warn, full })} value={p.percent} label={`${p.pool} (${p.subnet})`} height={4} />
                </li>
              ))}
            </ul>
          </div>
        )}
        {ha.length > 0 && (
          <div>
            <Label>{t('tiles.dhcp.ha')}</Label>
            <div className="flex flex-wrap gap-1.5">
              {ha.map((h) => (
                <Link
                  key={`${h.node_id}/${h.family}`}
                  to={`/dhcp/${h.family === 'v6' ? 'v6' : 'v4'}/ha`}
                  className={cn('dash-pill', `fx-tone-${haTone(h)}`)}
                  title={t(`common:status.${h.state}`, { defaultValue: h.state })}
                  data-testid="dhcp-ha-pill"
                >
                  <StatusDot tone={haTone(h)} size={5} />
                  {h.server_name || nameOf(h.node_id)} {h.family === 'v6' ? 'v6' : 'v4'}
                </Link>
              ))}
            </div>
          </div>
        )}
      </div>
    </TileFrame>
  )
}
