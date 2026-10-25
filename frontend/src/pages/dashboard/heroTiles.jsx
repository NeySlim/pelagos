// SPDX-License-Identifier: Apache-2.0
// Hero row of the dashboard: the cluster trace between a DNS panel (query rate strip,
// rcodes) and a DHCP panel (lease rate strip, the latest exchange and lease as DORA ticks, the
// busiest pools against their thresholds, HA pills). Mission Control keeps its radar in
// the center, loaded on demand under its effects only. Live rates come from useLiveRates
// through DashboardPage.
import { Suspense, lazy } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { Globe, Network } from '@phosphor-icons/react'
import { AmbientSpectrum, AmbientWave, Dora, MiniHistogram, RollingNumber, StatusDot, StripChart } from '../../components/motion'
import { UtilizationBar } from '../../components/UtilizationBar'
import { useEffectsLayer } from '../../contexts/ThemeContext'
import { cn } from '../../lib/utils'
import { LIVE_CAPACITY, LIVE_INTERVAL_MS, LIVE_MIN_SLOTS, RCODES, latest, latestExchange, share } from '../../lib/liveRates'
import { LiveStatus, TileFrame } from './tiles'
import { TraceTile } from './traceTile'
import { LatestLease } from './LatestLease'
import { dhcpFamily, haTone, poolThresholds, rateFormat, splitRate } from './summary'

const MissionRadarTile = lazy(() => import('./radarTile'))

const RCODE_TONE = { NOERROR: 'success', NXDOMAIN: 'warning', SERVFAIL: 'danger', REFUSED: 'neutral' }
const HISTOGRAM_BARS = 12
const SAMPLE_RATE = `${+(1000 / LIVE_INTERVAL_MS).toFixed(2)} S/s`

const peakOf = (series) => series.reduce((m, p) => Math.max(m, p.v), 0)
const timeOf = (lang) => (t) => (t ? new Date(t).toLocaleTimeString(lang, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }) : '')

function Collecting({ height }) {
  const { t } = useTranslation('dashboard')
  return (
    <div className="dash-collecting" style={{ height }} data-testid="tile-collecting">
      <StatusDot tone="primary" pulse />
      {t('live.collecting')}
    </div>
  )
}

function Sub({ children, right }) {
  return (
    <div className="dash-sub">
      <span>{children}</span>
      {right && <span className="dash-sub-right">{right}</span>}
    </div>
  )
}

// The center tile: the radar under Mission Control, the trace everywhere else.
export function ClusterTile(props) {
  if (useEffectsLayer() === 'mission') {
    return (
      <Suspense fallback={<div className="h-full card-soft" data-testid="tile-trace" />}>
        <MissionRadarTile {...props} />
      </Suspense>
    )
  }
  return <TraceTile {...props} />
}

export function DnsTile({ summary, editing, live, samples }) {
  const { t, i18n } = useTranslation(['dashboard', 'common'])
  const lang = i18n.language
  const dns = live?.dns
  const series = (dns?.series || []).slice(-LIVE_CAPACITY)
  const current = dns?.current
  const nx = share(dns?.rcodes, 'NXDOMAIN')
  const zones = summary?.zones || []
  const format = rateFormat(lang)
  const rate = splitRate(current, lang)
  return (
    <TileFrame
      id="dns"
      icon={Globe}
      title={t('tiles.dns.title')}
      link="/dns/instances"
      linkLabel={t('viewAll')}
      editing={editing}
      status={<LiveStatus active={current !== null && current !== undefined} />}
      ambient={<AmbientWave rate={current ?? 0} peak={peakOf(series)} tone="primary" />}
    >
      {!dns?.enabled ? (
        <p className="text-xs text-text-tertiary italic">{t('tiles.dns.none')}</p>
      ) : (
        <div className="dash-hero-body">
          <div className="dash-stats">
            <div className="dash-stat" style={{ '--fx-c': 'var(--accent-primary)' }}>
              <span className="dash-stat-label">{t('tiles.dns.rate')}</span>
              <span className="dash-stat-value">
                {current === null || current === undefined ? '-' : <RollingNumber value={rate.n} data-testid="dns-rate" />}
                <RollingNumber className="dash-unit" value={rate.u} delta={false} />
              </span>
            </div>
            <div className="dash-stat is-warn">
              <span className="dash-stat-label">{t('tiles.dns.nxdomain')}</span>
              <span className="dash-stat-value">
                {nx === null ? '-' : <RollingNumber value={format(nx)} />}
                <span className="dash-unit">%</span>
              </span>
            </div>
          </div>
          <Sub right={t('tiles.dns.zones', { count: zones.length })}>{t('tiles.dns.chart')}</Sub>
          {series.length < 2 ? (
            <Collecting height={104} />
          ) : (
            <StripChart
              points={series}
              kind="line"
              tone="dns"
              height={104}
              channel="CH1"
              unit="q/s"
              rate={SAMPLE_RATE}
              count={samples}
              format={(v) => t('tiles.dns.perSecond', { rate: format(v) })}
              formatTime={timeOf(lang)}
              label={t('tiles.dns.chartLabel', { rate: format(current ?? 0) })}
              testId="dns-strip"
            />
          )}
          <ul className="dash-list" data-testid="dns-rcodes">
            {RCODES.map((r) => {
              const points = dns?.rcodes?.[r] || []
              const v = latest(points)
              return (
                <li key={r} className="dash-list-row" data-testid="dns-rcode">
                  <StatusDot tone={RCODE_TONE[r]} />
                  <span className="font-mono text-text-secondary flex-1 min-w-0 truncate">{r}</span>
                  <span className="font-mono text-text-primary tabular-nums">{v === null ? '-' : <RollingNumber value={t('tiles.dns.perSecond', { rate: format(v) })} delta={false} />}</span>
                  <MiniHistogram data={points.slice(-HISTOGRAM_BARS).map((p) => p.v)} tone="primary" height={12} barWidth={2} gap={1} />
                </li>
              )
            })}
          </ul>
        </div>
      )}
    </TileFrame>
  )
}

function LatestExchange({ dhcp, family }) {
  const { t, i18n } = useTranslation(['dashboard', 'common'])
  const ex = latestExchange(dhcp)
  const format = (v) => (v === null || v === undefined ? '-' : rateFormat(i18n.language)(v))
  const v6 = family === 'v6'
  const keys = ['discover', 'offer', 'request', 'ack']
  const values = keys.map((k, i) => (i === 3 && ex?.nak ? t('tiles.dhcp.nak') : format(ex?.rates?.[k])))
  return (
    <div className="dash-lease" data-testid="dhcp-latest" title={keys.map((k, i) => `${t(`tiles.dhcp.steps.${v6 ? 'v6' : 'v4'}.${k}`)} ${values[i]}/s`).join(', ')}>
      <span className="dash-lease-who">
        <b>{ex ? t('tiles.dhcp.exchange', { count: ex.leases }) : '-'}</b>
        <span>{v6 ? 'DHCPv6' : 'DHCPv4'}</span>
      </span>
      <Dora beat={ex && ex.leases > 0 ? ex.t : null} nak={ex?.nak} labels={v6 ? ['S', 'A', 'R', 'R'] : ['D', 'O', 'R', 'A']} values={ex ? values : []} />
      <span className="dash-lease-when">{ex ? `${t('tiles.dhcp.perSecond')} · ${timeOf(i18n.language)(ex.t)}` : ''}</span>
    </div>
  )
}

export function DhcpTile({ summary, editing, live, thresholds, nameOf, samples }) {
  const { t, i18n } = useTranslation(['dashboard', 'common'])
  const lang = i18n.language
  const family = dhcpFamily(summary)
  const { warn, full } = poolThresholds(summary, thresholds)
  const pools = [...(summary?.pools || [])].sort((a, b) => b.percent - a.percent)
  const hot = pools.filter((p) => p.percent >= warn).length
  const ha = (summary?.ha || []).filter((h) => h.enabled !== false)
  const dhcp = live?.dhcp
  const series = (dhcp?.series || []).slice(-LIVE_CAPACITY)
  const current = dhcp?.current
  const format = rateFormat(lang)
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
      <div className="dash-hero-body">
        <div className="dash-stats">
          <div className="dash-stat" style={{ '--fx-c': 'var(--accent-pro)' }}>
            <span className="dash-stat-label">{t('tiles.dhcp.rate')}</span>
            <span className="dash-stat-value">{current === null || current === undefined ? '-' : <RollingNumber value={format(current)} data-testid="dhcp-rate" />}</span>
          </div>
          <div className={cn('dash-stat', hot && 'is-warn')}>
            <span className="dash-stat-label">{t('tiles.dhcp.hot')}</span>
            <span className="dash-stat-value">
              <RollingNumber value={hot} />
            </span>
          </div>
        </div>
        {dhcp?.enabled && (
          <>
            <Sub>{t('tiles.dhcp.chart')}</Sub>
            {series.length < 2 ? (
              <Collecting height={72} />
            ) : (
              <StripChart
                points={series}
                kind="bars"
                tone="dhcp"
                height={72}
                channel="CH2"
                unit="leases/s"
                rate={SAMPLE_RATE}
                count={samples}
                format={(v) => t('tiles.dns.perSecond', { rate: format(v) })}
                formatTime={timeOf(lang)}
                label={t('tiles.dhcp.chartLabel', { rate: format(current ?? 0) })}
                testId="dhcp-strip"
              />
            )}
            <Sub right={family === 'v6' ? 'SARR' : 'DORA'}>{t('tiles.dhcp.latest')}</Sub>
            <LatestExchange dhcp={dhcp} family={family} />
          </>
        )}
        <LatestLease family={family} />
        {pools.length > 0 && (
          <>
            <Sub>{t('tiles.dhcp.pools')}</Sub>
            <ul className="dash-pools">
              {pools.slice(0, 3).map((p) => (
                <li key={`${p.node_id}/${p.engine}/${p.subnet_id}/${p.pool}`} className={cn('dash-pool', p.percent >= full ? 'is-full' : p.percent >= warn && 'is-hot')} data-testid="dhcp-pool">
                  <span className="dash-pool-name" title={`${p.pool} (${p.subnet}, ${nameOf(p.node_id)})`}>
                    {p.pool}
                  </span>
                  <span className="dash-pool-pct">
                    <RollingNumber value={`${Math.round(p.percent)}%`} />
                  </span>
                  <UtilizationBar assigned={p.assigned} total={p.total} percent={p.percent} warn={warn} full={full} size="sm" showNumbers={false} label={`${p.pool} (${p.subnet})`} className="dash-pool-bar" />
                </li>
              ))}
            </ul>
          </>
        )}
        {ha.length > 0 && (
          <>
            <Sub>{t('tiles.dhcp.ha')}</Sub>
            <div className="dash-pills">
              {ha.map((h) => (
                <Link
                  key={`${h.node_id}/${h.family}`}
                  to={`/dhcp/${h.family === 'v6' ? 'v6' : 'v4'}/ha`}
                  className={cn('dash-pill', `fx-tone-${haTone(h)}`)}
                  title={t(`common:status.${h.state}`, { defaultValue: h.state })}
                  data-testid="dhcp-ha-pill"
                >
                  <StatusDot tone={haTone(h)} size={5} />
                  <span className="font-mono">{h.server_name || nameOf(h.node_id)}</span>
                  <span className="dash-pill-family">{h.family === 'v6' ? 'v6' : 'v4'}</span>
                </Link>
              ))}
            </div>
          </>
        )}
      </div>
    </TileFrame>
  )
}
