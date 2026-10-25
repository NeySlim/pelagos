// SPDX-License-Identifier: Apache-2.0
// The cluster trace tile (Instrument and the plain families): this node and its peer as
// cards joined by a signal link, then the strip-chart recorder (DNS queries, DHCP leases,
// HA heartbeats measured from Kea, events from the WebSocket) with its readouts, legend,
// sample count, scale bar and window. Everything that moves is a real event or sample.
import { useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Pulse } from '@phosphor-icons/react'
import { AmbientDots, ClusterTrace, HeartbeatTrace, RollingNumber, ScaleBar, SignalLink, SwapText } from '../../components/motion'
import { useElementSize } from '../../hooks/useElementSize'
import { useHaHeartbeats, useTraceEvents, observeNodeVersion } from '../../hooks/useClusterSignals'
import { usePermission } from '../../hooks/usePermission'
import { useAuth } from '../../contexts/AuthContext'
import { DEFAULT_WINDOW, TRACE_WINDOWS, scaleBar } from '../../lib/trace'
import { cn, formatRelativeTime } from '../../lib/utils'
import { LiveStatus, TileFrame } from './tiles'
import { TileRefresh } from './tileRefresh'
import { rateFormat, splitRate } from './summary'
import { clockOffset, haFamilies, heartbeatOf, heartbeatReadout, linkOf, nodeEngines, topology, traceLanes } from './traceModel'

const WINDOW_KEY = 'pelagos-trace-window'
const ENGINE_INK = { dns: 'var(--accent-primary)', dhcp: 'var(--accent-pro)', ok: 'var(--accent-success)' }

const readWindow = () => {
  try {
    const v = Number(sessionStorage.getItem(WINDOW_KEY))
    return TRACE_WINDOWS.includes(v) ? v : DEFAULT_WINDOW
  } catch {
    return DEFAULT_WINDOW
  }
}

function NodeCard({ node, self, engines, families, heartbeats, testId }) {
  const { t } = useTranslation(['dashboard', 'common'])
  const online = !node.status || node.status === 'online'
  return (
    <div className={cn('trace-node', !online && 'is-offline')} data-testid={testId}>
      {families.length > 0 && (
        <span className="trace-node-hb" title={t('trace.heartbeats')}>
          {families.map((f) => {
            const rec = heartbeats?.[`${f}:${node.peer.id}`]
            return <HeartbeatTrace key={f} beat={rec?.beats?.[0]?.t ?? null} lost={rec?.inTouch === false} label={`${t('trace.heartbeat')} ${f}`} />
          })}
        </span>
      )}
      <div className="trace-node-name">
        <span className={cn('fx-dot', online ? 'fx-tone-success' : 'fx-tone-danger')} role="img" aria-label={t(`common:status.${node.status || 'unknown'}`)} />
        <span className="font-mono">{node.peer.name}</span>
        {self && <span className="trace-node-self">{t('tiles.nodes.self')}</span>}
      </div>
      <div className="trace-node-meta">
        <span>v{node.version || '?'}</span>
        <span>
          {t('trace.config')} <RollingNumber value={node.config_version ?? '?'} />
        </span>
        <span>
          {t('trace.audit')} <RollingNumber value={node.audit_count ?? '?'} />
        </span>
      </div>
      <div className="trace-node-engines">
        {engines.map((e) => (
          <span key={e.key}>
            <i className="fx-dot" style={{ '--fx-c': ENGINE_INK[e.tone] }} />
            {e.label}
          </span>
        ))}
      </div>
    </div>
  )
}

function RangeSegment({ value, onChange, labels }) {
  const ref = useRef(null)
  const [thumb, setThumb] = useState(null)
  useEffect(() => {
    const b = ref.current?.querySelector('[aria-pressed="true"]')
    if (b) setThumb({ x: b.offsetLeft, w: b.offsetWidth })
  }, [value])
  return (
    <span ref={ref} className="trace-range" role="group" aria-label={labels.group} data-testid="trace-range">
      {thumb && <span className="trace-range-thumb" style={{ transform: `translateX(${thumb.x}px) scaleX(${thumb.w / 10})` }} aria-hidden="true" />}
      {TRACE_WINDOWS.map((w) => (
        <button key={w} type="button" aria-pressed={w === value} onClick={() => onChange(w)} data-window={w}>
          {labels[w]}
        </button>
      ))}
    </span>
  )
}

const REVEAL_KEY = 'pelagos-trace-revealed'
function firstReveal() {
  try {
    if (sessionStorage.getItem(REVEAL_KEY) === '1') return false
    sessionStorage.setItem(REVEAL_KEY, '1')
    return true
  } catch {
    return false
  }
}

export function TraceTile({ summary, editing, live, samples = 0 }) {
  const { t, i18n } = useTranslation(['dashboard', 'common'])
  const lang = i18n.language
  const pulses = useContext(TileRefresh)?.pulses
  const { hasPermission } = usePermission()
  const { modules } = useAuth()
  const nodes = useMemo(() => summary?.nodes || [], [summary?.nodes])
  const ha = useMemo(() => (summary?.ha || []).filter((h) => h.enabled !== false), [summary?.ha])
  const { self, peer, more } = topology(nodes)
  const families = useMemo(() => haFamilies(ha), [ha])
  const heartbeats = useHaHeartbeats(families, { enabled: hasPermission('read:dhcp') && families.length > 0 })
  const link = linkOf(self, peer, ha)
  const linkRef = useRef(null)
  const traceRef = useRef(null)
  const [windowMs, setWindowMs] = useState(readWindow)
  // The pen draws the history once per session: the first time the trace shows.
  const [reveal] = useState(firstReveal)
  const [sizeRef, size] = useElementSize()

  // Link signals for the events that travel between the nodes.
  const onEvent = useCallback((e) => {
    const l = linkRef.current
    if (!l) return
    if (e.kind === 'repl') l.pulse({ tone: 'neutral' })
    else if (e.kind === 'axfr') l.transfer({ tone: 'dns', label: String(e.params?.subject || '').replace(/^zone:/, '').replace(/@.*$/, '') })
    else if (e.kind === 'ha') l.pulse({ tone: 'dhcp', dir: 'back' })
  }, [])
  const events = useTraceEvents(onEvent)
  useEffect(() => {
    for (const n of nodes) {
      const e = observeNodeVersion(n)
      if (e) onEvent(e)
    }
  }, [nodes, onEvent])

  // A heartbeat answered by the partner crosses the link back to this node.
  const selfBeat = self && families[0] ? heartbeatOf(heartbeats, families[0], self.peer.id)?.beats?.[0]?.t : undefined
  const lastBeat = useRef(selfBeat)
  useEffect(() => {
    if (selfBeat !== undefined && lastBeat.current !== undefined && Math.abs(selfBeat - lastBeat.current) > 1000) linkRef.current?.tick({ tone: 'success', dir: 'back' })
    lastBeat.current = selfBeat
  }, [selfBeat])

  // The server clock offset, measured when a new sample arrives.
  const series = live?.dns?.enabled ? live.dns.series : live?.dhcp?.series || []
  const lastT = series[series.length - 1]?.t
  const [offset, setOffset] = useState(0)
  const seenT = useRef(lastT)
  useEffect(() => {
    if (lastT === undefined || lastT === seenT.current) return
    seenT.current = lastT
    setOffset(clockOffset(lastT, Date.now()))
  }, [lastT])

  const format = useMemo(() => ({ dns: (v) => `${rateFormat(lang)(v)} q/s`, dhcp: (v) => `${rateFormat(lang)(v)} /s` }), [lang])
  const labels = useMemo(
    () => ({
      dns: t('trace.lanes.dns'),
      dnsUnit: t('trace.units.dns'),
      dhcp: t('trace.lanes.dhcp'),
      dhcpUnit: t('trace.units.dhcp'),
      hb: t('trace.lanes.hb'),
      events: t('trace.lanes.events'),
    }),
    [t],
  )
  const lanes = useMemo(
    () => traceLanes({ live, heartbeats, events, families, selfId: self?.peer.id, labels, format }),
    [live, heartbeats, events, families, self?.peer.id, labels, format],
  )
  const traceLabels = useMemo(() => ({ now: t('live.now'), hbInterval: t('trace.hbInterval'), keys: t('trace.keys') }), [t])
  const eventLabel = useCallback(
    (e) => {
      const p = e.params || {}
      return t(e.key ? `trace.${e.key}` : `trace.events.${e.kind}`, {
        ...p,
        kind: p.kind ? t(`kinds.${p.kind}`, { defaultValue: p.kind }) : '',
        state: p.state ? t(`common:status.${p.state}`, { defaultValue: p.state }) : '',
        subject: String(p.subject || '').replace(/^zone:/, ''),
      })
    },
    [t],
  )

  const pickWindow = (w) => {
    setWindowMs(w)
    try {
      sessionStorage.setItem(WINDOW_KEY, String(w))
    } catch {
      // the window resets to 90 s next time
    }
  }

  const dnsNow = live?.dns?.enabled ? splitRate(live.dns.current, lang) : null
  const dhcpNow = live?.dhcp?.enabled ? live.dhcp.current : null
  const hb = heartbeatReadout(heartbeats, families, self?.peer.id)
  const lastEvent = events[events.length - 1]
  const bar = scaleBar(windowMs, Math.max(0, size.width - 16))
  const clock = lastT ? new Date(lastT).toLocaleTimeString(lang, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }) : null
  const active = live?.dns?.current !== null && live?.dns?.current !== undefined
  const peerName = peer?.peer.name || ''
  const linkStatus = link ? t(`trace.link.${link.status}`, { name: peerName, count: link.behind }) : ''
  const engineOpts = { dhcpv6: Boolean(modules?.dhcpv6) || ha.some((h) => h.family === 'v6') }

  return (
    <TileFrame
      id="trace"
      icon={Pulse}
      title={t('tiles.trace.title')}
      link="/nodes"
      linkLabel={t('tiles.trace.nodes')}
      editing={editing}
      status={
        <>
          <LiveStatus active={active} />
          {clock && <span className="dash-clock" data-testid="trace-clock">{clock}</span>}
        </>
      }
      bodyClassName="p-0 overflow-hidden"
      ambient={<AmbientDots pulse={pulses?.trace} />}
      className="dash-hero"
    >
      <div className="trace-tile" data-testid="cluster-trace-tile">
        {self && (
          <div className={cn('trace-topo', !peer && 'is-single')} data-testid="trace-topology">
            <NodeCard node={self} self engines={nodeEngines(self, engineOpts)} families={families} heartbeats={heartbeats} testId="trace-node" />
            {peer && (
              <SignalLink
                ref={linkRef}
                className="trace-link"
                state={link.state}
                rate={dhcpNow || 0}
                tickTone="dhcp"
                labelTop={t('trace.link.label')}
                labelBottom={<SwapText text={linkStatus} />}
                testId="trace-link"
              />
            )}
            {peer && (
              <div className="trace-peer">
                <NodeCard node={peer} engines={nodeEngines(peer, engineOpts)} families={families} heartbeats={heartbeats} testId="trace-node" />
                {more > 0 && <span className="trace-more">{t('trace.more', { count: more })}</span>}
              </div>
            )}
          </div>
        )}
        <div className="trace-lanes">
          <div ref={sizeRef} className="trace-plot">
            <ClusterTrace
              ref={traceRef}
              lanes={lanes}
              windowMs={windowMs}
              reveal={reveal}
              clockOffset={offset}
              locale={lang}
              labels={traceLabels}
              eventLabel={eventLabel}
              ariaLabel={t('trace.aria', { window: t(`trace.windows.${windowMs}`) })}
              testId="cluster-trace"
            />
          </div>
          <div className="trace-values" data-testid="trace-values">
            {dnsNow && (
              <div className="trace-value" style={{ '--fx-c': 'var(--accent-primary)' }}>
                <span>{t('trace.units.dns')}</span>
                <b data-testid="trace-dns-rate">
                  <RollingNumber value={dnsNow.n} delta={false} />
                  <RollingNumber className="trace-unit" value={dnsNow.u} delta={false} />
                </b>
              </div>
            )}
            {live?.dhcp?.enabled && (
              <div className="trace-value" style={{ '--fx-c': 'var(--accent-pro)' }}>
                <span>{t('trace.units.dhcp')}</span>
                <b>
                  <RollingNumber value={dhcpNow === null ? '-' : rateFormat(lang)(dhcpNow)} delta={false} />
                </b>
              </div>
            )}
            {families.length > 0 && (
              <div className="trace-value" data-testid="trace-heartbeat">
                <span>{t('trace.heartbeat')}</span>
                {hb?.lost ? (
                  <b className="is-bad">
                    {t('trace.noHeartbeat')}
                    <small>{hb.since ? t('trace.downSince', { when: formatRelativeTime(new Date(hb.since).toISOString(), t) }) : ''}</small>
                  </b>
                ) : (
                  <b className="is-hb">
                    {hb?.mean ? `${(hb.mean / 1000).toFixed(2)} s` : '-'}
                    {hb?.sd !== null && hb?.sd !== undefined && hb?.mean ? <em> ±{Math.round(hb.sd)} ms</em> : null}
                    <small>{hb?.state ? t(`common:status.${hb.state}`, { defaultValue: hb.state }) : t('trace.measuring')}</small>
                  </b>
                )}
              </div>
            )}
            <div className="trace-value">
              <span>{t('trace.lastEvent')}</span>
              <b className="is-text" title={lastEvent ? eventLabel(lastEvent) : undefined} data-testid="trace-last-event">
                <SwapText text={lastEvent ? eventLabel(lastEvent) : t('trace.noEvent')} />
              </b>
            </div>
          </div>
        </div>
        <div className="trace-foot">
          <span className="trace-legend" style={{ '--fx-c': 'var(--accent-primary)' }}>
            <i />
            {t('trace.legend.dns')}
          </span>
          <span className="trace-legend" style={{ '--fx-c': 'var(--accent-pro)' }}>
            <i />
            {t('trace.legend.dhcp')}
          </span>
          {families.length > 0 && (
            <span className="trace-legend is-tick" style={{ '--fx-c': 'var(--accent-success)' }}>
              <i />
              {t('trace.legend.heartbeat')}
            </span>
          )}
          <span className="trace-legend is-mark" style={{ '--fx-c': 'var(--accent-primary)' }}>
            <i />
            {t('trace.legend.plan')}
          </span>
          <span className="trace-legend is-mark is-round" style={{ '--fx-c': 'var(--accent-danger)' }}>
            <i />
            {t('trace.legend.alert')}
          </span>
          <span className="trace-legend is-mark is-diamond" style={{ '--fx-c': 'var(--text-secondary)' }}>
            <i />
            {t('trace.legend.replication')}
          </span>
          <span className="trace-foot-right">
            <span className="trace-count" data-testid="trace-count">
              n <RollingNumber value={String(samples).padStart(5, '0')} delta={false} />
            </span>
            <ScaleBar ratio={bar.ratio} label={bar.label} />
            <RangeSegment
              value={windowMs}
              onChange={pickWindow}
              labels={{ group: t('trace.window'), ...Object.fromEntries(TRACE_WINDOWS.map((w) => [w, t(`trace.windows.${w}`)])) }}
            />
          </span>
        </div>
      </div>
    </TileFrame>
  )
}

export default TraceTile
