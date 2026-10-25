// SPDX-License-Identifier: Apache-2.0
// Cluster radar: the nodes as waypoint pins on a perspective disc, replication links
// as flowing dashes (color and speed by state), zones as blips, alerts as markers,
// the query rate as a beam over the center and the HA servers as a rail of pills.
// Loops are CSS transform animations marked fx-loop, so the motion level stops them.
import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { useElementSize } from '../../hooks/useElementSize'
import { useMessage } from '../../i18n/message'
import { CountUp, PulsingHalo, Reticle, StatusDot } from '../../components/motion'
import { cn } from '../../lib/utils'
import {
  LINK_TONE, NODE_RADIUS, RADAR_SQUASH, alertMarkers, beamDuration, blipPoint, haTone, linkDuration, linkState,
  nodeAngles, nodeTone, polar, project, radarFrame, segment,
} from './radarLayout'
import './radar.css'

function tickPath(count = 90) {
  let d = ''
  for (let i = 0; i < count; i += 1) {
    const a = (i / count) * Math.PI * 2
    const len = i % 5 === 0 ? 3.2 : 1.6
    const [c, s] = [Math.cos(a), Math.sin(a)]
    d += `M${(50 + c * 49.5).toFixed(2)} ${(50 + s * 49.5).toFixed(2)}L${(50 + c * (49.5 - len)).toFixed(2)} ${(50 + s * (49.5 - len)).toFixed(2)}`
  }
  return d
}

const formatRate = (v, lang) => new Intl.NumberFormat(lang, { maximumFractionDigits: v < 10 ? 1 : 0 }).format(v)

export function ClusterRadar({ nodes = [], zones = [], ha = [], alerts = [], rates = {}, totalRate = null, compact = false }) {
  const { t, i18n } = useTranslation(['dashboard', 'common'])
  const msg = useMessage()
  const [ref, size] = useElementSize()
  const ticks = useMemo(() => tickPath(), [])
  const frame = radarFrame(size.width, size.height, { squash: RADAR_SQUASH, top: compact ? 58 : 72, bottom: ha.length ? (compact ? 52 : 62) : 24, side: 16 })

  const self = nodes.find((n) => n.is_self) || nodes[0]
  const angles = nodeAngles(nodes.length)
  const placed = nodes.map((n, i) => ({ node: n, floor: polar(angles[i], nodes.length === 1 ? 0.45 : NODE_RADIUS) }))
  const selfPlaced = placed.find((p) => p.node === self)
  const links = selfPlaced
    ? placed.filter((p) => p !== selfPlaced).map((p) => ({ id: p.node.peer.id, ...linkState(p.node, zones), seg: segment(selfPlaced.floor, p.floor) }))
    : []
  const { byNode, markers } = alertMarkers(alerts, nodes.map((n) => n.peer.id))
  const beam = beamDuration(totalRate)
  const ready = frame.r > 8

  return (
    <div ref={ref} className={cn('radar-stage', compact && 'is-compact')} data-testid="cluster-radar">
      {ready && (
        <>
          <div
            className="radar-floor"
            style={{ left: frame.cx - frame.r, top: frame.cy - frame.r, width: frame.r * 2, height: frame.r * 2, transform: `scaleY(${frame.squash})` }}
            aria-hidden="true"
          >
            <div className="radar-disc" />
            <div className="radar-sweep fx-loop" />
            <svg className="radar-rings" viewBox="0 0 100 100">
              <circle cx="50" cy="50" r="46" />
              <circle cx="50" cy="50" r={NODE_RADIUS * 50} className="radar-ring-nodes" />
              <circle cx="50" cy="50" r="16" />
              <path d="M50 4V96M4 50H96" className="radar-cross" />
            </svg>
            <div className="radar-ticks fx-loop">
              <svg viewBox="0 0 100 100">
                <path d={ticks} />
              </svg>
            </div>
            {zones.map((z) => {
              const p = blipPoint(`${z.view}/${z.zone}`)
              return (
                <span
                  key={`${z.view}/${z.zone}`}
                  className={cn('radar-blip', z.divergent ? 'fx-tone-warning is-hot' : 'fx-tone-success')}
                  style={{ left: `${50 + p.x * 50}%`, top: `${50 + p.y * 50}%` }}
                />
              )
            })}
            {links.map((l) => (
              <span
                key={l.id}
                className={cn('radar-link', `fx-tone-${LINK_TONE[l.state]}`, `is-${l.state}`)}
                style={{ left: `${l.seg.left}%`, top: `${l.seg.top}%`, width: `${l.seg.length}%`, transform: `translate(-50%, -50%) rotate(${l.seg.angle}deg)` }}
                data-testid="radar-link"
                data-state={l.state}
              >
                <span className="radar-link-strip fx-loop" style={linkDuration(l.state) ? { animationDuration: `${linkDuration(l.state)}s` } : { animation: 'none' }} />
              </span>
            ))}
          </div>

          {/* Center: halo, reticle and the query-rate beam rising to its readout. */}
          <span className="radar-center" style={{ left: frame.cx, top: frame.cy }} aria-hidden="true">
            <PulsingHalo tone="primary" size={Math.max(36, frame.r * 0.42)} rings={2} />
          </span>
          <Reticle
            tone="primary"
            size={9}
            className="radar-reticle"
            style={{ left: frame.cx, top: frame.cy, width: frame.r * 0.5, height: Math.max(24, frame.r * 0.5 * frame.squash + 10) }}
            aria-hidden="true"
          />
          <span
            className={cn('fx-flow fx-flow-v fx-tone-primary fx-flow-reverse radar-beam', !beam && 'is-idle')}
            style={{ left: frame.cx, top: compact ? 44 : 54, height: Math.max(0, frame.cy - (compact ? 44 : 54)) }}
            aria-hidden="true"
          >
            <span className="fx-flow-strip fx-loop" style={beam ? { animationDuration: `${beam}s` } : { animation: 'none' }} />
          </span>
          <div className="radar-readout" data-testid="radar-readout">
            <span className="radar-readout-label">{t('radar.queries')}</span>
            <span className="radar-readout-value">
              {totalRate === null ? '-' : <CountUp value={totalRate} format={(v) => formatRate(v, i18n.language)} />}
            </span>
          </div>

          {/* Cluster-wide alerts on the back rim. */}
          {markers.map(({ alert, point }) => {
            const pos = project(point, frame)
            return (
              <Link
                key={alert.id}
                to={`/alerts?severity=${alert.severity}`}
                className={cn('radar-marker', `fx-tone-${alert.severity === 'critical' ? 'danger' : alert.severity === 'warning' ? 'warning' : 'neutral'}`)}
                style={{ left: pos.left, top: pos.top }}
                title={msg(alert.title_message, alert.title)}
                aria-label={msg(alert.title_message, alert.title)}
                data-testid="radar-alert"
              />
            )
          })}

          {placed.map(({ node, floor }) => {
            const pos = project(floor, frame)
            const tone = nodeTone(node, alerts)
            const nodeAlerts = byNode[node.peer.id] || []
            const rate = rates[node.peer.id]
            return (
              <div key={node.peer.id} className="radar-pin" style={{ left: pos.left, top: pos.top }} data-testid="radar-node" data-tone={tone}>
                <PulsingHalo tone={tone} size={Math.max(40, frame.r * 0.36)} rings={2} className="radar-pin-halo" />
                <span className={cn('radar-pin-stem', `fx-tone-${tone}`)} aria-hidden="true" />
                <Link to="/nodes" className={cn('radar-pin-label', `fx-tone-${tone}`, node.is_self && 'is-self')}>
                  <StatusDot tone={tone} pulse={tone !== 'success'} label={t(`common:status.${node.status || 'unknown'}`)} />
                  <span className="radar-pin-name">{node.peer.name}</span>
                  {typeof rate === 'number' && (
                    <span className="radar-pin-rate">{t('radar.rate', { rate: formatRate(rate, i18n.language) })}</span>
                  )}
                  {nodeAlerts.length > 0 && (
                    <span className={cn('radar-pin-alerts', nodeAlerts.some((a) => a.severity === 'critical') ? 'fx-tone-danger' : 'fx-tone-warning')} title={nodeAlerts.map((a) => msg(a.title_message, a.title)).join('\n')}>
                      <span aria-hidden="true">{nodeAlerts.length}</span>
                      <span className="sr-only">{t('radar.alertCount', { count: nodeAlerts.length })}</span>
                    </span>
                  )}
                </Link>
              </div>
            )
          })}

          {ha.length > 0 && (
            <div className="radar-rail" data-testid="radar-ha-rail">
              {ha.map((h, i) => {
                const tone = haTone(h)
                const next = ha[i + 1]
                const joined = next && next.family === h.family
                return (
                  <div key={`${h.node_id}/${h.family}`} className="radar-rail-step">
                    <Link to={`/dhcp/${h.family === 'v6' ? 'v6' : 'v4'}/ha`} className={cn('radar-rail-pill', `fx-tone-${tone}`)} title={t(`common:status.${h.state}`, { defaultValue: h.state })} data-testid="radar-ha-pill" data-tone={tone}>
                      <span className="radar-rail-name">{h.server_name || nodes.find((n) => n.peer.id === h.node_id)?.peer.name || '?'}</span>
                      <span className="radar-rail-family">{h.family === 'v6' ? 'v6' : 'v4'}</span>
                    </Link>
                    <span className="radar-rail-state">{t(`common:status.${h.state}`, { defaultValue: h.state || '?' })}</span>
                    {joined && (
                      <span className={cn('radar-rail-joint fx-flow fx-flow-h', h.partner?.in_touch === false ? 'fx-tone-danger' : 'fx-tone-primary')} aria-hidden="true">
                        <span className="fx-flow-strip fx-loop" style={h.partner?.in_touch === false ? { animation: 'none' } : undefined} />
                      </span>
                    )}
                  </div>
                )
              })}
            </div>
          )}
        </>
      )}
    </div>
  )
}

export default ClusterRadar
