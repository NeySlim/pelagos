// SPDX-License-Identifier: Apache-2.0
// The topology of the cluster trace for three nodes or more: one compact card per node in a
// row (the HA pair first, then its backups, then the other nodes) and the links between them
// on one canvas: replication arcs above between every two nodes, the HA link between the two
// active servers, dashed lease update feeds below to each backup. Roles are words on the
// cards; a backup is drawn as such. Scales from 3 to 8 nodes, wrapping on narrow screens.
import { forwardRef, useMemo, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { HeartbeatTrace, MeshLinks, RollingNumber, SwapText } from '../../components/motion'
import { cn } from '../../lib/utils'
import { meshModel, meshStatus, nodeEngines } from './traceModel'

const ENGINE_INK = { dns: 'var(--accent-primary)', dhcp: 'var(--accent-pro)', ok: 'var(--accent-success)' }

function MeshCard({ card, engines, families, heartbeats }) {
  const { t } = useTranslation(['dashboard', 'common'])
  const { node, role } = card
  const online = !node.status || node.status === 'online'
  const active = role && role !== 'backup'
  return (
    <div
      className={cn('trace-node trace-node-compact', !online && 'is-offline', role === 'backup' && 'is-backup', node.is_self && 'is-self')}
      data-testid="trace-node"
      data-mesh-node={card.id}
      data-role={role || 'none'}
    >
      <div className="trace-node-name">
        <span className={cn('fx-dot', online ? 'fx-tone-success' : 'fx-tone-danger')} role="img" aria-label={t(`common:status.${node.status || 'unknown'}`)} />
        <span className="font-mono truncate">{node.peer.name}</span>
        {node.is_self && <span className="trace-node-self">{t('tiles.nodes.self')}</span>}
      </div>
      <div className="trace-node-role">
        {role ? (
          <span className={cn('trace-role', `is-${role}`)} data-testid="trace-node-role">
            {t(`common:status.${role}`, { defaultValue: role })}
          </span>
        ) : (
          <span className="trace-role is-none">{t('trace.mesh.noHa')}</span>
        )}
        {active && families.length > 0 && (
          <span className="trace-node-hb-inline" title={t('trace.heartbeats')}>
            {families.map((f) => {
              const rec = heartbeats?.[`${f}:${node.peer.id}`]
              return <HeartbeatTrace key={f} beat={rec?.beats?.[0]?.t ?? null} lost={rec?.inTouch === false} label={`${t('trace.heartbeat')} ${f}`} />
            })}
          </span>
        )}
      </div>
      <div className="trace-node-meta">
        <span>
          {t('trace.config')} <RollingNumber value={node.config_version ?? '?'} />
        </span>
        <span className="trace-node-dots" aria-label={engines.map((e) => e.label).join(', ')}>
          {engines.map((e) => (
            <i key={e.key} className="fx-dot" style={{ '--fx-c': ENGINE_INK[e.tone] }} title={e.label} />
          ))}
        </span>
      </div>
    </div>
  )
}

export const TraceMesh = forwardRef(function TraceMesh({ nodes, ha, self, engineOpts, families, heartbeats }, ref) {
  const { t } = useTranslation(['dashboard', 'common'])
  const rowRef = useRef(null)
  const { cards, links } = useMemo(() => meshModel(nodes, ha), [nodes, ha])
  const ids = useMemo(() => cards.map((c) => c.id), [cards])
  const status = meshStatus(self, nodes)
  const label = t(`trace.mesh.${status.status}`, { count: status.count, names: status.names.join(', ') })
  const hasHa = links.some((l) => l.kind === 'ha')
  const hasFeed = links.some((l) => l.kind === 'feed')
  return (
    <div className="trace-mesh" data-testid="trace-topology" data-nodes={cards.length}>
      <div ref={rowRef} className="trace-mesh-row" style={{ '--mesh-n': cards.length, '--mesh-narrow': Math.min(cards.length, 4) }}>
        <MeshLinks ref={ref} containerRef={rowRef} nodes={ids} links={links} testId="trace-mesh-links" />
        {cards.map((c) => (
          <MeshCard key={c.id} card={c} engines={nodeEngines(c.node, engineOpts)} families={families} heartbeats={heartbeats} />
        ))}
      </div>
      <div className="trace-mesh-foot">
        <span className="trace-mesh-key is-repl">{t('trace.mesh.replication')}</span>
        {hasHa && <span className="trace-mesh-key is-ha">{t('trace.mesh.ha')}</span>}
        {hasFeed && <span className="trace-mesh-key is-feed">{t('trace.mesh.feed')}</span>}
        <span className={cn('trace-mesh-status', status.status !== 'inSync' && 'is-warn')} data-testid="trace-mesh-status" data-status={status.status}>
          <SwapText text={label} />
        </span>
      </div>
    </div>
  )
})
