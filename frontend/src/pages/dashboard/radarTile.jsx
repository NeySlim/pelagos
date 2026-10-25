// SPDX-License-Identifier: Apache-2.0
// Mission Control's center tile: the cluster radar. Loaded on demand under the mission
// effects only (heroTiles.jsx), so the other families never fetch the radar code.
import { useContext } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { Crosshair, Globe, HardDrives, WarningDiamond, ArrowsLeftRight } from '@phosphor-icons/react'
import { AmbientDots, IconButton, StatChip } from '../../components/motion'
import { useElementSize } from '../../hooks/useElementSize'
import { LiveStatus, TileFrame } from './tiles'
import { TileRefresh } from './tileRefresh'
import { ClusterRadar } from './ClusterRadar'
import { dhcpFamily } from './summary'

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
      id="trace"
      icon={Crosshair}
      title={t('tiles.radar.title')}
      editing={editing}
      status={<LiveStatus active={live?.dns.current !== null && live?.dns.current !== undefined} />}
      bodyClassName="p-0 overflow-hidden relative"
      className="dash-hero"
      ambient={<AmbientDots pulse={pulses?.trace} />}
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

export default RadarTile
