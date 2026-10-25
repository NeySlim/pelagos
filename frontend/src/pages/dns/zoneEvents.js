// SPDX-License-Identifier: Apache-2.0
// A serial or transfer of this zone on any node (the zones topic, relayed ones included)
// reaches the zone page as it lands, not at the next poll.
import { useWsTopic } from '../../hooks/useWebSocket'

const bare = (name) => String(name || '').replace(/\.$/, '').toLowerCase()

export function sameZone(event, zone, view) {
  if (!event || !zone || bare(event.zone) !== bare(zone)) return false
  return !view || !event.view || event.view === view
}

export function useZoneEvents(zone, view, onEvent) {
  useWsTopic(zone ? 'zones' : null, (message) => {
    if (sameZone(message?.data, zone, view)) onEvent(message)
  })
}
