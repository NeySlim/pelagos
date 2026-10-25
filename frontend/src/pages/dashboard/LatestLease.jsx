// SPDX-License-Identifier: Apache-2.0
// The latest lease of the DHCP tile: the newest client transaction (cltt) across the nodes,
// from GET /dhcp/{family}/leases/recent (the collectors' lease watch) and the `leases`
// topic, which carries each new or renewed lease as the collector sees it. A lease that was
// not there before plays its DORA once; a declined one stops on red. Kea stores when the
// exchange completed (cltt), not when each of its four packets passed: the DORA marks the
// completed exchange, with no per-step timing.
import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Dora } from '../../components/motion'
import { usePoll } from '../../hooks/usePoll'
import { useWsTopic } from '../../hooks/useWebSocket'
import { useFallbackMs } from '../../hooks/useClusterSignals'
import { api } from '../../services/api'
import { formatRelativeTime } from '../../lib/utils'
import { latestLease } from './summary'

const POLL_MS = 30000

const leaseKey = (l) => (l ? `${l.ip_address}/${l.cltt}` : null)

export function LatestLease({ family = 'v4' }) {
  const { t } = useTranslation(['dashboard', 'common'])
  // Without read:dhcp the read is refused and the block stays hidden.
  const [allowed, setAllowed] = useState(true)
  const [lease, setLease] = useState(null)
  const [play, setPlay] = useState(0)
  const seen = useRef(null)
  const engine = family === 'v6' ? 'kea6' : 'kea4'

  const current = useRef(null)
  const show = useCallback((next) => {
    if (!next) return
    const cur = current.current
    // Never step back to an older transaction (a slow poll answering after an event).
    if (cur?.cltt && next.cltt && Date.parse(next.cltt) < Date.parse(cur.cltt)) return
    const key = leaseKey(next)
    if (key && seen.current && key !== seen.current) setPlay((n) => n + 1)
    seen.current = key
    current.current = next
    setLease(next)
  }, [])

  const load = useCallback(async () => {
    if (!allowed) return
    try {
      const res = await api.dhcp.recentLeases(family, { limit: 1 })
      show(latestLease(res?.items))
    } catch (err) {
      if (err?.status === 403 || err?.status === 404) setAllowed(false)
      // otherwise the tile keeps the last lease it read
    }
  }, [allowed, family, show])

  useEffect(() => {
    load()
  }, [load])
  usePoll(load, useFallbackMs(POLL_MS), { enabled: allowed })
  useWsTopic(allowed ? 'leases' : null, (message) => {
    const d = message?.data
    if (d?.engine !== engine) return
    if (message.event === 'lease' && d.lease) show({ ...d.lease, node_id: d.lease.node_id || message.node_id, change: d.change })
    else if (message.event === 'coalesced') load()
  })

  if (!allowed || !lease) return null
  const client = lease.hw_address || lease.duid || lease.client_id || ''
  return (
    <div className="dash-lease" data-testid="latest-lease" data-lease={lease.ip_address} title={t('tiles.dhcp.leaseTiming')}>
      <span className="dash-lease-who" title={client || undefined}>
        <b>{lease.ip_address}</b>
        <span data-testid="latest-lease-client">{lease.hostname || client}</span>
      </span>
      <Dora key={play} play={play > 0} nak={lease.state === 'declined'} />
      <span className="dash-lease-when" title={`${t('tiles.dhcp.latestLease')} ${client}`.trim()}>
        {lease.change === 'renewed' ? `${t('tiles.dhcp.renewed')} · ` : ''}
        {formatRelativeTime(lease.cltt)}
      </span>
    </div>
  )
}
