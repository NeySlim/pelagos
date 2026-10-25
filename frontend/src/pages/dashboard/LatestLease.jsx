// SPDX-License-Identifier: Apache-2.0
// The latest lease of the DHCP tile: the most recent client transaction among the leases
// read, re-read when the `leases` topic reports new ones (and every 30 s as a fallback).
// A lease that was not there before plays its DORA once; a declined one stops on red.
import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Dora } from '../../components/motion'
import { usePoll } from '../../hooks/usePoll'
import { useWsTopic } from '../../hooks/useWebSocket'
import { api } from '../../services/api'
import { formatRelativeTime } from '../../lib/utils'
import { latestLease } from './summary'

const POLL_MS = 30000
const SAMPLE = 100

const leaseKey = (l) => (l ? `${l.node_id || ''}/${l.ip_address}/${l.cltt}` : null)

export function LatestLease({ family = 'v4' }) {
  const { t } = useTranslation(['dashboard', 'common'])
  // Without read:dhcp the read is refused and the block stays hidden.
  const [allowed, setAllowed] = useState(true)
  const [lease, setLease] = useState(null)
  const [play, setPlay] = useState(0)
  const seen = useRef(null)

  const load = useCallback(async () => {
    if (!allowed) return
    try {
      const res = await api.dhcp.leases(family, { limit: SAMPLE })
      const next = latestLease(res?.items)
      const key = leaseKey(next)
      if (key && seen.current && key !== seen.current) setPlay((n) => n + 1)
      seen.current = key
      setLease(next)
    } catch (err) {
      if (err?.status === 403 || err?.status === 404) setAllowed(false)
      // otherwise the tile keeps the last lease it read
    }
  }, [allowed, family])

  useEffect(() => {
    load()
  }, [load])
  usePoll(load, POLL_MS, { enabled: allowed })
  useWsTopic(allowed ? 'leases' : null, (message) => {
    const d = message?.data
    if (d && d.engine === (family === 'v6' ? 'kea6' : 'kea4') && d.new_since_last > 0) load()
  })

  if (!allowed || !lease) return null
  return (
    <div className="dash-lease" data-testid="latest-lease" data-lease={lease.ip_address}>
      <span className="dash-lease-who">
        <b>{lease.ip_address}</b>
        <span>{lease.hw_address || lease.duid || ''}</span>
      </span>
      <Dora key={play} play={play > 0} nak={lease.state === 'declined'} />
      <span className="dash-lease-when" title={lease.cltt}>
        {`${t('tiles.dhcp.latestLease')} · ${formatRelativeTime(lease.cltt)}`}
      </span>
    </div>
  )
}
