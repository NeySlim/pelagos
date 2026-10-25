// SPDX-License-Identifier: Apache-2.0
// Pressure of a pool: its fill over the last hour (GET /series/pools, then the summary
// refreshes), against the warning and critical thresholds. A pool alert latches where it
// opened; when it resolves the latch goes hollow and a green one marks the end.
import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ThresholdTrace } from '../../components/motion'
import { usePermission } from '../../hooks/usePermission'
import { api } from '../../services/api'
import { observePoolAlerts, poolAlertsSeen } from '../../hooks/useClusterSignals'
import { alertForPool, poolLatches, poolPressure, tracedPool } from '../../lib/trace'

export const PRESSURE_WINDOW = 3600000
const STEP_S = 60

const poolKey = (p) => (p ? `${p.node_id}/${p.engine}/${p.subnet_id}/${p.pool}` : '')

function usePoolPressure(pool) {
  const { hasPermission } = usePermission()
  const canSeries = hasPermission('read:series')
  const key = poolKey(pool)
  const [samples, setSamples] = useState([])
  useEffect(() => {
    setSamples([])
    if (!pool || !canSeries) return undefined
    let alive = true
    const now = Date.now()
    Promise.resolve()
      .then(() => api.series.pools({ engine: pool.engine, subnet_id: pool.subnet_id, pool: pool.pool, node_id: pool.node_id, from: Math.floor((now - PRESSURE_WINDOW) / 1000), step: STEP_S }))
      .then((res) => {
        if (!alive) return
        const series = (res?.series || [])[0]
        setSamples((cur) => [...poolPressure(series?.points), ...cur].sort((a, b) => a.t - b.t))
      })
      .catch(() => {})
    return () => {
      alive = false
    }
    // The key stands for the pool.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, canSeries])
  // Each summary refresh adds the pool as it is now.
  const percent = pool?.percent
  useEffect(() => {
    if (typeof percent !== 'number') return
    setSamples((cur) => {
      const now = Date.now()
      const last = cur[cur.length - 1]
      if (last && now - last.t < 5000) return cur
      return [...cur.filter((s) => now - s.t <= PRESSURE_WINDOW * 1.2), { t: now, v: percent }]
    })
  }, [percent, key])
  return samples
}

// Latches of the traced pool: its open alerts, and the ones seen resolving on this page.
function useTracedPool(pools, openAlerts) {
  // Observed while rendering, so the trace never shows another pool for a frame when an
  // alert leaves the list; the store ignores a list it has already seen.
  const { resolved } = useMemo(() => {
    observePoolAlerts(openAlerts)
    return poolAlertsSeen()
  }, [openAlerts])
  const pool = tracedPool(pools, openAlerts, resolved, Date.now(), PRESSURE_WINDOW)
  const mine = useMemo(() => (openAlerts || []).filter((a) => alertForPool(a, pool)), [openAlerts, pool])
  const gone = useMemo(() => resolved.filter((a) => alertForPool(a, pool) && !mine.some((m) => m.id === a.id)), [resolved, pool, mine])
  return { pool, alerts: useMemo(() => [...gone, ...mine], [gone, mine]) }
}

export function PoolPressure({ pools, openAlerts, warn, full }) {
  const { t, i18n } = useTranslation(['dashboard', 'common'])
  const { pool, alerts } = useTracedPool(pools, openAlerts)
  const samples = usePoolPressure(pool)
  const latches = useMemo(() => poolLatches(alerts, samples), [alerts, samples])
  const thresholds = useMemo(() => [{ v: warn, label: String(warn) }, { v: full, label: String(full), bad: true }], [warn, full])
  const min = useMemo(() => Math.max(0, Math.min(warn - 20, ...samples.map((s) => s.v - 5))), [samples, warn])
  const labels = useMemo(() => ({ now: t('live.now'), keys: t('trace.keys') }), [t])
  if (!pool) return null
  return (
    <div className="dash-pressure-trace" data-testid="pool-pressure" data-latches={latches.map((l) => l.state).join(' ')}>
      <div className="dash-sub">
        <span>{t('tiles.pools.pressure')}</span>
        <span className="dash-sub-right font-mono truncate" title={pool.pool}>
          {pool.pool}
        </span>
      </div>
      <ThresholdTrace
        samples={samples}
        thresholds={thresholds}
        latches={latches}
        windowMs={PRESSURE_WINDOW}
        min={Math.floor(min)}
        max={104}
        color="dhcp"
        channel="CH2"
        unit={t('tiles.pools.used')}
        rate={t('tiles.pools.window')}
        readoutLabel={t('tiles.pools.used')}
        format={(v) => `${new Intl.NumberFormat(i18n.language, { maximumFractionDigits: 1 }).format(v)} %`}
        locale={i18n.language}
        labels={labels}
        ariaLabel={t('tiles.pools.pressureLabel', { pool: pool.pool, percent: Math.round(pool.percent) })}
        className="dash-pressure-canvas"
      />
    </div>
  )
}
