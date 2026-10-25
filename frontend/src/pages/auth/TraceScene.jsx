// SPDX-License-Identifier: Apache-2.0
// Sign-in scene of Instrument: the cluster trace before anything is measured. The paper
// runs at the real clock, empty lanes wait for their signals, and the pen writes a flat
// line from the moment the page opened, one sample every 4 s: an instrument switched on.
// Decorative only (aria-hidden), quieter than the card it sits behind but readable.
import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ClusterTrace } from '../../components/motion'
import { LIVE_INTERVAL_MS } from '../../lib/liveRates'

const KEEP = 90

export function TraceScene() {
  const { t } = useTranslation('dashboard')
  const [samples, setSamples] = useState(() => [{ t: Date.now(), v: 0 }])
  useEffect(() => {
    const id = setInterval(() => {
      if (document.visibilityState === 'hidden') return
      setSamples((cur) => [...cur.slice(-KEEP), { t: Date.now(), v: 0 }])
    }, LIVE_INTERVAL_MS)
    return () => clearInterval(id)
  }, [])
  const lanes = useMemo(
    () => [
      { type: 'line', key: 'dns', color: 'dns', label: t('trace.lanes.dns'), data: samples, max: 1, botPad: 0.2, baseline: 0.4 },
      { type: 'bars', key: 'dhcp', color: 'dhcp', label: t('trace.lanes.dhcp'), data: [], max: 1, botPad: 0.2, baseline: 0.4 },
      { type: 'ecg', key: 'hb', label: t('trace.lanes.hb'), rows: [{ label: 'v4', beats: [] }, { label: 'v6', beats: [] }] },
      { type: 'events', key: 'events', label: t('trace.lanes.events'), data: [] },
    ],
    [samples, t],
  )
  const labels = useMemo(() => ({ now: t('live.now') }), [t])
  return (
    <div className="login-trace" aria-hidden="true" data-testid="login-scene">
      <ClusterTrace lanes={lanes} windowMs={90000} pad={24} rightPad={40} reveal readout={false} labels={labels} testId="login-trace" />
    </div>
  )
}

export default TraceScene
