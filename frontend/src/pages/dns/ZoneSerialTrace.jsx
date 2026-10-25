// SPDX-License-Identifier: Apache-2.0
// Serial per node over the last 5 minutes on the zone page: a step per new serial, a marker
// per plan, and a playhead that rewinds to the plan's instant while its rollback runs,
// holds there, then returns to the present once the rollback is done.
import { useEffect, useMemo, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { SerialTrace } from '../../components/motion'
import { onPlanEvent, planZone } from '../../lib/planEvents'
import { useSerialHistory } from './serialHistory'

const TRACE_WINDOW_MS = 300000
const REWIND_LEAD_MS = 400
const REWIND_HOLD_MS = 350

export function ZoneSerialTrace({ zone, view, status, nameOf }) {
  const { t } = useTranslation(['dns', 'common'])
  const trace = useRef(null)
  const { lanes, markers } = useSerialHistory({ zone: zone.name, view, status, windowMs: TRACE_WINDOW_MS })
  useEffect(
    () =>
      onPlanEvent((event) => {
        if (planZone(event.plan) !== zone.name || !trace.current) return
        if (event.type === 'rollback-start' && event.at) trace.current.scrubTo(event.at - REWIND_LEAD_MS)
        if (event.type === 'rolled-back') setTimeout(() => trace.current?.release(), REWIND_HOLD_MS)
      }),
    [zone.name],
  )
  const named = useMemo(() => lanes.map((l) => ({ ...l, label: nameOf(l.id) })), [lanes, nameOf])
  const labeled = useMemo(() => markers.map((m) => ({ ...m, label: t(m.kind === 'rollback' ? 'trace.rolledBack' : 'trace.planApplied') })), [markers, t])
  if (!named.length) return null
  return (
    <div className="mb-3" data-testid="zone-serial-trace">
      <div className="fx-trace-head">
        <b>{t('trace.serials')}</b>
        <span className="font-mono">{t('trace.window', { minutes: TRACE_WINDOW_MS / 60000 })}</span>
      </div>
      <SerialTrace ref={trace} lanes={named} markers={labeled} windowMs={TRACE_WINDOW_MS} />
    </div>
  )
}
