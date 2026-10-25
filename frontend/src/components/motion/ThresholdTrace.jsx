// SPDX-License-Identifier: Apache-2.0
// A mini trace with threshold lines and latches: the signal crosses a line at an instant
// one can find again, a red latch closes there and stays; a resolved alert leaves it
// hollow and puts a green latch at its end, so the incident reads between the two. Built
// on ClusterTrace (one line lane), for pool pressure now, later qps or SERVFAIL.
import { forwardRef, useMemo } from 'react'
import { ClusterTrace } from './ClusterTrace'
import { Readout } from './Instrument'

export const ThresholdTrace = forwardRef(function ThresholdTrace(
  {
    samples = [],
    thresholds = [],
    latches = [],
    windowMs = 3600000,
    min,
    max,
    color = 'dhcp',
    channel,
    unit,
    rate,
    readoutLabel,
    format,
    locale,
    labels,
    ariaLabel,
    className,
    testId = 'threshold-trace',
  },
  ref,
) {
  const lanes = useMemo(
    () => [{ type: 'line', key: 'value', label: readoutLabel, readoutLabel, color, data: samples, thresholds, latches, min, max, topPad: 0.16, botPad: 0.1, format }],
    [samples, thresholds, latches, min, max, color, readoutLabel, format],
  )
  return (
    <ClusterTrace
      ref={ref}
      lanes={lanes}
      windowMs={windowMs}
      names={false}
      locale={locale}
      labels={labels}
      ariaLabel={ariaLabel}
      className={className}
      testId={testId}
    >
      {(channel || unit) && <Readout channel={channel} unit={unit} rate={rate} className="fx-trace-tag" />}
    </ClusterTrace>
  )
})
