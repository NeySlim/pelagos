// SPDX-License-Identifier: Apache-2.0
// Instrument marks that live with the measure: the readout label of a channel, the value
// ruler whose round ticks glide when the maximum changes, the scale bar that rescales with
// a time window, and registration marks on tile corners. All are decorative (aria-hidden):
// the values they frame are shown as text elsewhere.
import { useMemo } from 'react'
import { cn } from '../../lib/utils'
import { RollingNumber, SwapText } from './RollingNumber'
import { niceTicks } from './primitives'

// "CH1 · q/s · 0.5 S/s · n 00142": channel, unit, sample rate and a rolling sample count.
export function Readout({ channel, unit, rate, count, className }) {
  return (
    <span className={cn('fx-readout', className)} aria-hidden="true" data-testid="readout">
      {channel && <b>{channel}</b>}
      {unit && <span>{unit}</span>}
      {rate && <span>{rate}</span>}
      {count !== undefined && count !== null && (
        <span>
          n <RollingNumber value={String(Math.max(0, Math.floor(count))).padStart(5, '0')} delta={false} />
        </span>
      )}
    </span>
  )
}

// Value ruler on the right edge of a strip: ticks keyed by value glide (translateY) to
// their new height when the series maximum changes; the layer is the ruler's height.
export function Ruler({ max, count = 4, format = String, className }) {
  const ticks = useMemo(() => niceTicks(max, count).filter((v) => v > 0), [max, count])
  return (
    <span className={cn('fx-ruler', className)} aria-hidden="true" data-testid="ruler">
      {ticks.map((v) => (
        <span key={v} className="fx-ruler-tick" style={{ transform: `translateY(${((1 - v / max) * 100).toFixed(2)}%)` }}>
          <i />
          <span>{format(v)}</span>
        </span>
      ))}
    </span>
  )
}

// Scale bar: a 60 px reference scaled to `ratio`; the label crossfades ("10 s", "1 min").
export function ScaleBar({ ratio = 1, label, className }) {
  return (
    <span className={cn('fx-scalebar', className)} aria-hidden="true" data-testid="scalebar">
      <i style={{ transform: `scaleX(${Number(ratio).toFixed(3)})` }} />
      {label && <SwapText text={label} />}
    </span>
  )
}
