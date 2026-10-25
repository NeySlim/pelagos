// SPDX-License-Identifier: Apache-2.0
// DHCP and HA rhythm marks. Dora: four tick marks D, O, R, A landing 90 ms apart on the
// settle curve whenever a new exchange is counted; a NAK stops on a red fourth tick that
// stays. HeartbeatTrace: a tiny ECG that draws itself (stroke-dashoffset, 250 ms) when a
// heartbeat arrives, then rests at 35 %; a lost partner turns it into red dashes.
import { useEffect, useRef, useState } from 'react'
import { useMotionLevel } from '../../contexts/MotionContext'
import { cn } from '../../lib/utils'

const STEPS = ['D', 'O', 'R', 'A']

// `beat` changes (any value) when a new exchange lands; `values` are shown under the ticks.
export function Dora({ beat, nak = false, values = [], labels = STEPS, className, testId = 'dora' }) {
  const level = useMotionLevel()
  const [gen, setGen] = useState(0)
  const first = useRef(true)
  useEffect(() => {
    if (first.current) {
      first.current = false
      return
    }
    if (beat !== undefined && beat !== null) setGen((g) => g + 1)
  }, [beat])
  const landing = gen > 0 && level !== 'off'
  return (
    <span className={cn('fx-dora', beat !== undefined && beat !== null && 'is-on', landing && 'is-go', nak && 'is-nak', className)} key={gen} data-testid={testId} data-gen={gen} aria-hidden="true">
      {labels.map((l, i) => (
        <i key={`t${l}`} style={{ '--fx-k': i }} />
      ))}
      {labels.map((l, i) => (
        <span key={`l${l}`} style={{ '--fx-k': i }}>
          {l}
        </span>
      ))}
      {values.length > 0 &&
        values.map((v, i) => (
          <small key={`v${labels[i]}`} style={{ '--fx-k': i }}>
            {v}
          </small>
        ))}
    </span>
  )
}

const ECG = 'M0 7h7l2 1.5 2-7 2.5 5.5 2-2h10.5'

// `beat` changes when a heartbeat arrives; `lost` draws the partner-down state.
export function HeartbeatTrace({ beat, lost = false, label, className }) {
  const [gen, setGen] = useState(0)
  const first = useRef(true)
  useEffect(() => {
    if (first.current) {
      first.current = false
      return
    }
    if (beat !== undefined && beat !== null) setGen((g) => g + 1)
  }, [beat])
  return (
    <svg className={cn('fx-ecg', lost && 'is-lost', className)} viewBox="0 0 26 10" aria-hidden="true" data-testid="heartbeat-trace" data-gen={gen}>
      {label && <title>{label}</title>}
      <path key={gen} className={cn(gen > 0 && !lost && 'is-beat')} pathLength="1" d={ECG} />
    </svg>
  )
}
