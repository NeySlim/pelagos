// SPDX-License-Identifier: Apache-2.0
// Odometer for discrete values (serials, config versions, counts): only the characters
// that change roll, up or down with the sign of the change, and a hairline lights under
// the value. A unit is part of the text and rolls like a character. Screen readers get
// the final value only.
import { useEffect, useRef, useState } from 'react'
import { useMotionLevel } from '../../contexts/MotionContext'
import { cn } from '../../lib/utils'
import { rollCells, rollDirection } from './primitives'

export function RollingNumber({ value, format, direction, className, delta = true, 'data-testid': testId, ...props }) {
  const level = useMotionLevel()
  const text = value === null || value === undefined ? '' : String(format ? format(value) : value)
  const [state, setState] = useState(() => ({ text, previous: text, dir: 'up', gen: 0 }))
  const last = useRef(text)

  useEffect(() => {
    if (last.current === text) return
    const previous = last.current
    last.current = text
    setState((s) => ({ text, previous, dir: rollDirection(previous, text, direction), gen: s.gen + 1 }))
  }, [text, direction])

  const animate = level !== 'off' && state.gen > 0 && state.previous !== ''
  const cells = rollCells(animate ? state.previous : state.text, state.text)
  return (
    <span className={cn('fx-roll-wrap', className)} data-testid={testId} {...props}>
      <span className="sr-only">{state.text}</span>
      <span
        key={state.gen}
        className={cn('fx-roll', state.dir === 'down' && 'is-down', animate && delta && 'is-delta')}
        aria-hidden="true"
        data-value={state.text}
      >
        {cells.map(({ char, from }, i) => (
          <span className="fx-roll-ch" key={i}>
            {animate && from !== char ? (
              <>
                <span className="fx-roll-out">{from || ' '}</span>
                <span className="fx-roll-in">{char}</span>
              </>
            ) : (
              <span>{char}</span>
            )}
          </span>
        ))}
      </span>
    </span>
  )
}

// Crossfade of a state label: the old text fades out while the new one fades in.
export function SwapText({ text, className }) {
  const level = useMotionLevel()
  const [state, setState] = useState({ text, previous: null, gen: 0 })
  const last = useRef(text)
  useEffect(() => {
    if (last.current === text) return
    const previous = last.current
    last.current = text
    setState((s) => ({ text, previous, gen: s.gen + 1 }))
  }, [text])
  if (level === 'off' || state.previous === null) return <span className={className}>{state.text}</span>
  return (
    <span className={cn('fx-swap', className)} key={state.gen}>
      <span className="fx-swap-out" aria-hidden="true">{state.previous}</span>
      <span className="fx-swap-in">{state.text}</span>
    </span>
  )
}
