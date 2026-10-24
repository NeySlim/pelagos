// SPDX-License-Identifier: Apache-2.0
// Value that counts from what it showed last to `value`. Counting runs only at full
// motion level on a visible page; otherwise the value is shown at once.
import { useEffect, useRef, useState } from 'react'
import { useMotion } from '../contexts/MotionContext'
import { countUpAllowed, interpolate } from '../lib/motion'

export function useCountUp(value, { duration = 900, from = 0 } = {}) {
  const { level, hidden } = useMotion()
  const target = Number.isFinite(Number(value)) ? Number(value) : 0
  const animate = countUpAllowed(level) && !hidden
  const [shown, setShown] = useState(animate ? from : target)
  const shownRef = useRef(shown)
  shownRef.current = shown

  useEffect(() => {
    if (!animate || typeof requestAnimationFrame === 'undefined') {
      setShown(target)
      return undefined
    }
    const start = shownRef.current
    if (start === target) return undefined
    let frame = 0
    let t0 = null
    const step = (now) => {
      if (t0 === null) t0 = now
      const next = interpolate(start, target, now - t0, duration)
      setShown(next)
      if (next !== target) frame = requestAnimationFrame(step)
    }
    frame = requestAnimationFrame(step)
    return () => cancelAnimationFrame(frame)
  }, [target, animate, duration])

  return shown
}

export default useCountUp
