// SPDX-License-Identifier: Apache-2.0
// Value that counts from what it showed last to `value`, on the shared animation loop.
// Counting runs only at full motion level on a visible page; otherwise the value jumps.
import { useEffect, useRef, useState } from 'react'
import { useMotion } from '../contexts/MotionContext'
import { countUpAllowed, interpolate } from '../lib/motion'
import { addAnimator, removeAnimator } from './useAnimationLoop'

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
    const id = {}
    let elapsed = 0
    addAnimator(id, (_t, dt) => {
      elapsed += dt
      const next = interpolate(start, target, elapsed, duration)
      setShown(next)
      if (next === target) removeAnimator(id)
    })
    return () => removeAnimator(id)
  }, [target, animate, duration])

  return shown
}

export default useCountUp
