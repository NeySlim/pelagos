// SPDX-License-Identifier: Apache-2.0
// Content width of an element, measured before the first paint and kept current
// with a ResizeObserver, so a chart never paints at the fallback width.
import { useLayoutEffect, useRef, useState } from 'react'

export function useElementWidth(fallback = 300) {
  const ref = useRef(null)
  const [width, setWidth] = useState(fallback)
  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return undefined
    const initial = Math.round(el.getBoundingClientRect().width)
    if (initial > 0) setWidth(initial)
    if (typeof ResizeObserver === 'undefined') return undefined
    const ro = new ResizeObserver(([entry]) => {
      const w = Math.round(entry.contentRect.width)
      if (w > 0) setWidth(w)
    })
    ro.observe(el)
    return () => ro.disconnect()
  }, [])
  return [ref, width]
}

export default useElementWidth
