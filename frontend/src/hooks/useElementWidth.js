// SPDX-License-Identifier: Apache-2.0
// Content width of an element, kept current with a ResizeObserver.
import { useEffect, useRef, useState } from 'react'

export function useElementWidth(fallback = 300) {
  const ref = useRef(null)
  const [width, setWidth] = useState(fallback)
  useEffect(() => {
    const el = ref.current
    if (!el || typeof ResizeObserver === 'undefined') return undefined
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
