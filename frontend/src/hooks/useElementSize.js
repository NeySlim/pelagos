// SPDX-License-Identifier: Apache-2.0
// Content box of an element (width and height), measured before the first paint and
// kept current with a ResizeObserver.
import { useLayoutEffect, useRef, useState } from 'react'

export function useElementSize(fallback = { width: 0, height: 0 }) {
  const ref = useRef(null)
  const [size, setSize] = useState(fallback)
  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return undefined
    const rect = el.getBoundingClientRect()
    if (rect.width > 0) setSize({ width: Math.round(rect.width), height: Math.round(rect.height) })
    if (typeof ResizeObserver === 'undefined') return undefined
    const ro = new ResizeObserver(([entry]) => {
      const { width, height } = entry.contentRect
      if (width > 0) setSize((cur) => (cur.width === Math.round(width) && cur.height === Math.round(height) ? cur : { width: Math.round(width), height: Math.round(height) }))
    })
    ro.observe(el)
    return () => ro.disconnect()
  }, [])
  return [ref, size]
}

export default useElementSize
