// SPDX-License-Identifier: Apache-2.0
// A 2D canvas sized by ResizeObserver (never a layout read in a frame), device pixel
// ratio capped at 2. `draw({ ctx, width, height })` runs on resize and on redraw().
import { useCallback, useEffect, useRef } from 'react'

export const MAX_DPR = 2

export function useCanvas(draw) {
  const ref = useRef(null)
  const size = useRef({ width: 0, height: 0 })
  const drawRef = useRef(draw)
  useEffect(() => {
    drawRef.current = draw
  })

  const redraw = useCallback(() => {
    const canvas = ref.current
    const { width, height } = size.current
    if (!canvas || !width || !height) return
    const ctx = canvas.getContext?.('2d')
    if (!ctx) return
    const dpr = Math.min(MAX_DPR, window.devicePixelRatio || 1)
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    ctx.clearRect(0, 0, width, height)
    drawRef.current?.({ ctx, width, height })
  }, [])

  useEffect(() => {
    const canvas = ref.current
    if (!canvas || typeof ResizeObserver === 'undefined') return undefined
    const observer = new ResizeObserver(([entry]) => {
      const { width, height } = entry.contentRect
      const dpr = Math.min(MAX_DPR, window.devicePixelRatio || 1)
      size.current = { width, height }
      canvas.width = Math.round(width * dpr)
      canvas.height = Math.round(height * dpr)
      redraw()
    })
    observer.observe(canvas)
    return () => observer.disconnect()
  }, [redraw])

  return { ref, redraw, size }
}
