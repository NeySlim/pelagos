// SPDX-License-Identifier: Apache-2.0
// Cursors that glide between entries on the spring: the 2 px navigation cursor, which
// stretches while it travels, and the tab ink, which slides and resizes under the active
// tab. Both measure once per change (never per frame) and move by transform only; below
// full motion they jump. Their container must be position: relative.
import { useCallback, useEffect, useLayoutEffect, useRef } from 'react'
import { useMotionLevel } from '../../contexts/MotionContext'
import { cn } from '../../lib/utils'

const INK_BASE = 10 // px: the ink's layout width, scaled to the tab width

function useRemeasure(container, place) {
  useEffect(() => {
    const el = container.current
    if (!el) return undefined
    const ro = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(() => place(false)) : null
    ro?.observe(el)
    // A fold that ends (sidebar group) moves the entries: follow without the travel stretch.
    const onEnd = (e) => {
      if (e.propertyName === 'grid-template-rows') place(false)
    }
    const onResize = () => place(false)
    el.addEventListener('transitionend', onEnd)
    window.addEventListener('resize', onResize)
    return () => {
      ro?.disconnect()
      el.removeEventListener('transitionend', onEnd)
      window.removeEventListener('resize', onResize)
    }
  }, [container, place])
}

// `activeKey` and `layoutKey` (expanded groups, item list) trigger a new measure.
export function NavCursor({ container, activeKey, layoutKey, selector = '[aria-current="page"]', className }) {
  const level = useMotionLevel()
  const ref = useRef(null)
  const last = useRef(null)
  const full = useRef(level === 'full')
  useEffect(() => {
    full.current = level === 'full'
  }, [level])

  const place = useCallback(
    (animate = true) => {
      const host = container.current
      const cursor = ref.current
      if (!host || !cursor) return
      const active = host.querySelector(selector)
      const r = active?.getBoundingClientRect()
      if (!r || r.height < 4) {
        cursor.classList.remove('is-placed')
        last.current = null
        return
      }
      const hr = host.getBoundingClientRect()
      const y = Math.round(r.top - hr.top + host.scrollTop + (r.height - 16) / 2)
      if (last.current !== null && last.current !== y && animate && full.current) {
        // Restart the stretch: one reflow per navigation, not per frame.
        cursor.classList.remove('is-travel')
        void cursor.offsetWidth
        cursor.classList.add('is-travel')
      }
      last.current = y
      cursor.style.transform = `translateY(${y}px)`
      cursor.classList.add('is-placed')
    },
    [container, selector],
  )

  useLayoutEffect(() => {
    place(true)
  }, [place, activeKey, layoutKey])
  useRemeasure(container, place)

  return <span ref={ref} className={cn('fx-nav-cursor', className)} aria-hidden="true" data-testid="nav-cursor" />

}

export function TabInk({ container, activeKey, selector = '[aria-selected="true"], [data-state="active"], .is-active', className }) {
  const ref = useRef(null)
  const place = useCallback(() => {
    const host = container.current
    const ink = ref.current
    if (!host || !ink) return
    const active = host.querySelector(selector)
    const r = active?.getBoundingClientRect()
    if (!r || !r.width) {
      ink.classList.remove('is-placed')
      return
    }
    const hr = host.getBoundingClientRect()
    const x = r.left - hr.left + host.scrollLeft
    ink.style.transform = `translateX(${x.toFixed(1)}px) scaleX(${(r.width / INK_BASE).toFixed(3)})`
    ink.classList.add('is-placed')
  }, [container, selector])

  useLayoutEffect(() => {
    place()
  }, [place, activeKey])
  useRemeasure(container, place)

  return <span ref={ref} className={cn('fx-tab-ink', className)} aria-hidden="true" data-testid="tab-ink" />
}
