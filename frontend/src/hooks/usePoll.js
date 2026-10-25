// SPDX-License-Identifier: Apache-2.0
// Calls `fn` every `ms` while enabled and the tab is visible: the fallback that keeps live
// views moving when the collector publishes nothing on the WebSocket. A hidden tab polls
// nothing; coming back polls at once.
import { useEffect, useRef } from 'react'

export function usePoll(fn, ms, { enabled = true } = {}) {
  const ref = useRef(fn)
  useEffect(() => {
    ref.current = fn
  })
  useEffect(() => {
    if (!enabled || !(ms > 0)) return undefined
    let timer = null
    let alive = true
    const visible = () => typeof document === 'undefined' || document.visibilityState !== 'hidden'
    const tick = async () => {
      if (!alive) return
      if (visible()) {
        try {
          await ref.current()
        } catch {
          // a failed poll keeps the last data; the next tick retries
        }
      }
      if (alive) timer = setTimeout(tick, ms)
    }
    timer = setTimeout(tick, ms)
    const onVisible = () => {
      if (!visible() || !alive) return
      clearTimeout(timer)
      tick()
    }
    document.addEventListener('visibilitychange', onVisible)
    return () => {
      alive = false
      clearTimeout(timer)
      document.removeEventListener('visibilitychange', onVisible)
    }
  }, [ms, enabled])
}
